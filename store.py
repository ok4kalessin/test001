import os, datetime, time, secrets as pysecrets, random, logging
from typing import Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.data.tables import TableServiceClient, TableTransactionError, UpdateMode
from azure.identity import DefaultAzureCredential

LOG = logging.getLogger("store")


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("Invalid %s value '%s'; using %d.", name, raw, default)
        return default


TABLE = os.environ.get("APPROVALS_TABLE", "approvals")
ACCOUNT_URL = os.environ.get("STORAGE_ACCOUNT_URL")
if not ACCOUNT_URL:
    raise RuntimeError(
        "STORAGE_ACCOUNT_URL must be configured for managed identity access to Table Storage."
    )

_conn = TableServiceClient(account_url=ACCOUNT_URL, credential=DefaultAzureCredential())
_table = _conn.get_table_client(TABLE)
try: _table.create_table()
except Exception: pass

RETRY_BASE = 0.08   # seconds
RETRY_MAX  = 5      # attempts

def _iso() -> str: return datetime.datetime.utcnow().isoformat()+"Z"


NONCE_RID_DAILY_LIMIT = max(1, _int_env("NONCE_RID_DAILY_LIMIT", 50))

def _retry(fn, *a, **k):
    d = RETRY_BASE
    for i in range(RETRY_MAX):
        try:
            return fn(*a, **k)
        except HttpResponseError as e:
            code = getattr(e, "status_code", None)
            if code in (429, 500, 502, 503, 504):
                time.sleep(d + random.random()*d)
                d = min(d*2, 1.5)
                continue
            raise
    # last try
    return fn(*a, **k)

# ---------- Decisions: transaction (decision + audit) ----------
# PartitionKey = f"dec:{rid}"
# RowKey       = "decision" ; audits: "a:<tsms>:<rand12>"
def upsert_decision_once(rid: str, status: str, who: str) -> bool:
    pk = f"dec:{rid}"
    tsms = int(time.time() * 1000)
    audit_rk = f"a:{tsms}:{pysecrets.token_hex(6)}"  # 96 bits random

    ops = [
        ("create", {"PartitionKey": pk, "RowKey": "decision",
                    "status": status, "approver": who, "atUtc": _iso()}),
        ("create", {"PartitionKey": pk, "RowKey": audit_rk,
                    "status": status, "approver": who, "atUtc": _iso()})
    ]
    try:
        _retry(_table.submit_transaction, ops)
        return True
    except TableTransactionError:
        # First-wins: someone else wrote the decision. Append an audit attempt anyway.
        audit2 = {"PartitionKey": pk, "RowKey": f"a:{tsms}:{pysecrets.token_hex(6)}",
                  "status": status, "approver": who, "atUtc": _iso(), "note": "late-attempt"}
        try:
            _retry(_table.upsert_entity, audit2, mode=UpdateMode.REPLACE)
        except HttpResponseError:
            pass
        return False

def get_decision(rid: str) -> Optional[dict]:
    pk = f"dec:{rid}"
    try:
        e = _retry(_table.get_entity, pk, "decision")
        return {"status": e.get("status"), "approver": e.get("approver"), "at": e.get("atUtc")}
    except ResourceNotFoundError:
        return None

# ---------- Nonces: day-bucket PK, collision-safe RK (rid_nodash + "_" + j) ----------
# PartitionKey = f"nonce:{YYYYMMDD}"
# RowKey       = rid_nodash + "_" + j
def _nonce_pk(ts: int) -> str:
    day = datetime.datetime.utcfromtimestamp(ts).strftime("%Y%m%d")
    return f"nonce:{day}"

def nonce_used_or_expired(rid: str, j: str, ts: int, skew: int, now: int) -> bool:
    if abs(now - ts) > skew:
        return True
    pk = _nonce_pk(ts)
    rid_nodash = rid.replace("-", "")
    if _nonce_limit_exceeded(pk, rid, rid_nodash):
        return True
    rk = f"{rid_nodash}_{j}"
    ent = {"PartitionKey": pk, "RowKey": rk, "ts": ts, "exp": ts + skew}
    try:
        _retry(_table.create_entity, ent)
        return False
    except HttpResponseError as e:
        # 409 = already exists -> replay
        if getattr(e, "status_code", None) == 409:
            return True
        raise

# ---------- Cleanup: catch up to N days per run ----------
# NONCE_CLEAN_MAX_DAYS controls how many back-days we attempt each run (default 3)
def purge_old_nonces(keep_days: int = 7):
    max_days = int(os.environ.get("NONCE_CLEAN_MAX_DAYS", "3"))
    today = datetime.datetime.utcnow().date()
    targets = []
    for i in range(keep_days+1, keep_days+1+max_days):
        day = (today - datetime.timedelta(days=i)).strftime("%Y%m%d")
        targets.append(f"nonce:{day}")
    for pk in targets:
        _delete_partition(pk)

def _delete_partition(pk: str):
    # delete in chunks; retry on transient errors
    batch = []
    try:
        for e in _table.query_entities(f"PartitionKey eq '{pk}'", select=["PartitionKey","RowKey"]):
            batch.append((e["PartitionKey"], e["RowKey"]))
            if len(batch) >= 100:
                _batch_delete(batch); batch = []
        if batch:
            _batch_delete(batch)
    except HttpResponseError as exc:
        LOG.warning("Failed to enumerate nonce partition %s for cleanup: %s", pk, exc)

def _batch_delete(rows: list[tuple[str,str]]):
    ops = [("delete", {"PartitionKey": pk, "RowKey": rk}) for pk, rk in rows]
    try:
        _retry(_table.submit_transaction, ops)
    except Exception as exc:
        LOG.warning("Failed to delete %d nonce rows from %s: %s", len(rows), rows[0][0] if rows else "n/a", exc)


def _nonce_limit_exceeded(pk: str, rid: str, rid_nodash: str) -> bool:
    limit = NONCE_RID_DAILY_LIMIT
    if limit <= 0:
        return False

    prefix = f"{rid_nodash}_"
    upper = f"{rid_nodash}_g"
    query = f"PartitionKey eq '{pk}' and RowKey ge '{prefix}' and RowKey lt '{upper}'"

    def _count() -> int:
        seen = 0
        pager = _table.query_entities(query, select=["RowKey"], results_per_page=limit)
        for page in pager.by_page():
            for _ in page:
                seen += 1
                if seen >= limit:
                    return seen
        return seen

    try:
        seen = _retry(_count)
    except HttpResponseError:
        raise

    if seen >= limit:
        LOG.warning(
            "Rejecting nonce for rid %s; reached configured cap of %d entries in partition %s.",
            rid,
            limit,
            pk,
        )
        return True

    return False

