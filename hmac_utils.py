import os, re, time, hmac, hashlib, logging, threading
from typing import Optional, Tuple, Callable

LOG = logging.getLogger("hmac")

SKEW_SECONDS = int(os.environ.get("HMAC_SKEW", "60"))
UUIDV4_RX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

def _parse_ts(t: str) -> Optional[int]:
    try: ti = int(t)
    except Exception: return None
    if not (1_577_836_800 <= ti <= 4_102_444_800):  # ~2020..2100
        return None
    return ti

def validate_uuid4_lower(rid: str) -> bool:
    return rid == rid.strip() and UUIDV4_RX.match(rid) is not None

# ---- per-request secrets with rotation + sanity checks ----
_SECRETS_CACHE = {"loaded_at": 0, "secrets": [], "fingerprint": ""}
_LOCK = threading.Lock()

def _load_env_secrets_unchecked() -> list[bytes]:
    secs = []
    prim = (os.environ.get("HMAC_SECRET") or "").strip()
    prev = (os.environ.get("HMAC_SECRET_PREV") or "").strip()
    def parse(x):
        if len(x) >= 64:
            try: return bytes.fromhex(x)
            except ValueError: LOG.error("Invalid hex in HMAC secret env var."); return None
        return None
    p = parse(prim); q = parse(prev)
    if p: secs.append(p)
    if q:
        if p and p == q:
            LOG.warning("HMAC_SECRET and HMAC_SECRET_PREV are identical; rotation ineffective.")
        secs.append(q)
    return secs

def get_secrets(now_sec: int) -> Optional[list[bytes]]:
    if now_sec - _SECRETS_CACHE["loaded_at"] < 5 and _SECRETS_CACHE["secrets"]:
        return _SECRETS_CACHE["secrets"]
    with _LOCK:
        if now_sec - _SECRETS_CACHE["loaded_at"] < 5 and _SECRETS_CACHE["secrets"]:
            return _SECRETS_CACHE["secrets"]
        secs = _load_env_secrets_unchecked()
        _SECRETS_CACHE["loaded_at"] = now_sec
        _SECRETS_CACHE["secrets"] = secs or []
        return secs if secs else None

def canonical_base(version: str, ts: int, res: str, rid: str, j: str) -> str:
    return f"{version}|{ts}|{res}|{rid}|{j}"

def _reject_unknown_params(q: dict, allowed: set[str]) -> bool:
    return not set(q.keys()).issubset(allowed)

def verify_request(
    now_sec: int,
    q_getall: Callable[[], dict],
    expected_res: str,                    # "decide" or "status"
    ensure_nonce: Callable[[str, str, int, int, int], bool]  # (rid,j,ts,skew,now)-> used/expired?
) -> Tuple[bool, dict, int]:
    secrets = get_secrets(now_sec)
    if not secrets:
        return False, {}, 503  # service misconfigured

    q_raw: dict = q_getall() or {}
    allowed = {"v", "t", "sig", "rid", "j"} | ({"action"} if expected_res == "decide" else set())
    if _reject_unknown_params(q_raw, allowed):
        return False, {}, 401
    for k, v in q_raw.items():
        if v != v.strip():
            return False, {}, 401

    v   = q_raw.get("v", "1")
    t   = q_raw.get("t", "")
    sig = (q_raw.get("sig", "") or "").lower()
    rid = (q_raw.get("rid", "") or "")
    j   = (q_raw.get("j", "") or "").lower()

    if v != "1":
        return False, {}, 401

    ts = _parse_ts(t)
    if ts is None or abs(now_sec - ts) > SKEW_SECONDS:
        return False, {}, 401
    if not validate_uuid4_lower(rid):
        return False, {}, 401
    if not re.fullmatch(r"[0-9a-f]{32,64}", j):
        return False, {}, 401

    base = canonical_base(v, ts, expected_res, rid, j)
    ok_any = False
    for s in secrets:
        expect = hmac.new(s, base.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expect, sig):
            ok_any = True
            break
    if not ok_any:
        return False, {}, 401

    # check replay using single shared clock
    try:
        replay = ensure_nonce(rid, j, ts, SKEW_SECONDS, now_sec)
    except Exception:
        return False, {}, 503  # transient storage issue
    if replay:
        return False, {}, 401

    return True, {"rid": rid, "j": j, "ts": ts}, 200

