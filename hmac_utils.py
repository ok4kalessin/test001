import os, re, hmac, hashlib, logging, threading
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

LOG = logging.getLogger("hmac")

MAX_SKEW_SECONDS = 300


def _load_skew() -> int:
    raw = os.environ.get("HMAC_SKEW", "60")
    try:
        value = int(raw)
    except ValueError:
        LOG.error("Invalid HMAC_SKEW value '%s'; defaulting to 60 seconds.", raw)
        return 60
    if value < 0:
        LOG.error("Negative HMAC_SKEW (%d) is not allowed; using 0 seconds.", value)
        return 0
    if value > MAX_SKEW_SECONDS:
        LOG.warning(
            "HMAC_SKEW capped to %d seconds to contain the replay protection window.",
            MAX_SKEW_SECONDS,
        )
        return MAX_SKEW_SECONDS
    return value


SKEW_SECONDS = _load_skew()
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
@dataclass
class _SecretMaterial:
    value: bytes
    fingerprint: str
    source: str
    updated_on: Optional[str]


_SECRETS_CACHE = {"loaded_at": 0, "secrets": [], "fingerprint": ""}
_LOCK = threading.Lock()

_VAULT_URL = os.environ.get("HMAC_SECRET_VAULT_URL")
_ALLOW_ENV_SECRETS = (os.environ.get("ALLOW_ENV_HMAC_SECRET", "false").lower() == "true")
if not _VAULT_URL and not _ALLOW_ENV_SECRETS:
    raise RuntimeError(
        "HMAC_SECRET_VAULT_URL must be configured for managed secret rotation. "
        "(Set ALLOW_ENV_HMAC_SECRET=true only for local development.)"
    )
_VAULT_PRIMARY_NAME = os.environ.get("HMAC_SECRET_NAME", "hmac-primary")
_VAULT_SECONDARY_NAME = os.environ.get("HMAC_SECRET_PREVIOUS_NAME", "hmac-previous")
_SECRET_CLIENT: Optional[SecretClient] = None


def _get_secret_client() -> SecretClient:
    global _SECRET_CLIENT
    if _SECRET_CLIENT is None:
        if not _VAULT_URL:
            raise RuntimeError("HMAC_SECRET_VAULT_URL must be configured for managed secret access.")
        credential = DefaultAzureCredential()
        _SECRET_CLIENT = SecretClient(vault_url=_VAULT_URL, credential=credential)
    return _SECRET_CLIENT


def _load_env_secrets_unchecked() -> list[_SecretMaterial]:
    secs: list[_SecretMaterial] = []
    prim = (os.environ.get("HMAC_SECRET") or "").strip()
    prev = (os.environ.get("HMAC_SECRET_PREV") or "").strip()

    def parse(label: str, raw: str) -> Optional[_SecretMaterial]:
        if len(raw) >= 64:
            try:
                value = bytes.fromhex(raw)
            except ValueError:
                LOG.error("Invalid hex in HMAC secret env var '%s'.", label)
                return None
            fp = hashlib.sha256(value).hexdigest()[:12]
            return _SecretMaterial(value=value, fingerprint=f"env:{label}:{fp}", source="environment", updated_on=None)
        if raw:
            LOG.error("HMAC secret '%s' is too short; ignoring.", label)
        return None

    p = parse("HMAC_SECRET", prim)
    q = parse("HMAC_SECRET_PREV", prev)
    if p:
        secs.append(p)
    if q:
        if p and p.value == q.value:
            LOG.warning("HMAC_SECRET and HMAC_SECRET_PREV are identical; rotation ineffective.")
        secs.append(q)
    return secs


def _load_key_vault_secrets() -> list[_SecretMaterial]:
    client = _get_secret_client()
    materials: list[_SecretMaterial] = []

    def fetch(name: str) -> Optional[_SecretMaterial]:
        if not name:
            return None
        secret = client.get_secret(name)
        raw = secret.value.strip()
        if len(raw) < 64:
            LOG.error("Secret '%s' from Key Vault is too short; ignoring.", name)
            return None
        try:
            value = bytes.fromhex(raw)
        except ValueError:
            LOG.error("Secret '%s' from Key Vault is not valid hex; ignoring.", name)
            return None
        fingerprint = hashlib.sha256(value).hexdigest()[:12]
        updated = None
        props = getattr(secret, "properties", None)
        if props and getattr(props, "updated_on", None):
            updated = props.updated_on.replace(microsecond=0).isoformat() + "Z"
        return _SecretMaterial(
            value=value,
            fingerprint=f"vault:{name}:{fingerprint}",
            source="key-vault",
            updated_on=updated,
        )

    primary = fetch(_VAULT_PRIMARY_NAME)
    if primary:
        materials.append(primary)
    secondary = fetch(_VAULT_SECONDARY_NAME)
    if secondary:
        if primary and primary.value == secondary.value:
            LOG.warning("Key Vault secrets %s and %s are identical; rotation ineffective.", _VAULT_PRIMARY_NAME, _VAULT_SECONDARY_NAME)
        materials.append(secondary)

    return materials


def _load_secret_material() -> list[bytes]:
    sources: list[_SecretMaterial]
    try:
        if _VAULT_URL:
            sources = _load_key_vault_secrets()
        else:
            LOG.warning("Loading HMAC secrets from environment; audit protections are reduced.")
            sources = _load_env_secrets_unchecked()
    except Exception:
        LOG.exception("Unable to load HMAC secrets from configured source.")
        return []

    if not sources:
        LOG.error("No HMAC secrets were loaded; service is misconfigured.")
        return []

    fingerprint_report = ", ".join(
        f"{material.fingerprint}{'@' + material.updated_on if material.updated_on else ''}"
        for material in sources
    )

    if fingerprint_report != _SECRETS_CACHE["fingerprint"]:
        LOG.info(
            "Loaded %d HMAC secrets from %s (%s).",
            len(sources),
            sources[0].source,
            fingerprint_report,
        )
        _SECRETS_CACHE["fingerprint"] = fingerprint_report

    return [material.value for material in sources]

def get_secrets(now_sec: int) -> Optional[list[bytes]]:
    if now_sec - _SECRETS_CACHE["loaded_at"] < 5 and _SECRETS_CACHE["secrets"]:
        return _SECRETS_CACHE["secrets"]
    with _LOCK:
        if now_sec - _SECRETS_CACHE["loaded_at"] < 5 and _SECRETS_CACHE["secrets"]:
            return _SECRETS_CACHE["secrets"]
        secs = _load_secret_material()
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
    def _reject(code: int, reason: str) -> Tuple[bool, dict, int]:
        LOG.warning("Rejected %s request: %s", expected_res, reason)
        return False, {}, code

    secrets = get_secrets(now_sec)
    if not secrets:
        return _reject(503, "no secrets available")

    q_raw: dict = q_getall() or {}
    allowed = {"v", "t", "sig", "rid", "j"} | ({"action"} if expected_res == "decide" else set())
    if _reject_unknown_params(q_raw, allowed):
        return _reject(401, "unexpected query parameters present")
    for k, v in q_raw.items():
        if v != v.strip():
            return _reject(401, f"parameter {k} contains surrounding whitespace")

    v   = q_raw.get("v", "1")
    t   = q_raw.get("t", "")
    sig = (q_raw.get("sig", "") or "").lower()
    rid = (q_raw.get("rid", "") or "")
    j   = (q_raw.get("j", "") or "").lower()

    if v != "1":
        return _reject(401, f"unsupported version {v}")

    ts = _parse_ts(t)
    if ts is None or abs(now_sec - ts) > SKEW_SECONDS:
        return _reject(401, "timestamp invalid or outside skew window")
    if not validate_uuid4_lower(rid):
        return _reject(401, "rid not a canonical uuid4")
    if not re.fullmatch(r"[0-9a-f]{32,64}", j):
        return _reject(401, "nonce 'j' not lowercase hex")

    base = canonical_base(v, ts, expected_res, rid, j)
    ok_any = False
    for s in secrets:
        expect = hmac.new(s, base.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expect, sig):
            ok_any = True
            break
    if not ok_any:
        return _reject(401, "signature mismatch")

    # check replay using single shared clock
    try:
        replay = ensure_nonce(rid, j, ts, SKEW_SECONDS, now_sec)
    except Exception:
        LOG.exception("Nonce persistence failed during %s request.", expected_res)
        return False, {}, 503  # transient storage issue
    if replay:
        return _reject(401, "nonce replay detected")

    return True, {"rid": rid, "j": j, "ts": ts}, 200

