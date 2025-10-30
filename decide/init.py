import time

import azure.functions as func

from hmac_utils import verify_request
import store

def main(req: func.HttpRequest) -> func.HttpResponse:
    if req.method != "POST":
        return func.HttpResponse("Method Not Allowed", status_code=405)

    content_type = (req.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
        return func.HttpResponse("Unsupported Media Type", status_code=415)

    now = int(time.time())
    ok, info, code = verify_request(
        now,
        lambda: dict(req.params.items()),
        expected_res="decide",
        ensure_nonce=store.nonce_used_or_expired
    )
    if not ok:
        return func.HttpResponse("Service Unavailable" if code==503 else "Unauthorized", status_code=code)

    rid = info["rid"]
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Bad Request", status_code=400)

    action = (payload.get("action") if isinstance(payload, dict) else None) or (req.params.get("action") or "")
    action = action.lower()
    if action not in ("approve", "deny"):
        return func.HttpResponse("Bad Request", status_code=400)

    try:
        created = store.upsert_decision_once(rid, "approved" if action=="approve" else "denied", "service-desk")
    except Exception:
        return func.HttpResponse("Service Unavailable", status_code=503)

    return func.HttpResponse("OK" if created else "Conflict", status_code=200 if created else 409)

