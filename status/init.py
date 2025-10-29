import time, json
import azure.functions as func
from hmac_utils import verify_request
import store

def main(req: func.HttpRequest) -> func.HttpResponse:
    now = int(time.time())
    ok, info, code = verify_request(
        now,
        lambda: dict(req.params.items()),
        expected_res="status",
        ensure_nonce=store.nonce_used_or_expired
    )
    if not ok:
        return func.HttpResponse("Service Unavailable" if code==503 else "Unauthorized", status_code=code)

    rid = info["rid"]
    try:
        dec = store.get_decision(rid) or {"status":"pending"}
    except Exception:
        return func.HttpResponse("Service Unavailable", status_code=503)

    return func.HttpResponse(json.dumps(dec), mimetype="application/json", status_code=200)

