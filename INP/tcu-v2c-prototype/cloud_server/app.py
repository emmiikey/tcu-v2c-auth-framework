import os
from flask import Flask, request
from datetime import datetime, timezone
from database import (
    init_db,
    seed_data,
    insert_audit_log,
    revoke_tcu_by_id,
    is_request_id_used,
    store_request_id,
)
from auth import (
    verify_tcu_credentials,
    create_access_token,
    decode_access_token,
    has_scope,
    check_tcu_still_active,
    get_tcu_by_id,
)
from logs import get_audit_logs

ADMIN_KEY = os.getenv("ADMIN_KEY", "admin-secret")

app = Flask(__name__)

init_db()
seed_data()


@app.route("/")
def home():
    return {
        "message": "TCU Vehicle-to-Cloud Authentication and Authorisation Server is running"
    }


@app.route("/health")
def health_check():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Authentication endpoint
# ---------------------------------------------------------------------------

@app.route("/auth/tcu-login", methods=["POST"])
def tcu_login():
    data = request.get_json()

    if not data:
        return {"error": "Missing JSON body"}, 400

    tcu_id = data.get("tcu_id")
    secret = data.get("secret")

    if not tcu_id or not secret:
        return {"error": "tcu_id and secret are required"}, 400

    # Security check 1: verify TCU exists, is active, and credentials are correct
    tcu, error = verify_tcu_credentials(tcu_id, secret)

    if error:
        insert_audit_log(tcu_id, "/auth/tcu-login", "login", "deny", error)
        return {"error": error}, 401

    # Issue a short-lived JWT (15 minutes) only after all checks pass
    token = create_access_token(tcu)
    insert_audit_log(tcu_id, "/auth/tcu-login", "login", "allow", "authenticated")

    return {
        "message": "TCU authenticated successfully",
        "access_token": token,
        "tcu_id": tcu["tcu_id"],
        "vehicle_id": tcu["vehicle_id"],
        "scopes": [scope.strip() for scope in tcu["allowed_scopes"].split(",")]
    }


# ---------------------------------------------------------------------------
# Token validation helper (used by all protected endpoints)
# ---------------------------------------------------------------------------

def get_token_payload():
    auth_header = request.headers.get("Authorization")

    # Security check: bearer token must be present
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "missing bearer token"

    token = auth_header.split(" ")[1]
    # Security check: token must be valid and not expired
    return decode_access_token(token)


# ---------------------------------------------------------------------------
# Telemetry endpoint (low-risk, requires telemetry:write)
# ---------------------------------------------------------------------------

@app.route("/api/telemetry", methods=["POST"])
def receive_telemetry():
    # Security check 1: valid, non-expired JWT required
    payload, error = get_token_payload()
    if error:
        insert_audit_log(None, "/api/telemetry", "telemetry", "deny", error)
        return {"error": error}, 401

    tcu_id = payload["tcu_id"]

    # Security check 2: re-query DB to catch revocations that occurred after token issuance
    tcu, status_error = check_tcu_still_active(tcu_id)
    if status_error:
        insert_audit_log(tcu_id, "/api/telemetry", "telemetry", "deny", f"revoked identity: {status_error}")
        return {"error": status_error}, 401

    # Security check 3: scope enforcement
    if not has_scope(payload, "telemetry:write"):
        insert_audit_log(tcu_id, "/api/telemetry", "telemetry", "deny", "missing telemetry:write scope")
        return {"error": "insufficient scope for telemetry"}, 403

    data = request.get_json() or {}
    insert_audit_log(tcu_id, "/api/telemetry", "telemetry", "allow", "telemetry accepted")

    return {
        "message": "Telemetry received",
        "from_tcu": tcu_id,
        "vehicle_id": payload["vehicle_id"],
        "data": data
    }


# ---------------------------------------------------------------------------
# Diagnostics endpoint (low-risk, requires diagnostics:read)
# ---------------------------------------------------------------------------

@app.route("/api/diagnostics", methods=["GET"])
def diagnostics():
    # Security check 1: valid, non-expired JWT required
    payload, error = get_token_payload()
    if error:
        insert_audit_log(None, "/api/diagnostics", "diagnostics", "deny", error)
        return {"error": error}, 401

    tcu_id = payload["tcu_id"]

    # Security check 2: re-query DB to catch post-issuance revocations
    tcu, status_error = check_tcu_still_active(tcu_id)
    if status_error:
        insert_audit_log(tcu_id, "/api/diagnostics", "diagnostics", "deny", f"revoked identity: {status_error}")
        return {"error": status_error}, 401

    # Security check 3: scope enforcement
    if not has_scope(payload, "diagnostics:read"):
        insert_audit_log(tcu_id, "/api/diagnostics", "diagnostics", "deny", "missing diagnostics:read scope")
        return {"error": "insufficient scope for diagnostics"}, 403

    insert_audit_log(tcu_id, "/api/diagnostics", "diagnostics", "allow", "diagnostics access granted")

    return {
        "message": "Diagnostics endpoint reached",
        "from_tcu": tcu_id
    }


# ---------------------------------------------------------------------------
# Remote command endpoint (HIGH-risk — enforces the full policy layer)
# ---------------------------------------------------------------------------

@app.route("/api/remote-command", methods=["POST"])
def remote_command():
    # Security check 1: valid, non-expired JWT required
    payload, error = get_token_payload()
    if error:
        insert_audit_log(None, "/api/remote-command", "remote-command", "deny", error)
        return {"error": error}, 401

    tcu_id = payload["tcu_id"]

    # Security check 2: re-query DB to ensure TCU is still active (live revocation check)
    # A valid token is not sufficient for high-risk commands — DB status is always verified
    tcu, status_error = check_tcu_still_active(tcu_id)
    if status_error:
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", f"revoked identity: {status_error}")
        return {"error": status_error}, 401

    # Security check 3: scope enforcement — command:unlock required for remote commands
    if not has_scope(payload, "command:unlock"):
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "missing command:unlock scope")
        return {"error": "insufficient scope for remote command"}, 403

    data = request.get_json() or {}

    # Security check 4: request_id is mandatory — needed for replay protection
    request_id = data.get("request_id")
    if not request_id:
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "missing request_id")
        return {"error": "request_id is required for remote commands"}, 400

    # Security check 5: replay protection — reject any previously seen request_id
    if is_request_id_used(request_id):
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", f"replayed request_id: {request_id}")
        return {"error": "replayed request: this request_id has already been processed"}, 409

    # Security check 6: vehicle_id ownership — token's vehicle_id must match the DB record
    # Prevents a TCU from issuing commands on behalf of a different vehicle
    if tcu["vehicle_id"] != payload.get("vehicle_id"):
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "vehicle_id mismatch")
        return {"error": "vehicle identity mismatch"}, 403

    # Security check 7: request freshness — timestamp is mandatory, not optional
    # Every protected command must prove it is recent, not just unique
    timestamp_str = data.get("timestamp")
    if not timestamp_str:
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "missing timestamp")
        return {"error": "timestamp is required for remote commands"}, 400

    try:
        req_time = datetime.fromisoformat(timestamp_str)
        if req_time.tzinfo is None:
            req_time = req_time.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - req_time).total_seconds()
        if age_seconds > 60:
            insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "request timestamp too old")
            return {"error": "request is too old (max 60 seconds)"}, 400
    except ValueError:
        insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "deny", "invalid timestamp format")
        return {"error": "invalid timestamp format — use ISO-8601 UTC"}, 400

    # All checks passed — consume the request_id to prevent future replay
    store_request_id(request_id, tcu_id)
    insert_audit_log(tcu_id, "/api/remote-command", "remote-command", "allow", "remote command accepted")

    return {
        "message": "Remote command accepted",
        "from_tcu": tcu_id,
        "vehicle_id": payload["vehicle_id"],
        "data": data
    }


# ---------------------------------------------------------------------------
# Admin: runtime TCU revocation
# ---------------------------------------------------------------------------

@app.route("/admin/revoke-tcu", methods=["POST"])
def revoke_tcu():
    # Security check: admin key required — revocation is an administrative action
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        insert_audit_log(None, "/admin/revoke-tcu", "revoke", "deny", "missing or invalid admin key")
        return {"error": "invalid or missing admin key"}, 401

    data = request.get_json()

    if not data or not data.get("tcu_id"):
        return {"error": "tcu_id is required"}, 400

    tcu_id = data["tcu_id"]
    updated = revoke_tcu_by_id(tcu_id)

    if updated == 0:
        return {"error": "TCU not found"}, 404

    insert_audit_log(tcu_id, "/admin/revoke-tcu", "revoke", "allow", "TCU revoked")

    return {
        "message": "TCU revoked successfully",
        "tcu_id": tcu_id
    }


# ---------------------------------------------------------------------------
# Audit log retrieval
# ---------------------------------------------------------------------------

@app.route("/logs", methods=["GET"])
def get_logs():
    return {
        "message": "Audit logs retrieved",
        "logs": get_audit_logs()
    }


if __name__ == "__main__":
    app.run(debug=True)
