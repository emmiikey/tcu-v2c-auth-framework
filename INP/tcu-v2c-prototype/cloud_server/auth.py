import os
import jwt
from datetime import datetime, timedelta, timezone
from database import get_db_connection

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-later")


def get_tcu_by_id(tcu_id):
    conn = get_db_connection()
    tcu = conn.execute(
        "SELECT * FROM tcu_registry WHERE tcu_id = ?",
        (tcu_id,)
    ).fetchone()
    conn.close()
    return tcu


def verify_tcu_credentials(tcu_id, secret):
    tcu = get_tcu_by_id(tcu_id)

    if tcu is None:
        return None, "unknown TCU identity"

    if tcu["status"] == "revoked":
        return None, "revoked TCU identity"

    if tcu["status"] != "active":
        return None, f"TCU status is {tcu['status']}"

    if tcu["secret"] != secret:
        return None, "invalid TCU secret"

    return tcu, None


def create_access_token(tcu):
    payload = {
        "tcu_id": tcu["tcu_id"],
        "vehicle_id": tcu["vehicle_id"],
        "scopes": [scope.strip() for scope in tcu["allowed_scopes"].split(",")],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_access_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "token expired"
    except jwt.InvalidTokenError:
        return None, "invalid token"


def has_scope(payload, required_scope):
    return required_scope in payload.get("scopes", [])


def check_tcu_still_active(tcu_id):
    """
    Re-query the database for the TCU's current status.
    This catches revocations that happened after the JWT was issued — a token alone
    is not enough proof of ongoing authorisation for high-value operations.
    Returns (tcu_dict, None) if active, or (None, error_string) otherwise.
    """
    tcu = get_tcu_by_id(tcu_id)
    if tcu is None:
        return None, "TCU no longer registered"
    if tcu["status"] == "revoked":
        return None, "TCU has been revoked"
    if tcu["status"] != "active":
        return None, f"TCU status is {tcu['status']}"
    return dict(tcu), None