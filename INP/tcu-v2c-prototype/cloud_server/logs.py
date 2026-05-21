# logs.py
# Provides helper functions for retrieving audit log entries.
# Audit logging supports the auditability design principle:
# every authentication attempt and authorisation decision is recorded.

from database import get_db_connection


def get_audit_logs(limit=200):
    """
    Retrieve audit log entries in reverse chronological order.
    Returns a list of dicts, each representing one log entry.
    """
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT tcu_id, endpoint, action, decision, reason, created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]
