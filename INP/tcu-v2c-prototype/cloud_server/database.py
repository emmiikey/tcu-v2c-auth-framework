import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "tcu_registry.db"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tcu_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tcu_id TEXT NOT NULL UNIQUE,
            vehicle_id TEXT NOT NULL,
            secret TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'suspended')),
            allowed_scopes TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tcu_id TEXT,
            endpoint TEXT NOT NULL,
            action TEXT,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS used_request_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL UNIQUE,
            tcu_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def seed_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    tcus = [
        ("TCU001", "VEH001", "secret123", "active", "telemetry:write,diagnostics:read"),
        ("TCU002", "VEH002", "secret456", "revoked", "telemetry:write"),
        ("TCU003", "VEH003", "secret789", "active", "telemetry:write,diagnostics:read,command:unlock"),
        # TCU004 has only telemetry:write — used to demonstrate Threat 2 (unauthorised API access)
        ("TCU004", "VEH004", "secret000", "active", "telemetry:write"),
    ]

    for tcu in tcus:
        cursor.execute("""
            INSERT OR IGNORE INTO tcu_registry 
            (tcu_id, vehicle_id, secret, status, allowed_scopes)
            VALUES (?, ?, ?, ?, ?)
        """, tcu)

    conn.commit()
    conn.close()

def insert_audit_log(tcu_id, endpoint, action, decision, reason):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO audit_logs (tcu_id, endpoint, action, decision, reason)
        VALUES (?, ?, ?, ?, ?)
    """, (tcu_id, endpoint, action, decision, reason))
    conn.commit()
    conn.close()


def is_request_id_used(request_id):
    """Return True if this request_id has already been processed (replay protection)."""
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM used_request_ids WHERE request_id = ?",
        (request_id,)
    ).fetchone()
    conn.close()
    return row is not None


def store_request_id(request_id, tcu_id):
    """Record a request_id as consumed so it cannot be replayed."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO used_request_ids (request_id, tcu_id) VALUES (?, ?)",
        (request_id, tcu_id)
    )
    conn.commit()
    conn.close()


def revoke_tcu_by_id(tcu_id):
    conn = get_db_connection()
    cursor = conn.execute("""
        UPDATE tcu_registry
        SET status = 'revoked'
        WHERE tcu_id = ?
    """, (tcu_id,))
    conn.commit()
    conn.close()
    return cursor.rowcount


if __name__ == "__main__":
    init_db()
    seed_data()
    print(f"Database initialised at: {DB_PATH}")