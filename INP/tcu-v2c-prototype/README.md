# TCU Vehicle-to-Cloud Authentication and Authorisation Prototype

Honours project proof-of-concept for:
**"A TCU-Centric Reference Framework and Prototype for Secure Vehicle-to-Cloud Authentication and Authorisation"**

This prototype demonstrates TCU-to-cloud authentication, scope-based API authorisation,
protected remote commands, live revocation checking, replay protection, and comprehensive
audit logging using Flask, SQLite, and PyJWT.

---

## Project Structure

```
tcu-v2c-prototype/
    cloud_server/
        app.py          # Flask API routes — all security checks inline with comments
        auth.py         # JWT issuance, credential verification, live status checks
        database.py     # SQLite schema, seed data, replay protection helpers
        policies.py     # Scope and risk-level policy definitions
        logs.py         # Audit log retrieval
    data/
        tcu_registry.db # SQLite database (auto-created on first run)
    tcu_client/
        legitimate_tests.py  # Positive tests: five scenarios the framework must ACCEPT
        attacker_tests.py    # Attack tests: four threats + replay the framework must DENY
        valid_tcu.py         # Simple successful flow reference script
        fake_tcu.py          # Threat 1: TCU impersonation — unknown TCU rejected
        revoked_tcu.py       # Threat 4: revoked identity — denied at login
        low_privilege_tcu.py # Threat 3: privilege escalation blocked by scope check
    requirements.txt
    README.md
```

---

## TCU Registry (seed data)

| TCU ID  | Vehicle | Status  | Allowed Scopes                                            |
|---------|---------|---------|-----------------------------------------------------------|
| TCU001  | VEH001  | active  | `telemetry:write`, `diagnostics:read`                     |
| TCU002  | VEH002  | revoked | `telemetry:write`                                         |
| TCU003  | VEH003  | active  | `telemetry:write`, `diagnostics:read`, `command:unlock`   |
| TCU004  | VEH004  | active  | `telemetry:write`                                         |

TCU004 exists to demonstrate Threat 2: a valid, active TCU with only `telemetry:write`
being denied access to the `diagnostics:read` endpoint.

---

## Setup

### 1. Create and activate a virtual environment

```bash
cd tcu-v2c-prototype
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialise the database

The database is created automatically when the Flask server starts.
To reset it manually (wipes and re-seeds all data):

```bash
cd cloud_server
python database.py
```

---

## Running the server

```bash
cd cloud_server
python app.py
```

The server starts at `http://127.0.0.1:5000`.

To use a custom secret key:
```bash
SECRET_KEY=your-secret python app.py
```

---

## Running the attack simulation tests

With the Flask server running, open a second terminal from the project root:

```bash
# Positive tests — five scenarios the framework must ACCEPT
python tcu_client/legitimate_tests.py

# Attack tests — four threats + replay the framework must DENY
python tcu_client/attacker_tests.py

# Or run individual simulations:
python tcu_client/fake_tcu.py          # Threat 1: impersonation
python tcu_client/revoked_tcu.py       # Threat 4: revoked identity
python tcu_client/low_privilege_tcu.py # Threat 3: missing scope
python tcu_client/valid_tcu.py         # Reference: simple successful flow
```

---

## Threat Remediation Summary

| Threat | Attack Scenario | Framework Component | Mechanism | Result |
|--------|----------------|---------------------|-----------|--------|
| **1. TCU Impersonation** | TCU999 (not registered) attempts login | TCU Identity Registry + Authentication Layer | `verify_tcu_credentials()` looks up `tcu_id` in DB; returns `"unknown TCU identity"` if not found | **401 Denied** — no token issued |
| **2. Unauthorised API Access** | TCU004 (`telemetry:write` only) calls `/api/diagnostics` | API Authorisation Layer | Each endpoint checks `has_scope(payload, required_scope)` against token claims | **403 Denied** — missing `diagnostics:read` |
| **3. Protected Command Misuse** | TCU001 (no `command:unlock`) calls `/api/remote-command` | API Authorisation Layer + Remote Command Policy Layer | Scope check at endpoint; high-risk policy enforced before any command is executed | **403 Denied** — missing `command:unlock` |
| **4. Revoked Identity Access** | TCU002 (status = `revoked`) attempts login; or any revoked TCU uses an existing token | Revocation Layer + Live Status Check | Login: `verify_tcu_credentials()` rejects revoked status. API: `check_tcu_still_active()` re-queries DB on every protected request | **401 Denied** — revoked at login and at API level |
| **Bonus: Replay Attack** | TCU003 replays a used `request_id` | Replay Protection Layer | `is_request_id_used()` checks `used_request_ids` table; `store_request_id()` consumes it on first use | **409 Denied** — replayed request_id |

---

## Security checks enforced per endpoint

### `/auth/tcu-login`
1. TCU must exist in the identity registry
2. TCU status must be `active` (not `revoked` or `suspended`)
3. Secret must match the stored credential
4. Short-lived JWT (15 minutes) issued only after all checks pass

### `/api/telemetry` and `/api/diagnostics`
1. Valid, non-expired JWT required
2. TCU status re-checked against DB (catches post-token revocation)
3. Required scope enforced (`telemetry:write` / `diagnostics:read`)

### `/api/remote-command` (HIGH RISK — full policy layer)
1. Valid, non-expired JWT required
2. TCU status re-checked against DB
3. `command:unlock` scope required
4. `request_id` must be present in request body
5. `request_id` must not have been used before (replay protection)
6. `vehicle_id` in token must match DB record (ownership verification)
7. Optional `timestamp` must be within 60 seconds (request freshness)
8. `request_id` consumed in `used_request_ids` table after acceptance

---

## Audit log events

Every decision (allow or deny) is logged to the `audit_logs` table and readable via:

```bash
curl -s http://127.0.0.1:5000/logs | python3 -m json.tool
```

Logged denial reasons include:
- `unknown TCU identity`
- `invalid TCU secret`
- `revoked TCU identity`
- `TCU status is suspended`
- `missing bearer token`
- `token expired`
- `invalid token`
- `missing telemetry:write scope` / `missing diagnostics:read scope` / `missing command:unlock scope`
- `missing request_id`
- `replayed request_id: <id>`
- `vehicle_id mismatch`
- `request timestamp too old`

---

## Testing with curl

### Authenticate a valid TCU

```bash
curl -s -X POST http://127.0.0.1:5000/auth/tcu-login \
  -H "Content-Type: application/json" \
  -d '{"tcu_id": "TCU001", "secret": "secret123"}' | python3 -m json.tool
```

Copy the `access_token`, then use `TOKEN=<value>` in the requests below.

### Upload telemetry

```bash
curl -s -X POST http://127.0.0.1:5000/api/telemetry \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"speed": 85, "battery": 72, "temperature": 36}' | python3 -m json.tool
```

### Access diagnostics

```bash
curl -s http://127.0.0.1:5000/api/diagnostics \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Send a remote command (TCU003 only — has command:unlock)

```bash
# Get TCU003 token first
curl -s -X POST http://127.0.0.1:5000/auth/tcu-login \
  -H "Content-Type: application/json" \
  -d '{"tcu_id": "TCU003", "secret": "secret789"}' | python3 -m json.tool

# Then send command (replace TOKEN and use a unique request_id)
curl -s -X POST http://127.0.0.1:5000/api/remote-command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "unlock_doors", "request_id": "req-001", "timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}' \
  | python3 -m json.tool
```

### Try a revoked TCU (expect 401)

```bash
curl -s -X POST http://127.0.0.1:5000/auth/tcu-login \
  -H "Content-Type: application/json" \
  -d '{"tcu_id": "TCU002", "secret": "secret456"}' | python3 -m json.tool
```

### Revoke a TCU at runtime

Requires the `X-Admin-Key` header. Default key is `admin-secret` (override with `ADMIN_KEY` env var).

```bash
curl -s -X POST http://127.0.0.1:5000/admin/revoke-tcu \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: admin-secret" \
  -d '{"tcu_id": "TCU001"}' | python3 -m json.tool
```

### View audit logs

```bash
curl -s http://127.0.0.1:5000/logs | python3 -m json.tool
```

---

## Design principles demonstrated

| Principle                       | Implementation                                                                 |
|---------------------------------|--------------------------------------------------------------------------------|
| Least privilege                 | Each TCU is granted only the scopes it needs; no blanket access                |
| Explicit trust verification     | Every protected request validates the JWT before any logic runs                |
| Separation of authn / authz     | `auth.py` handles identity; scope checks in `app.py` gate each endpoint        |
| Risk-based protection           | `/api/remote-command` enforces seven security checks vs. three for low-risk endpoints |
| Lifecycle-aware trust           | `check_tcu_still_active()` re-queries DB on every protected call               |
| Replay resistance               | `request_id` consumed in `used_request_ids` table; duplicate rejected with 409 |
| Auditability                    | Every allow and deny decision logged with timestamp, TCU ID, endpoint, and reason |
