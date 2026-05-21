"""
legitimate_tests.py
Positive test suite — verifies the framework correctly accepts legitimate TCU requests.

A1. TCU001 authenticates and receives a JWT                  → 200
A2. TCU001 uploads telemetry (has telemetry:write)           → 200
A3. TCU001 reads diagnostics (has diagnostics:read)          → 200
A4. TCU003 authenticates and receives a JWT                  → 200
A5. TCU003 issues a remote command (has command:unlock)      → 200
"""

import uuid
import requests
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:5000"
PASS = "[PASS]"
FAIL = "[FAIL]"


def print_response(label, response):
    print(f"\n    {label}")
    print(f"    Status : {response.status_code}")
    try:
        print(f"    Body   : {response.json()}")
    except Exception:
        print(f"    Body   : {response.text}")


def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    suffix = f" — {detail}" if detail else ""
    print(f"    {status} {label}{suffix}")
    return condition


# ---------------------------------------------------------------------------
# A1. Legitimate authentication — TCU001
# ---------------------------------------------------------------------------

def test_legitimate_authentication():
    print("\n" + "-" * 60)
    print("  A1. Legitimate Authentication — TCU001")
    print("  TCU001 is active, credentials are correct.")
    print("  Expected: 200, JWT issued, scopes returned.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU001",
        "secret": "secret123"
    })
    print_response("Login (expect 200 ALLOW)", r)

    got_token = r.status_code == 200 and "access_token" in r.json()
    check("TCU001 authenticated and token issued", got_token,
          f"got HTTP {r.status_code}")

    if got_token:
        scopes = r.json().get("scopes", [])
        check("Token carries expected scopes",
              "telemetry:write" in scopes and "diagnostics:read" in scopes,
              f"scopes = {scopes}")

    return got_token, r.json().get("access_token") if got_token else None


# ---------------------------------------------------------------------------
# A2. Authorised telemetry upload — TCU001
# ---------------------------------------------------------------------------

def test_authorised_telemetry(token):
    print("\n" + "-" * 60)
    print("  A2. Authorised Telemetry Upload — TCU001")
    print("  TCU001 holds telemetry:write scope.")
    print("  Expected: 200, data echoed back.")
    print("-" * 60)

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(f"{BASE_URL}/api/telemetry", headers=headers, json={
        "speed": 85,
        "battery": 72,
        "temperature": 36
    })
    print_response("POST /api/telemetry (expect 200 ALLOW)", r)
    return check("Telemetry accepted for authorised TCU", r.status_code == 200,
                 f"got HTTP {r.status_code}")


# ---------------------------------------------------------------------------
# A3. Authorised diagnostics access — TCU001
# ---------------------------------------------------------------------------

def test_authorised_diagnostics(token):
    print("\n" + "-" * 60)
    print("  A3. Authorised Diagnostics Access — TCU001")
    print("  TCU001 holds diagnostics:read scope.")
    print("  Expected: 200.")
    print("-" * 60)

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}/api/diagnostics", headers=headers)
    print_response("GET /api/diagnostics (expect 200 ALLOW)", r)
    return check("Diagnostics access granted for authorised TCU", r.status_code == 200,
                 f"got HTTP {r.status_code}")


# ---------------------------------------------------------------------------
# A4. Legitimate authentication — TCU003
# ---------------------------------------------------------------------------

def test_legitimate_tcu3_auth():
    print("\n" + "-" * 60)
    print("  A4. Legitimate Authentication — TCU003")
    print("  TCU003 is active and holds command:unlock.")
    print("  Expected: 200, JWT issued.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU003",
        "secret": "secret789"
    })
    print_response("Login (expect 200 ALLOW)", r)

    got_token = r.status_code == 200 and "access_token" in r.json()
    check("TCU003 authenticated and token issued", got_token,
          f"got HTTP {r.status_code}")

    if got_token:
        scopes = r.json().get("scopes", [])
        check("Token carries command:unlock scope",
              "command:unlock" in scopes,
              f"scopes = {scopes}")

    return got_token, r.json().get("access_token") if got_token else None


# ---------------------------------------------------------------------------
# A5. Authorised remote command — TCU003
# ---------------------------------------------------------------------------

def test_authorised_remote_command(token):
    print("\n" + "-" * 60)
    print("  A5. Authorised Remote Command — TCU003")
    print("  TCU003 holds command:unlock, sends a fresh request_id and timestamp.")
    print("  Expected: 200, command accepted.")
    print("-" * 60)

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json={
        "command": "unlock_doors",
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    print_response("POST /api/remote-command (expect 200 ALLOW)", r)
    return check("Remote command accepted for authorised TCU", r.status_code == 200,
                 f"got HTTP {r.status_code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

print("\n" + "=" * 60)
print("  LEGITIMATE ACCESS TESTS — TCU Vehicle-to-Cloud Framework")
print("  All requests below should be ACCEPTED by the framework.")
print("=" * 60)

a1_ok, tcu001_token = test_legitimate_authentication()
a2_ok = test_authorised_telemetry(tcu001_token) if tcu001_token else False
a3_ok = test_authorised_diagnostics(tcu001_token) if tcu001_token else False
a4_ok, tcu003_token = test_legitimate_tcu3_auth()
a5_ok = test_authorised_remote_command(tcu003_token) if tcu003_token else False

results = [
    ("A1 — Legitimate authentication (TCU001)",     a1_ok),
    ("A2 — Authorised telemetry upload (TCU001)",   a2_ok),
    ("A3 — Authorised diagnostics access (TCU001)", a3_ok),
    ("A4 — Legitimate authentication (TCU003)",     a4_ok),
    ("A5 — Authorised remote command (TCU003)",     a5_ok),
]

print("\n" + "=" * 60)
print("  RESULTS SUMMARY")
print("=" * 60)
for name, passed in results:
    print(f"  {PASS if passed else FAIL}  {name}")

all_passed = all(p for _, p in results)
print()
if all_passed:
    print("  All legitimate requests correctly accepted.")
else:
    print("  One or more checks failed — review output above.")
print("=" * 60)
