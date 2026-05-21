"""
attacker_tests.py
Attack simulation — verifies the framework correctly blocks all four main threats
plus a replay attack.

B1. Threat 1 — TCU Impersonation:
    TCU999 (not in registry) tries to authenticate.
    Expected: 401 — unknown TCU identity.

B2. Threat 2 — Unauthorised API Access:
    TCU004 (active, telemetry:write only) tries diagnostics:read.
    Expected: 403 — missing diagnostics:read scope.

B3. Threat 3 — Protected Remote Command Misuse:
    TCU001 (active, no command:unlock) tries /api/remote-command.
    Expected: 403 — missing command:unlock scope.

B4. Threat 4 — Revoked Identity Access:
    TCU002 (revoked) tries to authenticate.
    Expected: 401 — revoked TCU identity, no token issued.

B5. Bonus — Replay Attack:
    TCU003 submits a valid command, then replays the same request_id.
    Expected: first 200, second 409.
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
# B1. Threat 1: TCU Impersonation
# ---------------------------------------------------------------------------

def test_tcu_impersonation():
    print("\n" + "-" * 60)
    print("  B1. THREAT 1 — TCU Impersonation")
    print("  Attacker: TCU999 is not in the identity registry.")
    print("  Expected: 401 — unknown TCU identity.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU999",
        "secret": "hacked123"
    })
    print_response("Login as TCU999 (expect 401 DENY)", r)
    return check("Unknown TCU rejected at authentication", r.status_code == 401,
                 f"got HTTP {r.status_code}, reason: {r.json().get('error', 'n/a')}")


# ---------------------------------------------------------------------------
# B2. Threat 2: Unauthorised API Access (wrong scope)
# ---------------------------------------------------------------------------

def test_unauthorised_api_access():
    print("\n" + "-" * 60)
    print("  B2. THREAT 2 — Unauthorised API Access")
    print("  Attacker: TCU004 (active, telemetry:write only) tries diagnostics:read.")
    print("  Expected: 403 — missing diagnostics:read scope.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU004",
        "secret": "secret000"
    })
    print_response("TCU004 login (expect 200)", r)

    if r.status_code != 200:
        print(f"    {FAIL} TCU004 login failed — cannot complete test.")
        return False

    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\n    Granted scopes: {r.json()['scopes']}")

    r2 = requests.get(f"{BASE_URL}/api/diagnostics", headers=headers)
    print_response("GET /api/diagnostics (expect 403 DENY)", r2)
    return check("Request without required scope rejected", r2.status_code == 403,
                 f"got HTTP {r2.status_code}, reason: {r2.json().get('error', 'n/a')}")


# ---------------------------------------------------------------------------
# B3. Threat 3: Protected Remote Command Misuse (missing command:unlock)
# ---------------------------------------------------------------------------

def test_remote_command_misuse():
    print("\n" + "-" * 60)
    print("  B3. THREAT 3 — Protected Remote Command Misuse")
    print("  Attacker: TCU001 (active, no command:unlock) tries /api/remote-command.")
    print("  Expected: 403 — missing command:unlock scope.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU001",
        "secret": "secret123"
    })
    print_response("TCU001 login (expect 200)", r)

    if r.status_code != 200:
        print(f"    {FAIL} TCU001 login failed — cannot complete test.")
        return False

    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\n    Granted scopes: {r.json()['scopes']}")

    r2 = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json={
        "command": "unlock_doors",
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    print_response("POST /api/remote-command (expect 403 DENY)", r2)
    return check("Remote command without required scope rejected", r2.status_code == 403,
                 f"got HTTP {r2.status_code}, reason: {r2.json().get('error', 'n/a')}")


# ---------------------------------------------------------------------------
# B4. Threat 4: Access by a Revoked Identity
# ---------------------------------------------------------------------------

def test_revoked_identity():
    print("\n" + "-" * 60)
    print("  B4. THREAT 4 — Revoked Identity Access")
    print("  Attacker: TCU002 (status = revoked) tries to authenticate.")
    print("  Expected: 401 — revoked TCU identity, no token issued.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU002",
        "secret": "secret456"
    })
    print_response("TCU002 login (expect 401 DENY)", r)
    login_blocked = check("Revoked TCU denied at login", r.status_code == 401,
                          f"got HTTP {r.status_code}, reason: {r.json().get('error', 'n/a')}")
    no_token = "access_token" not in r.json()
    check("No token issued to revoked TCU", no_token)
    return login_blocked and no_token


# ---------------------------------------------------------------------------
# B5. Bonus: Replay Attack
# ---------------------------------------------------------------------------

def test_replay_attack():
    print("\n" + "-" * 60)
    print("  B5. BONUS — Replay Attack")
    print("  TCU003 submits a valid command then replays the same request_id.")
    print("  Expected: first 200, second 409.")
    print("-" * 60)

    r = requests.post(f"{BASE_URL}/auth/tcu-login", json={
        "tcu_id": "TCU003",
        "secret": "secret789"
    })
    print_response("TCU003 login (expect 200)", r)

    if r.status_code != 200:
        print(f"    {FAIL} TCU003 login failed — cannot complete test.")
        return False

    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    replay_id = str(uuid.uuid4())
    payload = {
        "command": "unlock_doors",
        "request_id": replay_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    r1 = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json=payload)
    print_response("First command (expect 200 ALLOW)", r1)
    first_ok = check("First request accepted", r1.status_code == 200,
                     f"got HTTP {r1.status_code}")

    r2 = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json=payload)
    print_response("Replayed request (expect 409 DENY)", r2)
    replay_blocked = check("Replayed request_id rejected", r2.status_code == 409,
                           f"got HTTP {r2.status_code}, reason: {r2.json().get('error', 'n/a')}")

    return first_ok and replay_blocked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

print("\n" + "=" * 60)
print("  ATTACK SIMULATION — TCU Vehicle-to-Cloud Framework")
print("  All requests below should be DENIED by the framework.")
print("=" * 60)

results = [
    ("B1 — Threat 1: TCU Impersonation blocked",        test_tcu_impersonation()),
    ("B2 — Threat 2: Unauthorised API access blocked",  test_unauthorised_api_access()),
    ("B3 — Threat 3: Protected command misuse blocked", test_remote_command_misuse()),
    ("B4 — Threat 4: Revoked identity blocked",         test_revoked_identity()),
    ("B5 — Bonus: Replay attack blocked",               test_replay_attack()),
]

print("\n" + "=" * 60)
print("  RESULTS SUMMARY")
print("=" * 60)
for name, passed in results:
    print(f"  {PASS if passed else FAIL}  {name}")

all_passed = all(p for _, p in results)
print()
if all_passed:
    print("  All threats correctly mitigated by the framework.")
else:
    print("  One or more checks failed — review output above.")
print("=" * 60)
