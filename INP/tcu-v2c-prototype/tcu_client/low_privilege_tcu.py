"""
low_privilege_tcu.py
Simulates a low-privilege TCU (TCU001) attempting to access a high-privilege endpoint.

Demonstrates:
- Successful authentication (TCU001 is active and credentials are valid)
- Authorised telemetry upload (within granted scopes)
- Denied remote command (command:unlock is NOT in TCU001's allowed_scopes)

This script reflects the least-privilege and separation of authentication/authorisation
design principles. Authentication succeeds, but that alone does not grant access to
higher-privilege endpoints. This addresses Threat 3: Misuse of a protected remote command.
"""

import requests

BASE_URL = "http://127.0.0.1:5000"


def print_response(label, response):
    print(f"\n--- {label} ---")
    print(f"Status: {response.status_code}")
    try:
        print(f"Body:   {response.json()}")
    except Exception:
        print(f"Body:   {response.text}")


print("\n=== LOW-PRIVILEGE TCU (TCU001) PRIVILEGE ESCALATION ATTEMPT ===")

# Step 1: Authenticate — should SUCCEED (TCU001 is active)
login_resp = requests.post(f"{BASE_URL}/auth/tcu-login", json={
    "tcu_id": "TCU001",
    "secret": "secret123"
})
print_response("Login (expect 200 ALLOW)", login_resp)

if login_resp.status_code != 200:
    print("\nLogin failed. Is the Flask server running?")
    exit(1)

token = login_resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"\nGranted scopes: {login_resp.json()['scopes']}")

# Step 2: Upload telemetry — should SUCCEED (telemetry:write is in scope)
telemetry_resp = requests.post(f"{BASE_URL}/api/telemetry", headers=headers, json={
    "speed": 60,
    "battery": 90,
    "temperature": 33
})
print_response("Telemetry Upload (expect 200 ALLOW)", telemetry_resp)

# Step 3: Attempt remote command — should be DENIED (no command:unlock scope)
# This is the key test: an authenticated TCU cannot escalate to a higher-privilege endpoint.
cmd_resp = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json={
    "command": "unlock_doors"
})
print_response("Remote Command Privilege Escalation (expect 403 DENY)", cmd_resp)

if cmd_resp.status_code == 403:
    print("\n[PASS] Privilege escalation correctly blocked.")
else:
    print("\n[FAIL] Remote command was incorrectly allowed for low-privilege TCU.")
