"""
valid_tcu.py
Simulates a legitimate, active TCU (TCU001) interacting with the cloud server.

Demonstrates:
- Successful authentication and JWT token issuance
- Authorised telemetry upload (telemetry:write scope)
- Authorised diagnostics access (diagnostics:read scope)
- Denied remote command (TCU001 lacks command:unlock scope — insufficient privilege)

This script reflects the least-privilege principle:
TCU001 is authenticated but cannot access endpoints outside its granted scopes.
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


# Step 1: Authenticate TCU001
print("\n=== VALID TCU (TCU001) SIMULATION ===")

login_resp = requests.post(f"{BASE_URL}/auth/tcu-login", json={
    "tcu_id": "TCU001",
    "secret": "secret123"
})
print_response("Login", login_resp)

if login_resp.status_code != 200:
    print("\nLogin failed. Is the Flask server running?")
    exit(1)

token = login_resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}


# Step 2: Upload telemetry — should be ALLOWED (telemetry:write in scope)
telemetry_resp = requests.post(f"{BASE_URL}/api/telemetry", headers=headers, json={
    "speed": 85,
    "battery": 72,
    "temperature": 36
})
print_response("Telemetry Upload (expect 200 ALLOW)", telemetry_resp)


# Step 3: Access diagnostics — should be ALLOWED (diagnostics:read in scope)
diag_resp = requests.get(f"{BASE_URL}/api/diagnostics", headers=headers)
print_response("Diagnostics Access (expect 200 ALLOW)", diag_resp)


# Step 4: Attempt remote command — should be DENIED (no command:unlock scope)
cmd_resp = requests.post(f"{BASE_URL}/api/remote-command", headers=headers, json={
    "command": "unlock_doors"
})
print_response("Remote Command (expect 403 DENY — insufficient scope)", cmd_resp)
