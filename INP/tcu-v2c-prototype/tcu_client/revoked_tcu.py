"""
revoked_tcu.py
Simulates a revoked TCU (TCU002) attempting to authenticate with the cloud server.

Demonstrates:
- Authentication denial for a revoked identity
- No token is issued — the TCU cannot proceed to any API endpoint

This script reflects the lifecycle-aware trust design principle:
once a TCU is revoked, its identity is permanently rejected at the login stage.
This directly addresses Threat 4: Access by a revoked identity.
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


print("\n=== REVOKED TCU (TCU002) SIMULATION ===")

# Attempt to authenticate with a revoked TCU — should be DENIED
login_resp = requests.post(f"http://127.0.0.1:5000/auth/tcu-login", json={
    "tcu_id": "TCU002",
    "secret": "secret456"
})
print_response("Login (expect 401 DENY — revoked identity)", login_resp)

if login_resp.status_code == 200:
    print("\n[FAIL] Revoked TCU was incorrectly authenticated.")
else:
    print("\n[PASS] Revoked TCU correctly rejected. No token issued.")
