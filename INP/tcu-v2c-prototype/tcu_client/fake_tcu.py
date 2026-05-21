"""
fake_tcu.py
Simulates Threat 1: TCU Impersonation.

An attacker attempts to authenticate as TCU999, which is not registered in the
TCU identity registry. The system must reject this at the authentication stage
before any token is issued or any API endpoint is reachable.

Expected outcome: 401 Unauthorized — unknown TCU identity.
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


print("\n=== THREAT 1: TCU IMPERSONATION (TCU999 — not registered) ===")
print("An attacker is attempting to authenticate as an unregistered TCU identity.")
print("The system must reject this before issuing any token.")

# Attempt 1: completely made-up tcu_id and secret
login_resp = requests.post(f"{BASE_URL}/auth/tcu-login", json={
    "tcu_id": "TCU999",
    "secret": "hacked123"
})
print_response("Login with unknown TCU999 (expect 401 DENY)", login_resp)

if login_resp.status_code == 401:
    print("\n[PASS] Unknown TCU identity correctly rejected. No token issued.")
    print(f"       Reason: {login_resp.json().get('error', 'n/a')}")
else:
    print("\n[FAIL] Unknown TCU was incorrectly authenticated — impersonation succeeded!")

# Attempt 2: valid tcu_id but wrong secret, to confirm credential checking
print("\n--- Bonus: registered TCU with wrong credentials ---")
login_resp2 = requests.post(f"{BASE_URL}/auth/tcu-login", json={
    "tcu_id": "TCU001",
    "secret": "wrongpassword"
})
print_response("Login with TCU001 + wrong secret (expect 401 DENY)", login_resp2)

if login_resp2.status_code == 401:
    print("\n[PASS] Invalid credentials correctly rejected.")
    print(f"       Reason: {login_resp2.json().get('error', 'n/a')}")
else:
    print("\n[FAIL] Invalid credentials were incorrectly accepted!")
