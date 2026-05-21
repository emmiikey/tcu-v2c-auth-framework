
REQUIRED_SCOPES = {
    "/api/telemetry": "telemetry:write",
    "/api/diagnostics": "diagnostics:read",
    "/api/remote-command": "command:unlock",
}


ENDPOINT_RISK = {
    "/api/telemetry": "low",
    "/api/diagnostics": "low",
    "/api/remote-command": "high",
}


def get_required_scope(endpoint):
    """Return the required scope string for a given endpoint, or None if not defined."""
    return REQUIRED_SCOPES.get(endpoint)


def get_risk_level(endpoint):
    """Return the risk level for a given endpoint."""
    return ENDPOINT_RISK.get(endpoint, "unknown")
