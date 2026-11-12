from __future__ import annotations

import requests


def fetch_snapshot(base_url: str, api_key: str, device_id: str, timeout_seconds: int) -> dict:
    url = f"{base_url.rstrip('/')}/device-access/{device_id}"
    response = requests.get(
        url,
        headers={"x-functions-key": api_key, "Accept": "application/json"},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()
    for field in ("version", "generatedUtc", "validUntilUtc", "users"):
        if field not in payload:
            raise ValueError(f"RBAC API response is missing required field: {field}")
    return payload
