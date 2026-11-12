from __future__ import annotations

import msal
import requests


def interactive_device_login(tenant_id: str, client_id: str) -> dict:
    if not tenant_id or not client_id:
        raise RuntimeError("ENTRA_TENANT_ID and EDGE_PUBLIC_CLIENT_ID must be configured")

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.PublicClientApplication(client_id=client_id, authority=authority)
    flow = app.initiate_device_flow(scopes=["User.Read"])
    if "user_code" not in flow:
        raise RuntimeError(f"Unable to start device-code flow: {flow}")

    print("\nMicrosoft Entra sign-in")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(result.get("error_description") or str(result))

    # Query /me so the edge app receives canonical object ID and UPN.
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName,accountEnabled",
        headers={"Authorization": f"Bearer {result['access_token']}"},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()
