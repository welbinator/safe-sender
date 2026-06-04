"""Microsoft Entra ID (Azure AD) OIDC token validation."""
from __future__ import annotations

import os
import time
from typing import Any

import httpx
from fastapi import HTTPException

MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")

MICROSOFT_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MICROSOFT_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"


async def verify_microsoft_id_token(id_token: str) -> dict[str, Any]:
    """Validate a Microsoft id_token and return the claims dict."""
    if not id_token:
        raise HTTPException(status_code=401, detail="No Microsoft token provided.")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://graph.microsoft.com/oidc/userinfo",
                headers={"Authorization": f"Bearer {id_token}"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=401, detail=f"Microsoft userinfo request failed: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Microsoft token validation failed.")

    claims = resp.json()
    email = claims.get("email") or claims.get("preferred_username", "")
    if not email or "@" not in email:
        raise HTTPException(status_code=401, detail="Microsoft token missing email claim.")

    return {
        "sub": claims.get("sub", ""),
        "email": email,
        "name": claims.get("name", ""),
    }
