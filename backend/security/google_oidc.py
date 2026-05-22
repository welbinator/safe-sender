"""Google ID token verification via the tokeninfo endpoint.

Enforces aud, iss, email_verified, and (when WORKSPACE_ONLY=1) the `hd` claim
matching the email domain — rejecting personal @gmail.com accounts.
"""
import os
from typing import Any

import httpx
from fastapi import HTTPException, status

GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_VALID_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
WORKSPACE_ONLY = os.environ.get("WORKSPACE_ONLY", "1") == "1"


async def verify_google_id_token(id_token: str) -> dict[str, Any]:
    """Verify a Google ID token. Returns the claims dict on success."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            GOOGLE_TOKEN_INFO_URL, params={"id_token": id_token}
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google ID token",
        )

    claims = resp.json()

    if GOOGLE_CLIENT_ID and claims.get("aud") != GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token audience mismatch",
        )

    if claims.get("iss", "") not in GOOGLE_VALID_ISSUERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token issuer not trusted",
        )

    ev = claims.get("email_verified", False)
    if not (ev is True or (isinstance(ev, str) and ev.lower() == "true")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified by Google",
        )

    if not {"sub", "email"}.issubset(claims.keys()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incomplete token claims",
        )

    if WORKSPACE_ONLY:
        hd = claims.get("hd", "").strip().lower()
        if not hd:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Sender Safety requires a Google Workspace account "
                    "(personal @gmail.com accounts are not supported)."
                ),
            )
        email_domain = claims["email"].split("@", 1)[-1].lower()
        if hd != email_domain:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Workspace domain mismatch",
            )

    return claims
