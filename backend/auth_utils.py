"""
JWT creation/verification and Google ID token verification.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"

# Fail fast on weak or default secrets. Anything < 32 chars or matching a
# well-known default is rejected at import time. This prevents accidentally
# running with the literal "changeme" placeholder in production.
_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}
if JWT_SECRET.lower() in _WEAK_SECRETS or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET is missing, default, or shorter than 32 chars. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )
JWT_EXPIRE_DAYS = 30

GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")


def create_jwt(customer_id: str, email: str) -> str:
    """Return a signed JWT for the given customer."""
    payload = {
        "sub": customer_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT.  Raises HTTPException 401 on any failure.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def verify_google_id_token(id_token: str) -> dict[str, Any]:
    """
    Call Google's tokeninfo endpoint to validate an ID token.
    Returns the token claims dict on success.
    Raises HTTPException 401 on failure.
    """
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

    # Validate audience — must match our Google Client ID
    if GOOGLE_CLIENT_ID and claims.get("aud") != GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token audience mismatch",
        )

    required = {"sub", "email"}
    if not required.issubset(claims.keys()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incomplete token claims",
        )

    return claims
