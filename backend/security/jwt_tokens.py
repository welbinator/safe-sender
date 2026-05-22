"""HS256 JWT creation + strict verification.

Sprint B H10/H11/H12 hardening:
  - 7-day expiry, explicit iss/aud/jti, iat/nbf set at mint
  - decode requires sub/exp/iat/jti/iss/aud (no lenient fallback)

Sprint C1 C-2 hotfix: STRICT_JWT_CLAIMS toggle removed — strict is the only
mode. Any pre-Sprint-C1 tokens without iss/aud/jti will fail and force a
re-login (worst case ~JWT_EXPIRE_DAYS of session churn).
"""
import os
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "sendersafety")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "sendersafety-app")
JWT_EXPIRE_DAYS = int(os.environ.get("JWT_EXPIRE_DAYS", "7"))

_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}
if JWT_SECRET.lower() in _WEAK_SECRETS or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET is missing, default, or shorter than 32 chars. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )


def create_jwt(customer_id: str, email: str) -> str:
    """Return a signed JWT with iss/aud/sub/jti/iat/nbf/exp."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": customer_id,
        "email": email,
        "jti": _secrets.token_urlsafe(16),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode + verify a JWT. Raises HTTPException 401 on any failure."""
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["sub", "exp", "iat", "jti", "iss", "aud"],
                "verify_iat": True,
                "verify_nbf": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
