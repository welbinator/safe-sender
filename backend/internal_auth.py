"""
Authentication for /internal/* routes.

The SMTP service authenticates to the backend with a shared secret in the
`X-Internal-Secret` header. Every internal route MUST depend on
`require_internal_secret` — without it any /internal/* endpoint would be a
public oracle for password spraying, suppression-list poisoning, etc.

Fails fast at import time if INTERNAL_SHARED_SECRET is missing or weak.
"""
import hmac
import os

from fastapi import Header, HTTPException, status

INTERNAL_SHARED_SECRET = os.environ.get("INTERNAL_SHARED_SECRET", "")

_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}
if INTERNAL_SHARED_SECRET.lower() in _WEAK_SECRETS or len(INTERNAL_SHARED_SECRET) < 32:
    raise RuntimeError(
        "INTERNAL_SHARED_SECRET is missing, default, or shorter than 32 chars. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )


async def require_internal_secret(
    x_internal_secret: str = Header(default="", alias="X-Internal-Secret"),
) -> None:
    """
    FastAPI dependency that enforces shared-secret auth on internal endpoints.
    Uses constant-time comparison to avoid timing attacks.
    """
    if not hmac.compare_digest(x_internal_secret, INTERNAL_SHARED_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal secret",
        )
