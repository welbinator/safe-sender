"""
Authentication for /internal/* routes.

The SMTP service authenticates to the backend with a shared secret in the
``X-Internal-Secret`` header. Every internal route MUST depend on
``require_internal_secret`` — without it any /internal/* endpoint would be a
public oracle for password spraying, suppression-list poisoning, etc.

Fails fast at import time if INTERNAL_SHARED_SECRET is missing or weak.

Rotation (F-26)
---------------
Restarting both services with a brand-new secret used to be a synchronous
cutover: between the moment the backend reloaded and the moment the SMTP
service caught up, every internal request 401'd and inbound mail bounced.

To make rotation a zero-downtime, non-coordinated operation we accept up
to *two* secrets on the backend side:

    INTERNAL_SHARED_SECRET            current (always required)
    INTERNAL_SHARED_SECRET_PREVIOUS   optional second value still accepted

Rotation procedure:

    1. Generate a new secret S2.
    2. Backend: deploy with INTERNAL_SHARED_SECRET=S2,
       INTERNAL_SHARED_SECRET_PREVIOUS=S1. Backend now accepts both.
    3. SMTP: deploy with INTERNAL_SHARED_SECRET=S2. SMTP starts sending S2.
    4. Backend: drop INTERNAL_SHARED_SECRET_PREVIOUS. S1 is now dead.

Every step is independently deployable, no traffic is dropped, and a
botched step 3 can be rolled back simply by re-deploying SMTP with S1.
"""
import hmac
import os

from fastapi import Header, HTTPException, status

_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}


def _validate(name: str, value: str, *, required: bool) -> str:
    if not value:
        if required:
            raise RuntimeError(
                f"{name} is missing. "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        return ""
    if value.lower() in _WEAK_SECRETS or len(value) < 32:
        raise RuntimeError(
            f"{name} is default or shorter than 32 chars. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
        )
    return value


INTERNAL_SHARED_SECRET = _validate(
    "INTERNAL_SHARED_SECRET",
    os.environ.get("INTERNAL_SHARED_SECRET", ""),
    required=True,
)
INTERNAL_SHARED_SECRET_PREVIOUS = _validate(
    "INTERNAL_SHARED_SECRET_PREVIOUS",
    os.environ.get("INTERNAL_SHARED_SECRET_PREVIOUS", ""),
    required=False,
)

# Sanity check — pointless (and dangerous) to keep both slots at the same
# value, that defeats the whole reason previous exists.
if (
    INTERNAL_SHARED_SECRET_PREVIOUS
    and hmac.compare_digest(INTERNAL_SHARED_SECRET, INTERNAL_SHARED_SECRET_PREVIOUS)
):
    raise RuntimeError(
        "INTERNAL_SHARED_SECRET_PREVIOUS equals INTERNAL_SHARED_SECRET. "
        "Either unset PREVIOUS or rotate the current secret first."
    )

# Pre-built tuple so the hot path is just two constant-time compares.
_ACCEPTED_SECRETS: tuple[str, ...] = tuple(
    s for s in (INTERNAL_SHARED_SECRET, INTERNAL_SHARED_SECRET_PREVIOUS) if s
)


async def require_internal_secret(
    x_internal_secret: str = Header(default="", alias="X-Internal-Secret"),
) -> None:
    """
    FastAPI dependency that enforces shared-secret auth on internal endpoints.
    Uses constant-time comparison to avoid timing attacks.

    Accepts the current secret OR the (optional) previous secret so that
    secrets can be rotated without coordinated restarts. See module docstring.
    """
    # Always run both compares to keep timing flat regardless of which (if
    # any) secret matches. `any()` short-circuits, which would leak which
    # slot matched via response timing on attacker-controlled inputs.
    matched = False
    for accepted in _ACCEPTED_SECRETS:
        if hmac.compare_digest(x_internal_secret, accepted):
            matched = True
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal secret",
        )
