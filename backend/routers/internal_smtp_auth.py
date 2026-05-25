"""
POST /internal/smtp-auth — verify SMTP credentials.

Extracted from main.py (#22 audit refactor).
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import get_pool
from internal_auth import require_internal_secret

logger = logging.getLogger(__name__)

router = APIRouter()


class SmtpAuthRequest(BaseModel):
    """
    S-H4: wire format for /internal/smtp-auth.

    The password is delivered as an AES-256-GCM blob (`auth_blob`) keyed off
    `INTERNAL_SHARED_SECRET` via HKDF. The blob carries a unix timestamp so
    the backend can reject replays older than `MAX_AGE_SECONDS`.
    """
    v: int = 1
    username: str
    auth_blob: str


# H-3: precomputed bcrypt hash of a random secret, used as a "dummy verify"
# target to equalize timing on the admin and unknown-user code paths in
# /internal/smtp-auth. Generated once at module import.
def _make_dummy_bcrypt_hash() -> bytes:
    import bcrypt as _b
    import secrets as _s
    return _b.hashpw(_s.token_bytes(16), _b.gensalt(12))


_DUMMY_BCRYPT_HASH = _make_dummy_bcrypt_hash()


@router.post("/internal/smtp-auth", dependencies=[Depends(require_internal_secret)])
async def smtp_auth(body: SmtpAuthRequest):
    """
    Verify SMTP credentials. Returns customer info on success, 401 on failure.
    Also accepts global AUTH_USERNAME/AUTH_PASSWORD env vars as admin fallback.

    Body is POSTed (not query params) so credentials never appear in access logs.
    """
    username = body.username
    # S-H4: decrypt the AES-GCM-sealed password blob. open_password() enforces
    # AAD (binds username + version), MAC, and a 60s freshness window. Any
    # failure is treated as an auth failure (no user-visible distinction).
    from security.internal_auth_crypto import open_password as _open_password
    try:
        password = _open_password(username, body.auth_blob)
    except ValueError as exc:
        logger.warning("smtp-auth: rejected sealed payload", extra={"reason": str(exc)})
        # Still pay the bcrypt cost to keep timing flat with the success path.
        import bcrypt as _bcrypt
        await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # H-3: Admin/test fallback — constant-time + bcrypt-equivalent timing.
    # ------------------------------------------------------------------
    import bcrypt as _bcrypt

    admin_user = os.environ.get("AUTH_USERNAME", "")
    admin_pass = os.environ.get("AUTH_PASSWORD", "")

    cmp_user_a = admin_user.encode("utf-8") if admin_user else b"\x00" * 32
    cmp_user_b = username.encode("utf-8").ljust(len(cmp_user_a), b"\x00")[: len(cmp_user_a)]
    cmp_pass_a = admin_pass.encode("utf-8") if admin_pass else b"\x00" * 32
    cmp_pass_b = password.encode("utf-8").ljust(len(cmp_pass_a), b"\x00")[: len(cmp_pass_a)]

    user_match = hmac.compare_digest(cmp_user_a, cmp_user_b) and bool(admin_user)
    pass_match = hmac.compare_digest(cmp_pass_a, cmp_pass_b) and bool(admin_pass)

    # Always burn a bcrypt cycle so admin-path timing ≈ DB-path timing.
    await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)

    if user_match and pass_match:
        return {"customer_id": None, "domain": None, "admin": True}

    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, domain, smtp_password_hash FROM customers WHERE smtp_username = $1",
            username,
        )
    if not row or not row["smtp_password_hash"]:
        # Still burn a bcrypt cycle so unknown-user vs wrong-password
        # have indistinguishable timing.
        await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Sprint C2 (audit F-02): bcrypt.checkpw is CPU-bound (~250-500ms).
    valid = await asyncio.to_thread(
        _bcrypt.checkpw, password.encode(), row["smtp_password_hash"].encode()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"customer_id": str(row["id"]), "domain": row["domain"], "admin": False}
