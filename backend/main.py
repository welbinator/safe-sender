"""
Sender Safety API — Sprint 3.

Adds customer-facing endpoints on top of Sprint 2's internal SMTP endpoints:

  Auth:
    POST /auth/google          — exchange Google ID token for session JWT

  Customers:
    GET  /customers/me         — current customer profile
    PATCH /customers/me        — update name

  Rules:
    GET    /rules              — list rules
    POST   /rules              — create rule
    PUT    /rules/{id}         — update rule
    DELETE /rules/{id}         — delete rule

  Logs:
    GET  /logs                 — paginated scan logs

Internal (SMTP service only, not exposed via nginx):
  GET  /internal/rules/{domain}
  POST /internal/scan-log
"""
import asyncio
import hashlib
import logging
import os
from typing import Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Sprint C1: Fail-fast on missing/weak DATABASE_URL (audit H-3).
# Runs BEFORE other imports so the guard fires even if internal_auth or
# downstream modules have their own (less specific) startup checks.
# ---------------------------------------------------------------------------
_WEAK_DB_PASSWORDS = {"changeme", "secret", "password", "default", "test", ""}

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required. Refusing to start with an insecure default. "
        "Set DATABASE_URL in the environment (see .env.example)."
    )
_db_password = (urlparse(DATABASE_URL).password or "").lower()
if _db_password in _WEAK_DB_PASSWORDS:
    raise RuntimeError(
        "DATABASE_URL contains a weak/default password "
        f"({_db_password!r}). Set a strong password before starting."
    )
logger = logging.getLogger("sender_safety.backend")

logger.info("DATABASE_URL host portion: ...@%s", DATABASE_URL.split("@")[-1])

# ---------------------------------------------------------------------------
# Sprint C1 HOTFIX (audit C-1): Refuse to start if test-token bypass is
# enabled in production. ALLOW_TEST_TOKENS=1 lets `auth/google` accept
# `test:<json>` strings as a valid Google ID token — fine for CI, catastrophic
# in prod (anyone can mint a session for any email).
# ---------------------------------------------------------------------------
_ENV = os.environ.get("ENV", "").lower()
_ALLOW_TEST_TOKENS = os.environ.get("ALLOW_TEST_TOKENS") == "1"
if _ENV in ("production", "prod") and _ALLOW_TEST_TOKENS:
    raise RuntimeError(
        "FATAL: ALLOW_TEST_TOKENS=1 is set while ENV=production. "
        "This would let anyone forge a session JWT by POSTing a fake "
        "Google ID token. Unset ALLOW_TEST_TOKENS (or set it to 0) "
        "before starting. Refusing to start."
    )

import asyncpg
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from internal_auth import require_internal_secret
from db import close_pool, get_pool, set_pool

app = FastAPI(title="Sender Safety API", version="0.3.0")
# ---------------------------------------------------------------------------
# Database connection pool (created on startup; lives in db.py — F-13)
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup():
    import asyncio
    import socket as _socket

    loop = asyncio.get_running_loop()

    # WSL2 Docker bug: thread-pool executor threads cannot call getaddrinfo.
    # Patch loop.getaddrinfo to run synchronously in the event loop thread.
    async def _sync_getaddrinfo(host, port, *args, **kwargs):
        return _socket.getaddrinfo(host, port, *args, **kwargs)

    loop.getaddrinfo = _sync_getaddrinfo

    last_err = None
    for attempt in range(10):
        try:
            # Parse the URL into explicit kwargs to avoid asyncpg calling
            # loop.getaddrinfo() — which hangs in executor threads on this
            # Docker/WSL2 kernel combo even for raw IPs.
            from urllib.parse import urlparse
            _u = urlparse(DATABASE_URL)
            pool = await asyncio.wait_for(
                asyncpg.create_pool(
                    host=_u.hostname,
                    port=_u.port or 5432,
                    user=_u.username,
                    password=_u.password,
                    database=_u.path.lstrip("/"),
                    min_size=2,
                    max_size=10,
                    ssl=False,
                    timeout=10,
                ),
                timeout=15,
            )
            set_pool(pool)
            return
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            logger.warning("DB connect attempt %d failed: %s. Retrying in %ds...", attempt + 1, e, wait)
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect to database after 10 attempts: {last_err}")


@app.on_event("shutdown")
async def shutdown():
    await close_pool()


# ---------------------------------------------------------------------------
# Register Sprint 3 routers
# ---------------------------------------------------------------------------
from routers import admin, auth, customers, logs, rules, webhooks  # noqa: E402

app.include_router(auth.router)
app.include_router(customers.router)
app.include_router(rules.router)
app.include_router(logs.router)
app.include_router(webhooks.router)
app.include_router(admin.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /internal/rules/{domain}
# ---------------------------------------------------------------------------

@app.get("/internal/rules/{domain}", dependencies=[Depends(require_internal_secret)])
async def get_rules(domain: str):
    """
    Return customer_id and active rules for a given sender domain.
    Returns 404 if domain is not registered.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        customer = await conn.fetchrow(
            "SELECT id, domain_verified, subject_hash_salt FROM customers WHERE domain = $1",
            domain.lower(),
        )
        if not customer:
            raise HTTPException(status_code=404, detail="Domain not registered")
        if not customer["domain_verified"]:
            raise HTTPException(status_code=403, detail="Domain not verified")

        customer_id = customer["id"]
        rows = await conn.fetch(
            """
            SELECT id, pattern, match_type, scope, is_exception, applies_to_email
            FROM rules
            WHERE customer_id = $1 AND active = true
            """,
            customer_id,
        )

    rules_list = [
        {
            "id": str(r["id"]),
            "pattern": r["pattern"],
            "match_type": r["match_type"],
            "scope": r["scope"] or "both",
            "is_exception": r["is_exception"],
            "applies_to_user": r["applies_to_email"],
        }
        for r in rows
    ]

    # C12: hand the SMTP service this customer's HMAC key for subject hashing.
    # Hex-encoded for clean JSON transport; SMTP decodes back to bytes.
    salt_hex = bytes(customer["subject_hash_salt"]).hex()

    return {
        "customer_id": str(customer_id),
        "rules": rules_list,
        "subject_hash_salt": salt_hex,
    }


# ---------------------------------------------------------------------------
# POST /internal/scan-log
# ---------------------------------------------------------------------------

class ScanLogRequest(BaseModel):
    customer_id: str = Field(..., max_length=64)
    sender: str = Field(..., max_length=320)        # RFC 5321
    recipient: str = Field(..., max_length=320)
    subject_hash: str = Field(..., max_length=128)  # hex SHA-256
    matched_rule_id: Optional[str] = Field(default=None, max_length=64)
    outcome: str = Field(..., max_length=16)
    # F-08: plaintext `subject` removed — only the HMAC `subject_hash` is stored.
    # Accept-and-discard remains for one rollout window so an older SMTP worker
    # POSTing the field doesn't 422; safe to delete after all SMTP workers ship.
    subject: Optional[str] = Field(default=None, max_length=998, deprecated=True)

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, v: str) -> str:
        if v not in ("allowed", "blocked"):
            raise ValueError("outcome must be 'allowed' or 'blocked'")
        return v


@app.post("/internal/scan-log", status_code=201, dependencies=[Depends(require_internal_secret)])
async def create_scan_log(body: ScanLogRequest):
    """Insert a scan log row. Email content is never stored."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scan_logs
                (customer_id, sender, recipient, subject_hash, matched_rule_id, outcome)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            body.customer_id,
            body.sender,
            body.recipient,
            body.subject_hash,
            body.matched_rule_id,
            body.outcome,
        )
    return {"status": "logged"}

# ---------------------------------------------------------------------------
# GET /internal/suppressed/{customer_id}/{email}
# ---------------------------------------------------------------------------
#
# Sprint B C16: per-customer suppression isolation. A hard bounce on
# alice@example.com for customer A must not block customer B from sending to
# the same address. We treat legacy rows (customer_id IS NULL) as still global
# until backfill completes, so existing suppressions don't quietly stop
# working during rollout.


@app.get(
    "/internal/suppressed/{customer_id}/{email}",
    dependencies=[Depends(require_internal_secret)],
)
async def check_suppressed(customer_id: str, email: str):
    """Returns 200 if address is suppressed for this customer, 404 if not."""
    pool = get_pool()
    addr = email.lower().strip()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT email FROM suppressed_addresses
            WHERE email = $1
              AND (customer_id = $2::uuid OR customer_id IS NULL)
            LIMIT 1
            """,
            addr,
            customer_id,
        )
    if row:
        return {"suppressed": True}
    raise HTTPException(status_code=404, detail="Not suppressed")


# ---------------------------------------------------------------------------
# POST /internal/smtp-auth  — called by SMTP server to verify credentials
# ---------------------------------------------------------------------------

class SmtpAuthRequest(BaseModel):
    username: str
    password: str


@app.post("/internal/smtp-auth", dependencies=[Depends(require_internal_secret)])
async def smtp_auth(body: SmtpAuthRequest):
    """
    Verify SMTP credentials. Returns customer info on success, 401 on failure.
    Also accepts global AUTH_USERNAME/AUTH_PASSWORD env vars as admin fallback.

    Body is POSTed (not query params) so credentials never appear in access logs.
    """
    username = body.username
    password = body.password

    # Admin/test fallback
    admin_user = os.environ.get("AUTH_USERNAME", "")
    admin_pass = os.environ.get("AUTH_PASSWORD", "")
    if admin_user and username == admin_user and password == admin_pass:
        return {"customer_id": None, "domain": None, "admin": True}

    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, domain, smtp_password_hash FROM customers WHERE smtp_username = $1",
            username,
        )
    if not row or not row["smtp_password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    import bcrypt as _bcrypt
    # Sprint C2 (audit F-02): bcrypt.checkpw is CPU-bound (~250-500ms).
    # This endpoint sits on the SMTP auth hot path — every inbound message
    # hits it. Offload to a worker thread so we don't stall the FastAPI
    # event loop under concurrent SMTP authentication.
    valid = await asyncio.to_thread(
        _bcrypt.checkpw, password.encode(), row["smtp_password_hash"].encode()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"customer_id": str(row["id"]), "domain": row["domain"], "admin": False}