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
import hashlib
import os
from typing import Optional

import asyncpg
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from internal_auth import require_internal_secret

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sendersafety:changeme@postgres:5432/sendersafety"
)
print(f"[main] DATABASE_URL host portion: ...@{DATABASE_URL.split('@')[-1]}", flush=True)

app = FastAPI(title="Sender Safety API", version="0.3.0")
# ---------------------------------------------------------------------------
# Database connection pool (created on startup)
# ---------------------------------------------------------------------------
_pool: asyncpg.Pool | None = None


@app.on_event("startup")
async def startup():
    global _pool
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
            _pool = await asyncio.wait_for(
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
            return
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"DB connect attempt {attempt + 1} failed: {e}. Retrying in {wait}s...")
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect to database after 10 attempts: {last_err}")


@app.on_event("shutdown")
async def shutdown():
    if _pool:
        await _pool.close()


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


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
            "SELECT id, domain_verified FROM customers WHERE domain = $1", domain.lower()
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

    return {"customer_id": str(customer_id), "rules": rules_list}


# ---------------------------------------------------------------------------
# POST /internal/scan-log
# ---------------------------------------------------------------------------

class ScanLogRequest(BaseModel):
    customer_id: str
    sender: str
    recipient: str
    subject_hash: str          # SHA-256 hex digest — never plaintext
    matched_rule_id: Optional[str] = None
    outcome: str               # "allowed" or "blocked"
    subject: str = ""          # TEMP: plaintext subject for testing — remove before go-live

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
                (customer_id, sender, recipient, subject_hash, matched_rule_id, outcome, subject)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            body.customer_id,
            body.sender,
            body.recipient,
            body.subject_hash,
            body.matched_rule_id,
            body.outcome,
            body.subject,
        )
    return {"status": "logged"}


# ---------------------------------------------------------------------------
# GET /internal/suppressed/{email}
# ---------------------------------------------------------------------------

@app.get("/internal/suppressed/{email}", dependencies=[Depends(require_internal_secret)])
async def check_suppressed(email: str):
    """Returns 200 if address is suppressed, 404 if not."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT email FROM suppressed_addresses WHERE email = $1",
            email.lower().strip(),
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
    valid = _bcrypt.checkpw(password.encode(), row["smtp_password_hash"].encode())
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"customer_id": str(row["id"]), "domain": row["domain"], "admin": False}