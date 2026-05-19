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
import re
import socket
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sendersafety:changeme@postgres:5432/sendersafety"
)

# ---------------------------------------------------------------------------
# Pre-resolve the DB hostname at module load time (before asyncio starts).
# On WSL2, Docker's embedded DNS (127.0.0.11) is unreachable from within an
# asyncio event loop's thread-pool executor. Resolving synchronously here,
# before the event loop is created, works around this kernel bug.
# ---------------------------------------------------------------------------
def _resolve_db_url(url: str) -> str:
    match = re.search(r"@([^:/]+)(:\d+)?/", url)
    if match:
        hostname = match.group(1)
        try:
            ip = socket.gethostbyname(hostname)
            url = url.replace(f"@{hostname}", f"@{ip}", 1)
            print(f"[startup] Resolved DB host {hostname!r} -> {ip}")
        except Exception as e:
            print(f"[startup] Could not resolve DB host {hostname!r}: {e}")
    return url

_RESOLVED_DB_URL = _resolve_db_url(DATABASE_URL)

app = FastAPI(title="Sender Safety API", version="0.3.0")
# ---------------------------------------------------------------------------
# Database connection pool (created on startup)
# ---------------------------------------------------------------------------
_pool: asyncpg.Pool | None = None


@app.on_event("startup")
async def startup():
    global _pool
    import asyncio

    last_err = None
    for attempt in range(10):
        try:
            _pool = await asyncpg.create_pool(
                _RESOLVED_DB_URL,
                min_size=2,
                max_size=10,
                ssl=False,
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
from routers import auth, customers, logs, rules  # noqa: E402

app.include_router(auth.router)
app.include_router(customers.router)
app.include_router(rules.router)
app.include_router(logs.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /internal/rules/{domain}
# ---------------------------------------------------------------------------

@app.get("/internal/rules/{domain}")
async def get_rules(domain: str):
    """
    Return customer_id and active rules for a given sender domain.
    Returns 404 if domain is not registered.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        customer = await conn.fetchrow(
            "SELECT id FROM customers WHERE domain = $1", domain.lower()
        )
        if not customer:
            raise HTTPException(status_code=404, detail="Domain not registered")

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

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, v: str) -> str:
        if v not in ("allowed", "blocked"):
            raise ValueError("outcome must be 'allowed' or 'blocked'")
        return v


@app.post("/internal/scan-log", status_code=201)
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
