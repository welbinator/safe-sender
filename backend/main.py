"""
Sender Safety API — Sprint 2.

Adds internal endpoints for the SMTP service:
  GET  /internal/rules/{domain}  — fetch customer + active rules
  POST /internal/scan-log        — record scan outcome

These endpoints are NOT exposed via nginx (internal Docker network only).
"""
import hashlib
import os
from typing import Optional

import asyncpg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sendersafety:changeme@postgres:5432/sendersafety"
)

app = FastAPI(title="Sender Safety API", version="0.2.0")

# ---------------------------------------------------------------------------
# Database connection pool (created on startup)
# ---------------------------------------------------------------------------
_pool: asyncpg.Pool | None = None


@app.on_event("startup")
async def startup():
    global _pool
    _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)


@app.on_event("shutdown")
async def shutdown():
    if _pool:
        await _pool.close()


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


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
            SELECT id, pattern, match_type, scope, is_exception, applies_to_user
            FROM rules
            WHERE customer_id = $1 AND active = true
            """,
            customer_id,
        )

    rules = [
        {
            "id": r["id"],
            "pattern": r["pattern"],
            "match_type": r["match_type"],
            "scope": r["scope"] or "both",
            "is_exception": r["is_exception"],
            "applies_to_user": r["applies_to_user"],
        }
        for r in rows
    ]

    return {"customer_id": customer_id, "rules": rules}


# ---------------------------------------------------------------------------
# POST /internal/scan-log
# ---------------------------------------------------------------------------

class ScanLogRequest(BaseModel):
    customer_id: int
    sender: str
    recipient: str
    subject_hash: str          # SHA-256 hex digest — never plaintext
    matched_rule_id: Optional[int] = None
    outcome: str               # "passed" or "blocked"

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, v: str) -> str:
        if v not in ("passed", "blocked"):
            raise ValueError("outcome must be 'passed' or 'blocked'")
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
