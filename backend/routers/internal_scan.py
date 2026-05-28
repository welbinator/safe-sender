"""
POST /internal/scan-log — called by SMTP server to record a scan result.

Extracted from main.py (#22 audit refactor).
"""
from __future__ import annotations

import logging
import os
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from db import get_pool
from internal_auth import require_internal_secret

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanLogRequest(BaseModel):
    # M-5: parse as UUID so a malformed/oversized string fails at the edge
    # rather than blowing up the asyncpg cast deep in the handler. Pydantic
    # coerces strings; max_length stays as a defense-in-depth byte cap.
    customer_id: UUID
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


@router.post("/internal/scan-log", status_code=201, dependencies=[Depends(require_internal_secret)])
async def create_scan_log(body: ScanLogRequest):
    """Insert a scan log row. Email content is never stored.

    M-5: enforce sender↔customer binding. The internal-auth shared secret
    proves the caller is an SMTP worker, NOT that the worker is allowed to
    log activity for an arbitrary customer. A bug or compromise on one
    worker shouldn't let it forge logs against every customer's domain.
    We require the sender's domain to match the customer's registered
    domain. Default ON (SCAN_LOG_BIND_SENDER=1); set =0 only during
    rollout windows when older SMTP workers may not yet send the full payload.
    """
    pool = get_pool()
    bind_sender = os.environ.get("SCAN_LOG_BIND_SENDER", "1") == "1"
    if bind_sender:
        sender_domain = body.sender.rsplit("@", 1)[-1].lower().strip()
        async with pool.acquire() as conn:
            customer_row = await conn.fetchrow(
                "SELECT 1 FROM customers WHERE id = $1",
                body.customer_id,
            )
            if customer_row is None:
                logger.warning(
                    "scan_log_unknown_customer",
                    extra={"customer_id": str(body.customer_id)},
                )
                raise HTTPException(status_code=404, detail="Unknown customer")
            domain_row = await conn.fetchrow(
                "SELECT 1 FROM customer_domains WHERE customer_id = $1 AND domain = $2 AND verified = TRUE",
                body.customer_id,
                sender_domain,
            )
        if domain_row is None:
            logger.warning(
                "scan_log_sender_domain_not_verified",
                extra={
                    "customer_id": str(body.customer_id),
                    "sender_domain": sender_domain,
                },
            )
            raise HTTPException(
                status_code=403,
                detail="Sender domain does not belong to customer",
            )
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
