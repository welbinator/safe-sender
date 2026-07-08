"""
AI policy endpoints (AI Add-On — Sprint 2).

  GET    /ai/status            — whether AI scan is enabled + policy count
  GET    /ai/policies          — list policies for authenticated customer
  POST   /ai/policies          — create a policy (max 10)
  DELETE /ai/policies/{id}     — delete a policy
  POST   /ai/enable            — enable AI scan
  POST   /ai/disable           — disable AI scan
"""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from db import get_pool
from deps import get_current_customer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ai", tags=["ai"])

MAX_POLICIES = 10


class PolicyCreate(BaseModel):
    policy_text: str = Field(..., min_length=10, max_length=500)


class PolicyResponse(BaseModel):
    id: str
    policy_text: str
    created_at: str


class AIStatusResponse(BaseModel):
    ai_scan_enabled: bool
    policy_count: int


@router.get("/status", response_model=AIStatusResponse)
async def ai_status(customer=Depends(get_current_customer)):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT ai_scan_enabled FROM customers WHERE id = $1",
            customer["id"],
        )
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM ai_policies WHERE customer_id = $1",
            customer["id"],
        )
    return {"ai_scan_enabled": bool(row["ai_scan_enabled"]), "policy_count": int(count)}


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(customer=Depends(get_current_customer)):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, policy_text, created_at FROM ai_policies WHERE customer_id = $1 ORDER BY created_at",
            customer["id"],
        )
    return [
        {"id": str(r["id"]), "policy_text": r["policy_text"], "created_at": r["created_at"].isoformat()}
        for r in rows
    ]


@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def create_policy(body: PolicyCreate, customer=Depends(get_current_customer)):
    pool = get_pool()
    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM ai_policies WHERE customer_id = $1",
            customer["id"],
        )
        if count >= MAX_POLICIES:
            raise HTTPException(status_code=400, detail=f"Maximum {MAX_POLICIES} policies allowed")
        row = await conn.fetchrow(
            """INSERT INTO ai_policies (customer_id, policy_text)
               VALUES ($1, $2)
               RETURNING id, policy_text, created_at""",
            customer["id"],
            body.policy_text,
        )
    return {
        "id": str(row["id"]),
        "policy_text": row["policy_text"],
        "created_at": row["created_at"].isoformat(),
    }


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: UUID, customer=Depends(get_current_customer)):
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM ai_policies WHERE id = $1 AND customer_id = $2",
            policy_id,
            customer["id"],
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/enable", status_code=200)
async def enable_ai(customer=Depends(get_current_customer)):
    """Enable AI scanning for this customer."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE customers SET ai_scan_enabled = TRUE WHERE id = $1",
            customer["id"],
        )
    return {"ai_scan_enabled": True}


@router.post("/disable", status_code=200)
async def disable_ai(customer=Depends(get_current_customer)):
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE customers SET ai_scan_enabled = FALSE WHERE id = $1",
            customer["id"],
        )
    return {"ai_scan_enabled": False}
