"""
GET /customers/me — return current customer's profile.
PATCH /customers/me — update name / domain (domain change re-verified separately).
"""
from typing import Any, Optional

import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from deps import get_current_customer, get_pool

router = APIRouter(prefix="/customers", tags=["customers"])


class CustomerResponse(BaseModel):
    id: str
    domain: str
    name: Optional[str]
    email: str
    plan: str
    active: bool


class CustomerUpdate(BaseModel):
    name: Optional[str] = None


@router.get("/me", response_model=CustomerResponse)
async def get_me(customer: dict[str, Any] = Depends(get_current_customer)):
    return CustomerResponse(
        id=str(customer["id"]),
        domain=customer["domain"],
        name=customer["name"],
        email=customer["email"],
        plan=customer["plan"],
        active=customer["active"],
    )


@router.patch("/me", response_model=CustomerResponse)
async def update_me(
    body: CustomerUpdate,
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE customers
            SET name = COALESCE($1, name),
                updated_at = NOW()
            WHERE id = $2
            RETURNING *
            """,
            body.name,
            customer["id"],
        )
    return CustomerResponse(
        id=str(row["id"]),
        domain=row["domain"],
        name=row["name"],
        email=row["email"],
        plan=row["plan"],
        active=row["active"],
    )
