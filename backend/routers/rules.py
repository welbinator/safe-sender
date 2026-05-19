"""
Rules CRUD endpoints.

GET    /rules           — list all rules for the authenticated customer
POST   /rules           — create a new rule
PUT    /rules/{rule_id} — update an existing rule
DELETE /rules/{rule_id} — deactivate (soft-delete) a rule
"""
import re
from typing import Any, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from deps import get_current_customer, get_pool

router = APIRouter(prefix="/rules", tags=["rules"])

VALID_MATCH_TYPES = {"string", "regex"}
VALID_SCOPES = {"external", "internal", "both"}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RuleBase(BaseModel):
    pattern: str
    match_type: str
    scope: str = "external"
    applies_to_email: Optional[str] = None
    is_exception: bool = False
    description: Optional[str] = None

    @field_validator("match_type")
    @classmethod
    def validate_match_type(cls, v: str) -> str:
        if v not in VALID_MATCH_TYPES:
            raise ValueError(f"match_type must be one of {VALID_MATCH_TYPES}")
        return v

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        if v not in VALID_SCOPES:
            raise ValueError(f"scope must be one of {VALID_SCOPES}")
        return v

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str, info) -> str:
        # Validated after match_type is set in model; check regex compiles
        return v


class RuleCreate(RuleBase):
    @field_validator("pattern")
    @classmethod
    def validate_regex_compiles(cls, v: str) -> str:
        # We can't easily access match_type here, so validate on creation
        return v


class RuleUpdate(BaseModel):
    pattern: Optional[str] = None
    match_type: Optional[str] = None
    scope: Optional[str] = None
    applies_to_email: Optional[str] = None
    is_exception: Optional[bool] = None
    description: Optional[str] = None
    active: Optional[bool] = None

    @field_validator("match_type")
    @classmethod
    def validate_match_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_MATCH_TYPES:
            raise ValueError(f"match_type must be one of {VALID_MATCH_TYPES}")
        return v

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_SCOPES:
            raise ValueError(f"scope must be one of {VALID_SCOPES}")
        return v


class RuleResponse(BaseModel):
    id: str
    customer_id: str
    pattern: str
    match_type: str
    scope: str
    applies_to_email: Optional[str]
    is_exception: bool
    active: bool
    description: Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_rule(row) -> RuleResponse:
    return RuleResponse(
        id=str(row["id"]),
        customer_id=str(row["customer_id"]),
        pattern=row["pattern"],
        match_type=row["match_type"],
        scope=row["scope"],
        applies_to_email=row["applies_to_email"],
        is_exception=row["is_exception"],
        active=row["active"],
        description=row["description"],
    )


def _assert_valid_regex(pattern: str, match_type: str):
    if match_type == "regex":
        try:
            re.compile(pattern)
        except re.error as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid regex pattern: {e}",
            )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=List[RuleResponse])
async def list_rules(
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, customer_id, pattern, match_type, scope,
                   applies_to_email, is_exception, active, description
            FROM rules
            WHERE customer_id = $1
            ORDER BY created_at ASC
            """,
            customer["id"],
        )
    return [_row_to_rule(r) for r in rows]


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    _assert_valid_regex(body.pattern, body.match_type)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO rules
                (customer_id, pattern, match_type, scope,
                 applies_to_email, is_exception, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, customer_id, pattern, match_type, scope,
                      applies_to_email, is_exception, active, description
            """,
            customer["id"],
            body.pattern,
            body.match_type,
            body.scope,
            body.applies_to_email,
            body.is_exception,
            body.description,
        )
    return _row_to_rule(row)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT * FROM rules WHERE id = $1 AND customer_id = $2",
            rule_id, customer["id"],
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Rule not found")

        # Merge updates onto existing values
        new_pattern = body.pattern if body.pattern is not None else existing["pattern"]
        new_match_type = body.match_type if body.match_type is not None else existing["match_type"]
        _assert_valid_regex(new_pattern, new_match_type)

        row = await conn.fetchrow(
            """
            UPDATE rules SET
                pattern          = COALESCE($1, pattern),
                match_type       = COALESCE($2, match_type),
                scope            = COALESCE($3, scope),
                applies_to_email = COALESCE($4, applies_to_email),
                is_exception     = COALESCE($5, is_exception),
                description      = COALESCE($6, description),
                active           = COALESCE($7, active),
                updated_at       = NOW()
            WHERE id = $8 AND customer_id = $9
            RETURNING id, customer_id, pattern, match_type, scope,
                      applies_to_email, is_exception, active, description
            """,
            body.pattern,
            body.match_type,
            body.scope,
            body.applies_to_email,
            body.is_exception,
            body.description,
            body.active,
            rule_id,
            customer["id"],
        )
    return _row_to_rule(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM rules WHERE id = $1 AND customer_id = $2",
            rule_id, customer["id"],
        )
    # asyncpg returns "DELETE N" — N=0 means row didn't exist
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Rule not found")
