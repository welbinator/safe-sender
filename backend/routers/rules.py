"""
Rules CRUD endpoints.

GET    /rules           — list all rules for the authenticated customer
POST   /rules           — create a new rule
PUT    /rules/{rule_id} — update an existing rule
DELETE /rules/{rule_id} — deactivate (soft-delete) a rule
"""
from typing import Any, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

# google-re2 — RE2 has linear-time guarantees and is immune to ReDoS.
# Falls back to the stdlib `re` module if google-re2 isn't installed so dev
# checkouts don't break, but a startup warning makes it loud.
try:
    import re2 as _regex_engine  # type: ignore
    _USING_RE2 = True
except ImportError:  # pragma: no cover - dev fallback
    import re as _regex_engine  # type: ignore
    _USING_RE2 = False
    import logging
    logging.getLogger(__name__).warning(
        "google-re2 not installed — falling back to stdlib `re`. "
        "Customer regexes will NOT be ReDoS-safe. Install google-re2 in prod."
    )

from deps import get_current_customer, get_pool

router = APIRouter(prefix="/rules", tags=["rules"])

VALID_MATCH_TYPES = {"string", "regex"}
VALID_SCOPES = {"external", "internal", "both"}

# Customer-controlled regex patterns are capped to keep the engine fast and
# the storage column bounded.
MAX_PATTERN_LEN = 1000
MAX_NAME_LEN = 200
MAX_DESCRIPTION_LEN = 2000
MAX_EMAIL_LEN = 320  # RFC 5321 max


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RuleBase(BaseModel):
    name: Optional[str] = Field(default=None, max_length=MAX_NAME_LEN)
    pattern: str = Field(..., min_length=1, max_length=MAX_PATTERN_LEN)
    match_type: str = Field(..., max_length=16)
    scope: str = Field(default="external", max_length=16)
    applies_to_email: Optional[str] = Field(default=None, max_length=MAX_EMAIL_LEN)
    is_exception: bool = False
    description: Optional[str] = Field(default=None, max_length=MAX_DESCRIPTION_LEN)

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


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=MAX_NAME_LEN)
    pattern: Optional[str] = Field(default=None, min_length=1, max_length=MAX_PATTERN_LEN)
    match_type: Optional[str] = Field(default=None, max_length=16)
    scope: Optional[str] = Field(default=None, max_length=16)
    applies_to_email: Optional[str] = Field(default=None, max_length=MAX_EMAIL_LEN)
    is_exception: Optional[bool] = None
    description: Optional[str] = Field(default=None, max_length=MAX_DESCRIPTION_LEN)
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
    name: Optional[str]
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
        name=row["name"],
        pattern=row["pattern"],
        match_type=row["match_type"],
        scope=row["scope"],
        applies_to_email=row["applies_to_email"],
        is_exception=row["is_exception"],
        active=row["active"],
        description=row["description"],
    )


def _assert_valid_regex(pattern: str, match_type: str):
    if match_type != "regex":
        return
    try:
        _regex_engine.compile(pattern)
    except Exception as e:
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
            SELECT id, customer_id, name, pattern, match_type, scope,
                   applies_to_email, is_exception, active, description
            FROM rules
            WHERE customer_id = $1 AND active = TRUE
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
                (customer_id, name, pattern, match_type, scope,
                 applies_to_email, is_exception, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, customer_id, name, pattern, match_type, scope,
                      applies_to_email, is_exception, active, description
            """,
            customer["id"],
            body.name,
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

        new_pattern = body.pattern if body.pattern is not None else existing["pattern"]
        new_match_type = body.match_type if body.match_type is not None else existing["match_type"]
        _assert_valid_regex(new_pattern, new_match_type)

        row = await conn.fetchrow(
            """
            UPDATE rules SET
                name             = COALESCE($1, name),
                pattern          = COALESCE($2, pattern),
                match_type       = COALESCE($3, match_type),
                scope            = COALESCE($4, scope),
                applies_to_email = COALESCE($5, applies_to_email),
                is_exception     = COALESCE($6, is_exception),
                description      = COALESCE($7, description),
                active           = COALESCE($8, active),
                updated_at       = NOW()
            WHERE id = $9 AND customer_id = $10
            RETURNING id, customer_id, name, pattern, match_type, scope,
                      applies_to_email, is_exception, active, description
            """,
            body.name,
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
    """Soft-delete (deactivate) a rule.

    We never hard-delete: rules remain referenced by `scan_logs.matched_rule_id`
    for audit purposes (H9). 404 if the rule was already inactive — clients
    should treat that as 'already gone'.
    """
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE rules
               SET active = FALSE,
                   updated_at = NOW()
             WHERE id = $1 AND customer_id = $2 AND active = TRUE
            """,
            rule_id, customer["id"],
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Rule not found")
