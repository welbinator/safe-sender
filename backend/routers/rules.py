"""
Rules CRUD endpoints.

GET    /rules           — list all active rules for the authenticated customer
POST   /rules           — create a new rule
PUT    /rules/{rule_id} — update an existing rule
DELETE /rules/{rule_id} — deactivate (soft-delete) a rule

This router is thin by design: it parses request bodies, hands them to
RuleService, and translates service errors to HTTPException.
"""
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from deps import get_current_customer, get_rule_service
from services import (
    InvalidRegexPattern,
    NotFoundError,
    RuleService,
    TooManyRules,
)
from services.rules import VALID_MATCH_TYPES, VALID_SCOPES

router = APIRouter(prefix="/rules", tags=["rules"])

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

def _row_to_rule(row: dict[str, Any]) -> RuleResponse:
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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=List[RuleResponse])
async def list_rules(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: RuleService = Depends(get_rule_service),
):
    rows = await service.list_for_customer(customer["id"])
    return [_row_to_rule(r) for r in rows]


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(
    body: RuleCreate,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: RuleService = Depends(get_rule_service),
):
    try:
        row = await service.create(
            customer_id=customer["id"],
            name=body.name,
            pattern=body.pattern,
            match_type=body.match_type,
            scope=body.scope,
            applies_to_email=body.applies_to_email,
            is_exception=body.is_exception,
            description=body.description,
        )
    except InvalidRegexPattern as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    except TooManyRules as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    return _row_to_rule(row)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: RuleService = Depends(get_rule_service),
):
    try:
        row = await service.update(
            rule_id=rule_id,
            customer_id=customer["id"],
            name=body.name,
            pattern=body.pattern,
            match_type=body.match_type,
            scope=body.scope,
            applies_to_email=body.applies_to_email,
            is_exception=body.is_exception,
            description=body.description,
            active=body.active,
        )
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except InvalidRegexPattern as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    except TooManyRules as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    return _row_to_rule(row)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: RuleService = Depends(get_rule_service),
):
    """Soft-delete (deactivate) a rule.

    We never hard-delete: rules remain referenced by `scan_logs.matched_rule_id`
    for audit purposes (H9). 404 if the rule was already inactive — clients
    should treat that as 'already gone'.
    """
    try:
        await service.soft_delete(rule_id, customer["id"])
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
