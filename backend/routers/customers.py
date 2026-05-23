"""
Customer endpoints:
  GET    /customers/me                          — profile
  PATCH  /customers/me                          — update name
  POST   /customers/verify-domain/init          — generate DNS TXT verification token
  POST   /customers/verify-domain/check         — confirm TXT record is live in DNS
  POST   /customers/test-connection             — send a test email through our SMTP, wait for scan log
  GET    /customers/me/smtp-credentials         — host/port/username (no password)
  POST   /customers/me/smtp-credentials/rotate  — rotate password, returns plaintext once

This router is thin: parse → call CustomerService → translate errors → respond.
SMTP/DNS/bcrypt machinery lives in the service.
"""
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from deps import get_current_customer, get_customer_service
from services import NotFoundError
from services.customers import CustomerService

router = APIRouter(prefix="/customers", tags=["customers"])

# Environment-provided SMTP override for test-connection only. The
# *destination* gateway hostname/port are pinned in the service; these are the
# *auth* creds the smoke test will present (typically empty for now).
_SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.sendersafety.com")
_SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
_SMTP_AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
_SMTP_AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CustomerResponse(BaseModel):
    id: str
    domain: str
    name: Optional[str]
    email: str
    plan: str
    active: bool
    domain_verified: bool


class CustomerUpdate(BaseModel):
    name: Optional[str] = None


class VerifyInitResponse(BaseModel):
    token: str
    txt_name: str
    txt_value: str


class VerifyCheckResponse(BaseModel):
    verified: bool
    message: str


class TestConnectionResponse(BaseModel):
    # F-16: handler returns 202 + test_id; the dashboard polls status via GET.
    test_id: str
    status: str  # always "pending" on POST


class TestConnectionStatusResponse(BaseModel):
    status: str  # "pending" | "done"
    success: Optional[bool] = None
    message: Optional[str] = None


class SmtpCredentialsResponse(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_username: str


class SmtpRotateResponse(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str  # plaintext — shown once only


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_customer_response(row: dict) -> CustomerResponse:
    return CustomerResponse(
        id=str(row["id"]),
        domain=row["domain"],
        name=row["name"],
        email=row["email"],
        plan=row["plan"],
        active=row["active"],
        domain_verified=row.get("domain_verified", False),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/me", response_model=CustomerResponse)
async def get_me(customer: dict[str, Any] = Depends(get_current_customer)):
    return _to_customer_response(customer)


@router.patch("/me", response_model=CustomerResponse)
async def update_me(
    body: CustomerUpdate,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    row = await service.update_name(customer["id"], body.name)
    return _to_customer_response(row)


@router.post("/verify-domain/init", response_model=VerifyInitResponse)
async def verify_domain_init(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Generate (or return-existing) a DNS TXT verification token."""
    result = await service.init_domain_verification(customer)
    return VerifyInitResponse(**result)


@router.post("/verify-domain/check", response_model=VerifyCheckResponse)
async def verify_domain_check(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Look up the customer's domain TXT record and confirm the token matches."""
    try:
        result = await service.check_domain_verification(customer)
    except Exception as e:
        from services.errors import DomainVerificationNotInitialized
        if isinstance(e, DomainVerificationNotInitialized):
            raise HTTPException(status_code=e.status_code, detail=str(e))
        raise
    return VerifyCheckResponse(verified=result.verified, message=result.message)


@router.post("/test-connection", response_model=TestConnectionResponse, status_code=202)
async def test_connection(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Kick off an SMTP smoke-test in the background. F-16: returns immediately."""
    test_id = await service.start_test_smtp_connection(
        customer,
        smtp_host=_SMTP_HOST,
        smtp_port=_SMTP_PORT,
        auth_username=_SMTP_AUTH_USERNAME,
        auth_password=_SMTP_AUTH_PASSWORD,
    )
    return TestConnectionResponse(test_id=test_id, status="pending")


@router.get(
    "/test-connection/{test_id}", response_model=TestConnectionStatusResponse
)
async def test_connection_status(
    test_id: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Poll for a previously-started test. 404 hides cross-tenant existence."""
    status = await service.get_test_connection_status(test_id, customer["id"])
    if status is None:
        raise HTTPException(status_code=404, detail="Test not found")
    return TestConnectionStatusResponse(**status)


@router.get("/me/smtp-credentials", response_model=SmtpCredentialsResponse)
async def get_smtp_credentials(
    customer: dict = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Return SMTP host/port/username. Password is never returned after initial signup."""
    try:
        result = await service.get_smtp_credentials(customer["id"])
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return SmtpCredentialsResponse(**result)


@router.post("/me/smtp-credentials/rotate", response_model=SmtpRotateResponse)
async def rotate_smtp_credentials(
    customer: dict = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    """Generate a new password. Returns plaintext password once — store it immediately."""
    try:
        result = await service.rotate_smtp_password(customer["id"])
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return SmtpRotateResponse(**result)
