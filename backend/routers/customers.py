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
from services.errors import DomainConflictError, CannotRemoveLastDomainError, DomainVerificationNotInitialized

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

class DomainEntry(BaseModel):
    id: str
    domain: str
    verified: bool
    created_at: Optional[str]


class AddDomainRequest(BaseModel):
    domain: str


class CustomerResponse(BaseModel):
    id: str
    domain: str
    name: Optional[str]
    email: str
    plan: str
    active: bool
    domain_verified: bool
    domains: list[DomainEntry] = []


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

def _to_customer_response(row: dict, domains: list = None) -> CustomerResponse:
    domain_entries = []
    if domains:
        for d in domains:
            domain_entries.append(DomainEntry(
                id=str(d["id"]),
                domain=d["domain"],
                verified=d.get("verified", False),
                created_at=d["created_at"].isoformat() if d.get("created_at") else None,
            ))
    return CustomerResponse(
        id=str(row["id"]),
        domain=row["domain"],
        name=row["name"],
        email=row["email"],
        plan=row["plan"],
        active=row["active"],
        domain_verified=row.get("domain_verified", False),
        domains=domain_entries,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/me", response_model=CustomerResponse)
async def get_me(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    domains = await service.list_domains(customer["id"])
    if not domains and customer.get("domain"):
        # backward compat: expose legacy single domain as unverified entry
        domains = [{"id": str(customer["id"]), "domain": customer["domain"], "verified": customer.get("domain_verified", False), "created_at": None}]
    return _to_customer_response(customer, domains)


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

# ---------------------------------------------------------------------------
# Multi-domain management routes
# ---------------------------------------------------------------------------

@router.get("/domains", response_model=list[DomainEntry])
async def list_domains(
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    domains = await service.list_domains(customer["id"])
    return [
        DomainEntry(
            id=str(d["id"]),
            domain=d["domain"],
            verified=d.get("verified", False),
            created_at=d["created_at"].isoformat() if d.get("created_at") else None,
        )
        for d in domains
    ]


@router.post("/domains", response_model=DomainEntry, status_code=201)
async def add_domain(
    body: AddDomainRequest,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    try:
        row = await service.add_domain(customer, body.domain)
    except DomainConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return DomainEntry(
        id=str(row["id"]),
        domain=row["domain"],
        verified=row.get("verified", False),
        created_at=row.get("created_at"),
    )


@router.post("/domains/{domain}/verify/init", response_model=VerifyInitResponse)
async def domain_verify_init(
    domain: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    try:
        result = await service.init_domain_verification_for(customer, domain)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return VerifyInitResponse(**result)


@router.post("/domains/{domain}/verify/check", response_model=VerifyCheckResponse)
async def domain_verify_check(
    domain: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    try:
        result = await service.check_domain_verification_for(customer, domain)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except DomainVerificationNotInitialized as e:
        raise HTTPException(status_code=400, detail=str(e))
    return VerifyCheckResponse(verified=result.verified, message=result.message)


@router.delete("/domains/{domain}", status_code=204)
async def remove_domain(
    domain: str,
    customer: dict[str, Any] = Depends(get_current_customer),
    service: CustomerService = Depends(get_customer_service),
):
    try:
        await service.remove_domain(customer, domain)
    except CannotRemoveLastDomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
