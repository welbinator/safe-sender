"""
Customer endpoints:
  GET    /customers/me                  — profile
  PATCH  /customers/me                  — update name
  POST   /customers/verify-domain/init  — generate DNS TXT verification token
  POST   /customers/verify-domain/check — confirm TXT record is live in DNS
  POST   /customers/test-connection     — send a test email through our SMTP, wait for scan log
"""
import os
import secrets
import smtplib
import time
from email.mime.text import MIMEText
from typing import Any, Optional

import asyncpg
import bcrypt
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from deps import get_current_customer, get_pool

router = APIRouter(prefix="/customers", tags=["customers"])

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.sendersafety.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
SMTP_AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")


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
    txt_name: str      # e.g. "@" or "_sendersafety"
    txt_value: str     # full value to paste into DNS


class VerifyCheckResponse(BaseModel):
    verified: bool
    message: str


class TestConnectionResponse(BaseModel):
    success: bool
    message: str


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
    return _to_customer_response(dict(row))


@router.post("/verify-domain/init", response_model=VerifyInitResponse)
async def verify_domain_init(
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Generate a DNS TXT verification token for the customer's domain.
    The customer must add a TXT record to their domain's DNS:
      Name:  _sendersafety
      Value: sendersafety-verify=<token>
    """
    if customer.get("domain_verified"):
        return VerifyInitResponse(
            token="already-verified",
            txt_name="_sendersafety",
            txt_value="already-verified",
        )

    token = secrets.token_hex(20)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE customers SET domain_verification_token = $1 WHERE id = $2",
            token,
            customer["id"],
        )

    return VerifyInitResponse(
        token=token,
        txt_name="_sendersafety",
        txt_value=f"sendersafety-verify={token}",
    )


@router.post("/verify-domain/check", response_model=VerifyCheckResponse)
async def verify_domain_check(
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Look up the DNS TXT record for the customer's domain and confirm the token matches.
    """
    if customer.get("domain_verified"):
        return VerifyCheckResponse(verified=True, message="Domain already verified.")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT domain_verification_token FROM customers WHERE id = $1",
            customer["id"],
        )
    token = row["domain_verification_token"] if row else None
    if not token:
        raise HTTPException(status_code=400, detail="Run verify-domain/init first.")

    domain = customer["domain"]
    expected = f"sendersafety-verify={token}"
    found = False

    try:
        answers = dns.resolver.resolve(f"_sendersafety.{domain}", "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode() == expected:
                    found = True
                    break
    except Exception:
        pass

    if found:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE customers SET domain_verified = TRUE WHERE id = $1",
                customer["id"],
            )
        return VerifyCheckResponse(verified=True, message="Domain verified successfully!")
    else:
        return VerifyCheckResponse(
            verified=False,
            message=(
                f"TXT record not found yet. Make sure you added:\n"
                f"  Name: _sendersafety.{domain}\n"
                f"  Value: {expected}\n"
                f"DNS changes can take up to 48 hours to propagate."
            ),
        )


@router.post("/test-connection", response_model=TestConnectionResponse)
async def test_connection(
    customer: dict[str, Any] = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Send a real SMTP test email through our gateway and confirm it appears in scan logs.
    The test email uses the sender sendersafety-test@<domain> so it bypasses rule matching
    but still exercises the full SMTP path and produces a scan log entry.
    """
    domain = customer["domain"]
    customer_id = str(customer["id"])
    test_sender = f"sendersafety-test@{domain}"
    test_recipient = "delivery-test@sendersafety.com"
    test_subject = "Sender Safety connection test"

    # Record the count of scan logs before we send
    async with pool.acquire() as conn:
        before_count = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_logs WHERE customer_id = $1", customer["id"]
        )

    # Send the test email via our own SMTP server
    try:
        msg = MIMEText("This is an automated connection test from Sender Safety.")
        msg["Subject"] = test_subject
        msg["From"] = test_sender
        msg["To"] = test_recipient

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if SMTP_AUTH_USERNAME and SMTP_AUTH_PASSWORD:
                smtp.login(SMTP_AUTH_USERNAME, SMTP_AUTH_PASSWORD)
            smtp.sendmail(test_sender, [test_recipient], msg.as_string())
    except Exception as e:
        return TestConnectionResponse(
            success=False,
            message=f"Could not connect to SMTP gateway: {e}",
        )

    # Poll for a new scan log entry (up to 10 seconds)
    deadline = time.time() + 10
    appeared = False
    while time.time() < deadline:
        async with pool.acquire() as conn:
            after_count = await conn.fetchval(
                "SELECT COUNT(*) FROM scan_logs WHERE customer_id = $1", customer["id"]
            )
        if after_count > before_count:
            appeared = True
            break
        import asyncio
        await asyncio.sleep(1)

    if appeared:
        return TestConnectionResponse(
            success=True,
            message="✅ Success! Your email passed through the Sender Safety gateway and appeared in your scan logs.",
        )
    else:
        return TestConnectionResponse(
            success=False,
            message=(
                "The test email was sent but didn't appear in scan logs within 10 seconds. "
                "Your SMTP gateway may not be configured yet, or DNS propagation is still in progress."
            ),
        )


# ---------------------------------------------------------------------------
# GET  /customers/me/smtp-credentials
# POST /customers/me/smtp-credentials/rotate
# ---------------------------------------------------------------------------

class SmtpCredentialsResponse(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_username: str


class SmtpRotateResponse(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str  # plaintext — shown once only


@router.get("/me/smtp-credentials", response_model=SmtpCredentialsResponse)
async def get_smtp_credentials(
    customer: dict = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Return SMTP host/port/username. Password is never returned after initial signup."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT smtp_username FROM customers WHERE id = $1", customer["id"]
        )
    if not row or not row["smtp_username"]:
        raise HTTPException(status_code=404, detail="SMTP credentials not yet generated")
    return SmtpCredentialsResponse(
        smtp_host="smtp.sendersafety.com",
        smtp_port=587,
        smtp_username=row["smtp_username"],
    )


@router.post("/me/smtp-credentials/rotate", response_model=SmtpRotateResponse)
async def rotate_smtp_credentials(
    customer: dict = Depends(get_current_customer),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Generate a new password. Returns plaintext password once — store it immediately."""
    new_password = secrets.token_urlsafe(16)
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE customers
            SET smtp_password_hash = $1
            WHERE id = $2
            RETURNING smtp_username
            """,
            new_hash,
            customer["id"],
        )
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")
    return SmtpRotateResponse(
        smtp_host="smtp.sendersafety.com",
        smtp_port=587,
        smtp_username=row["smtp_username"],
        smtp_password=new_password,
    )
