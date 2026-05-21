"""
POST /auth/google — exchange Google ID token for session JWT.

Flow:
1. Client obtains a Google ID token (via Google Sign-In JS lib).
2. Client POSTs that token here.
3. We verify it with Google's tokeninfo endpoint (incl. hd-claim binding when
   WORKSPACE_ONLY=1; see auth_utils.verify_google_id_token).
4. We upsert a customer row keyed on google_sub.
5. We return our own JWT session token.

Sprint B hardening:
  - C10: html.escape() in welcome email — no user input is interpolated into
         HTML without escaping.
  - H12: domain is derived from Google's verified `hd` claim only — the client
         can no longer impersonate other Workspace domains via body.domain.
  - H13: welcome email send moved off the request path via BackgroundTasks +
         asyncio.to_thread so we never block the event loop on SES.
"""
import html as _html
import os
import secrets
import asyncio
from typing import Optional

import asyncpg
import bcrypt
import boto3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from auth_utils import create_jwt, verify_google_id_token
from deps import get_pool

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_SOURCE_ARN = os.environ.get("SES_SOURCE_ARN", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@sendersafety.com")

router = APIRouter(prefix="/auth", tags=["auth"])


def _send_welcome_email_sync(to_email: str, name: str, domain: str) -> None:
    """Send the welcome email via SES (synchronous boto3 call).

    All untrusted strings (name, domain) are HTML-escaped before
    interpolation into the HTML body. The plain-text body interpolates the
    raw values (no escaping required there).
    """
    safe_name_html = _html.escape(name)
    safe_domain_html = _html.escape(domain)

    subject = "Welcome to Sender Safety — let's get you set up"
    body_text = f"""Hi {name},

Welcome to Sender Safety! You're one step away from protecting every email that leaves {domain}.

Here's what to do next:

1. Verify your domain
   Log in to your dashboard and follow the domain verification steps. You'll add a simple DNS record — takes about 2 minutes.

2. Configure your SMTP gateway
   In Google Workspace Admin, go to Apps → Gmail → Routing → Outbound Gateway and point it to:
   smtp.sendersafety.com (port 587)

3. Add your first keyword rule
   Head to the Rules section and add any words or phrases you want to flag or block in outgoing emails.

4. Test the connection
   Use the "Test connection" button in your dashboard to confirm emails are flowing through the gateway.

That's it. Once those four steps are done, Sender Safety is live for your entire organization.

If you run into anything, just reply to this email.

— The Sender Safety team
https://app.sendersafety.com
"""

    body_html = f"""<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#222;">
<h2 style="color:#1a1a1a;">Welcome to Sender Safety 👋</h2>
<p>Hi {safe_name_html},</p>
<p>You're one step away from protecting every email that leaves <strong>{safe_domain_html}</strong>.</p>
<h3>Here's what to do next:</h3>
<ol>
  <li style="margin-bottom:12px;">
    <strong>Verify your domain</strong><br>
    Log in to your dashboard and follow the domain verification steps. You'll add a simple DNS record — takes about 2 minutes.
  </li>
  <li style="margin-bottom:12px;">
    <strong>Configure your SMTP gateway</strong><br>
    In Google Workspace Admin, go to <em>Apps → Gmail → Routing → Outbound Gateway</em> and point it to:<br>
    <code style="background:#f4f4f4;padding:2px 6px;border-radius:3px;">smtp.sendersafety.com (port 587)</code>
  </li>
  <li style="margin-bottom:12px;">
    <strong>Add your first keyword rule</strong><br>
    Head to the Rules section and add any words or phrases you want to flag in outgoing emails.
  </li>
  <li style="margin-bottom:12px;">
    <strong>Test the connection</strong><br>
    Use the "Test connection" button in your dashboard to confirm emails are flowing through the gateway.
  </li>
</ol>
<p>Once those four steps are done, Sender Safety is live for your entire organization.</p>
<p>If you run into anything, just reply to this email.</p>
<p style="margin-top:32px;color:#888;font-size:13px;">— The Sender Safety team<br>
<a href="https://app.sendersafety.com">app.sendersafety.com</a></p>
</body></html>"""

    try:
        ses = boto3.client("ses", region_name=AWS_REGION)
        kwargs = dict(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": body_text, "Charset": "UTF-8"},
                    "Html": {"Data": body_html, "Charset": "UTF-8"},
                },
            },
        )
        if SES_SOURCE_ARN:
            kwargs["SourceArn"] = SES_SOURCE_ARN
        ses.send_email(**kwargs)
    except Exception as exc:
        print(f"[auth] Welcome email failed (non-fatal): {exc}", flush=True)


async def _send_welcome_email_bg(to_email: str, name: str, domain: str) -> None:
    """Run the blocking SES send in a worker thread so we never stall the loop."""
    await asyncio.to_thread(_send_welcome_email_sync, to_email, name, domain)


class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., max_length=4096)
    # Optional: customer's Google Workspace domain (e.g. "acme.com").
    # IGNORED for security — we trust Google's `hd` claim instead. Kept for
    # backwards-compat with the client; do NOT use without re-verifying.
    domain: Optional[str] = Field(default=None, max_length=253)
    company_name: Optional[str] = Field(default=None, max_length=200)


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    customer_id: str
    email: str
    is_new: bool
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None  # plaintext, returned once on signup only


def _generate_smtp_credentials() -> tuple[str, str, str]:
    """Return (smtp_username, raw_password, password_hash)."""
    smtp_username = "ss_" + secrets.token_hex(8)
    raw_password = secrets.token_urlsafe(16)
    password_hash = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
    return smtp_username, raw_password, password_hash


@router.post("/google", response_model=AuthResponse)
async def auth_google(
    body: GoogleAuthRequest,
    background_tasks: BackgroundTasks,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Verify Google ID token, upsert customer, return session JWT."""
    # Test-mode bypass: ALLOW_TEST_TOKENS=1 lets tests pass fake claims as
    # JSON-encoded id_token prefixed with "test:". Never enable in prod.
    if os.environ.get("ALLOW_TEST_TOKENS") == "1" and body.id_token.startswith("test:"):
        import json as _json
        claims = _json.loads(body.id_token[5:])
    else:
        claims = await verify_google_id_token(body.id_token)

    google_sub = claims["sub"]
    email = claims["email"]
    name = claims.get("name", "")
    # SECURITY (H12): trust Google's verified `hd` claim — never body.domain.
    # Falls back to email-derived domain only when WORKSPACE_ONLY is off
    # (test/dev only — verify_google_id_token requires hd in prod).
    domain = (claims.get("hd") or email.split("@")[-1]).lower()
    company_name = body.company_name or name

    async with pool.acquire() as conn:
        # Look up by google_sub first (returning customer)
        row = await conn.fetchrow(
            "SELECT id, email FROM customers WHERE google_sub = $1", google_sub
        )
        smtp_username = None
        smtp_raw_password = None
        if row:
            customer_id = str(row["id"])
            is_new = False
        else:
            # Check if someone already registered this domain under a different Google account
            domain_row = await conn.fetchrow(
                "SELECT id FROM customers WHERE domain = $1", domain
            )
            if domain_row:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "This domain is already registered. "
                        "Contact support if you believe this is an error."
                    ),
                )

            # New customer — generate SMTP credentials + insert
            smtp_username, smtp_raw_password, smtp_password_hash = _generate_smtp_credentials()
            row = await conn.fetchrow(
                """
                INSERT INTO customers (domain, name, email, google_sub, plan, smtp_username, smtp_password_hash)
                VALUES ($1, $2, $3, $4, 'basic', $5, $6)
                RETURNING id, email
                """,
                domain,
                company_name,
                email,
                google_sub,
                smtp_username,
                smtp_password_hash,
            )
            customer_id = str(row["id"])
            is_new = True

    token = create_jwt(customer_id, email)

    if is_new:
        # H13: off the request path — runs after the response is sent.
        background_tasks.add_task(
            _send_welcome_email_bg, email, name or email.split("@")[0], domain
        )

    return AuthResponse(
        access_token=token,
        customer_id=customer_id,
        email=email,
        is_new=is_new,
        smtp_username=smtp_username if is_new else None,
        smtp_password=smtp_raw_password if is_new else None,
    )
