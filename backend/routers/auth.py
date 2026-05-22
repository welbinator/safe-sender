"""
POST /auth/google — exchange Google ID token for session JWT.
POST /auth/logout — clears the session cookie.

Sprint C1 t7: the upsert + domain-conflict + SMTP credential minting moved to
AuthService; the welcome-email body (HTML/plaintext) lives in services.email_templates
and is dispatched via BackgroundTasks. The router now owns only:
  - Google ID-token verification (incl. ALLOW_TEST_TOKENS bypass)
  - cookie semantics (HttpOnly, Secure, SameSite=Lax)
  - background-task scheduling for the welcome email
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

import boto3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from security import create_jwt, verify_google_id_token
from deps import get_auth_service
from services import AuthService, ConflictError, ServiceError
from services.email_templates import render_welcome_email

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_SOURCE_ARN = os.environ.get("SES_SOURCE_ARN", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@sendersafety.com")

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Welcome email — sent off the request path via BackgroundTasks.
# Templates live in services.email_templates; SES delivery stays here because
# it's an HTTP/SES adapter concern, not business logic.
# ---------------------------------------------------------------------------
def _send_welcome_email_sync(to_email: str, name: str, domain: str) -> None:
    subject, body_text, body_html = render_welcome_email(name=name, domain=domain)
    try:
        ses = boto3.client("ses", region_name=AWS_REGION)
        kwargs: dict = dict(
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
        # H13 + general welcome-email failures are non-fatal.
        print(f"[auth] Welcome email failed (non-fatal): {exc}", flush=True)


async def _send_welcome_email_bg(to_email: str, name: str, domain: str) -> None:
    await asyncio.to_thread(_send_welcome_email_sync, to_email, name, domain)


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------
class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., max_length=4096)
    # IGNORED for security (H12) — we trust Google's `hd` claim. Kept for
    # backwards-compat with the client; do NOT use without re-verifying.
    domain: Optional[str] = Field(default=None, max_length=253)
    company_name: Optional[str] = Field(default=None, max_length=200)


class AuthResponse(BaseModel):
    # C13: the JWT is delivered via HttpOnly cookie, never in the body. SMTP
    # plaintext password is no longer returned at signup — the client calls
    # POST /customers/me/smtp-credentials/rotate. `is_new=true` triggers the
    # "show rotate prompt" UX.
    customer_id: str
    email: str
    is_new: bool
    smtp_username: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/google", response_model=AuthResponse)
async def auth_google(
    body: GoogleAuthRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
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
    # H12: trust Google's verified `hd` claim — never body.domain. Falls back
    # to email-derived domain only when WORKSPACE_ONLY is off (test/dev only).
    domain = (claims.get("hd") or email.split("@")[-1]).lower()
    company_name = body.company_name or name

    try:
        result = await auth.login_with_google_claims(
            google_sub=google_sub,
            email=email,
            domain=domain,
            company_name=company_name,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    token = create_jwt(result.customer_id, result.email)

    # C13: HttpOnly session cookie. JS can't read it, so XSS can't steal the
    # JWT. SameSite=Lax + Secure prevents CSRF on the dominant vectors.
    response.set_cookie(
        key="session",
        value=token,
        max_age=60 * 60 * 24 * 7,
        path="/",
        httponly=True,
        secure=os.environ.get("COOKIE_INSECURE") != "1",
        samesite="lax",
    )

    if result.is_new:
        # H13: off the request path — runs after the response is sent.
        background_tasks.add_task(
            _send_welcome_email_bg,
            email,
            name or email.split("@")[0],
            domain,
        )

    return AuthResponse(
        customer_id=result.customer_id,
        email=result.email,
        is_new=result.is_new,
        smtp_username=result.smtp_username,
    )


@router.post("/logout", status_code=204)
async def auth_logout(response: Response):
    """Clear the session cookie. Idempotent."""
    response.delete_cookie("session", path="/")
    return Response(status_code=204)
