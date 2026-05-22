"""
POST /auth/google — exchange Google ID token for session JWT.
POST /auth/logout — clears the session cookie.

Sprint C1 t7: the upsert + domain-conflict + SMTP credential minting moved to
AuthService; the welcome-email body (HTML/plaintext) lives in services.email_templates
and is dispatched via BackgroundTasks. Sprint C3 F-27: SES transport now lives
in services.email_dispatch — this router owns only:
  - Google ID-token verification (incl. ALLOW_TEST_TOKENS bypass)
  - cookie semantics (HttpOnly, Secure, SameSite=Lax)
  - background-task scheduling for the welcome email
"""
from __future__ import annotations

import json
import os
from typing import Optional

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from security import create_jwt, verify_google_id_token
from deps import get_auth_service, issue_csrf_token
from services import AuthService, ConflictError, ServiceError
from services.email_dispatch import send_welcome_email

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/auth", tags=["auth"])


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
        claims = json.loads(body.id_token[5:])
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

    # C3 F-11: paired non-HttpOnly CSRF token. JS-readable BY DESIGN — the
    # dashboard reads this cookie and mirrors it into the X-CSRF-Token header
    # on every mutation. Cross-origin attackers can't read it (SOP) and can't
    # guess 256 bits, so they can't satisfy the backend's compare_digest check.
    response.set_cookie(
        key="csrf_token",
        value=issue_csrf_token(),
        max_age=60 * 60 * 24 * 7,
        path="/",
        httponly=False,
        secure=os.environ.get("COOKIE_INSECURE") != "1",
        samesite="lax",
    )

    if result.is_new:
        # H13: off the request path — runs after the response is sent.
        background_tasks.add_task(
            send_welcome_email,
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
    """Clear the session + csrf cookies. Idempotent."""
    response.delete_cookie("session", path="/")
    response.delete_cookie("csrf_token", path="/")
    return Response(status_code=204)
