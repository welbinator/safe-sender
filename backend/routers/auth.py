"""
POST /auth/google     — DEPRECATED: GIS popup ID-token exchange. Kept one
                        release as a deprecation cushion; emit a warning
                        on use so we notice if anything still calls it.
GET  /auth/google/start    — F-57: kick off server-side OAuth redirect flow.
GET  /auth/google/callback — F-57: handle Google's authorization-code redirect.
POST /auth/logout          — clears the session cookie.

F-57 design (server-side redirect flow):
  - Frontend is a plain <a href="/api/auth/google/start">. No 3rd-party JS,
    no popup, no GIS <script> tag, no inline handlers — drops every
    accounts.google.com allowance from CSP.
  - /start mints state+PKCE, stuffs them in an HMAC-signed HttpOnly cookie
    (oauth_state, 10-min TTL), and 302s to Google.
  - /callback verifies the state cookie binds the inbound state param,
    exchanges code+verifier for tokens at oauth2.googleapis.com/token
    using GOOGLE_CLIENT_SECRET, then runs Google's id_token through the
    existing verify_google_id_token() pipeline so all WORKSPACE_ONLY /
    hd-claim hardening still applies.
  - On success: same cookie semantics as the legacy POST endpoint
    (session + csrf_token), then 302 back to the SPA (/ or /?new=1 to
    trigger SMTP onboarding modal).
  - On any failure: 302 to /login?error=<code> so the SPA can show a
    readable message instead of a stack trace.

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
import logging
import os
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from security import (
    GOOGLE_AUTH_URL,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_TOKEN_URL,
    STATE_TTL_SECONDS,
    create_jwt,
    new_state,
    pkce_challenge,
    seal_state,
    unseal_state,
    verify_google_id_token,
)
from deps import get_auth_service, issue_csrf_token, rate_limit_auth_ip
from services import ConflictError, ServiceError
from services.auth import AuthService
from services.email_dispatch import send_welcome_email

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/auth", tags=["auth"])


# Public origin the SPA + Google are configured against. Used both as the
# redirect_uri sent to Google (must match the GCP-registered URI exactly)
# and for the post-login 302 back to the SPA.
PUBLIC_ORIGIN = os.environ.get("PUBLIC_ORIGIN", "https://app.sendersafety.com")
GOOGLE_REDIRECT_URI = f"{PUBLIC_ORIGIN}/api/auth/google/callback"

MICROSOFT_REDIRECT_URI = f"{PUBLIC_ORIGIN}/api/auth/microsoft/callback"
MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"


def _cookie_secure() -> bool:
    return os.environ.get("COOKIE_INSECURE") != "1"


def _set_session_cookies(response: Response, token: str) -> None:
    """Set the session JWT + paired CSRF cookies. Used by both the legacy
    POST endpoint and the new redirect callback so cookie semantics stay
    identical."""
    secure = _cookie_secure()
    # C13: HttpOnly session cookie. JS can't read it, so XSS can't steal the
    # JWT. SameSite=Lax + Secure prevents CSRF on the dominant vectors.
    response.set_cookie(
        key="session",
        value=token,
        max_age=60 * 60 * 24 * 7,
        path="/",
        httponly=True,
        secure=secure,
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
        secure=secure,
        samesite="lax",
    )


# ---------------------------------------------------------------------------
# Request / response shapes (legacy POST endpoint)
# ---------------------------------------------------------------------------
class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., max_length=4096)
    company_name: Optional[str] = Field(default=None, max_length=200)

    # F-37: previously accepted-and-ignored `domain`. We now hard-reject any
    # client that sends it so callers don't silently assume the server honors
    # it. Domain is *always* derived from Google's signed `hd` claim.
    model_config = {"extra": "forbid"}


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
# Shared login pipeline — given verified Google claims, upsert the customer,
# mint the JWT, set cookies, queue welcome email. Used by both the legacy
# POST /google endpoint and the new GET /google/callback redirect endpoint.
# ---------------------------------------------------------------------------
async def _complete_login(
    claims: dict,
    company_name: Optional[str],
    auth: AuthService,
    response: Response,
    background_tasks: BackgroundTasks,
):
    google_sub = claims["sub"]
    email = claims["email"]
    name = claims.get("name", "")
    # H12: trust Google's verified `hd` claim — never body.domain. Falls back
    # to email-derived domain only when WORKSPACE_ONLY is off (test/dev only).
    domain = (claims.get("hd") or email.split("@")[-1]).lower()
    company = company_name or name

    try:
        result = await auth.login_with_google_claims(
            google_sub=google_sub,
            email=email,
            domain=domain,
            company_name=company,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    token = create_jwt(result.customer_id, result.email)
    _set_session_cookies(response, token)

    if result.is_new:
        # H13: off the request path — runs after the response is sent.
        background_tasks.add_task(
            send_welcome_email,
            email,
            name or email.split("@")[0],
            domain,
        )

    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/google", response_model=AuthResponse, dependencies=[Depends(rate_limit_auth_ip)])
async def auth_google(
    body: GoogleAuthRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
):
    """DEPRECATED (F-57): GIS popup ID-token exchange. Use GET /auth/google/start.

    Kept for one release so any cached SPA bundle out there keeps working.
    Logs a warning on every call so we notice if anything stops upgrading."""
    logger.warning(
        "deprecated_auth_endpoint",
        extra={"endpoint": "POST /auth/google", "successor": "GET /auth/google/start"},
    )
    # Test-mode bypass: ALLOW_TEST_TOKENS=1 lets tests pass fake claims as
    # JSON-encoded id_token prefixed with "test:". Never enable in prod.
    if os.environ.get("ALLOW_TEST_TOKENS") == "1" and body.id_token.startswith("test:"):
        claims = json.loads(body.id_token[5:])
    else:
        claims = await verify_google_id_token(body.id_token)

    result = await _complete_login(claims, body.company_name, auth, response, background_tasks)

    return AuthResponse(
        customer_id=result.customer_id,
        email=result.email,
        is_new=result.is_new,
        smtp_username=result.smtp_username,
    )


@router.get("/google/start", dependencies=[Depends(rate_limit_auth_ip)])
async def auth_google_start(request: Request, return_to: str = "/"):
    """Begin server-side OAuth redirect flow (F-57).

    Mints state+PKCE, stores them in an HttpOnly cookie, 302s to Google.
    The dashboard renders this as a plain <a href> — no JS, no popup."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        # Fail loud in prod; surfacing as a redirect would silently hide
        # a misconfiguration that breaks every signup attempt.
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured (GOOGLE_CLIENT_ID/SECRET missing).",
        )

    # Reject obviously bogus return_to up front rather than after a Google
    # round-trip. Must be a same-origin path; never a full URL.
    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/"

    state = new_state(return_to=return_to)
    challenge = pkce_challenge(state.verifier)

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "state": state.state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "online",
        "prompt": "select_account",
    }

    redirect = RedirectResponse(
        url=f"{GOOGLE_AUTH_URL}?{urlencode(params)}",
        status_code=302,
    )
    redirect.set_cookie(
        key="oauth_state",
        value=seal_state(state),
        max_age=STATE_TTL_SECONDS,
        path="/api/auth/google/callback",  # nginx strips /api prefix
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
    )
    return redirect


@router.get("/google/callback")
async def auth_google_callback(
    request: Request,
    background_tasks: BackgroundTasks,
    auth: AuthService = Depends(get_auth_service),
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    """Handle Google's authorization-code redirect (F-57).

    Verifies state cookie binds the inbound state param, exchanges code for
    tokens (with PKCE), runs the returned id_token through our standard
    verifier (so WORKSPACE_ONLY + hd-claim checks still apply), then sets
    session cookies and 302s back to the SPA."""

    def _error_redirect(reason: str) -> RedirectResponse:
        # Always burn the state cookie on the way out — even on error — so a
        # half-completed attempt can't be retried with the same state.
        r = RedirectResponse(url=f"{PUBLIC_ORIGIN}/login?error={reason}", status_code=302)
        r.delete_cookie("oauth_state", path="/api/auth/google/callback")
        return r

    if error:
        # User clicked "cancel" or Google rejected (access_denied, etc.)
        return _error_redirect(error)
    if not code or not state:
        return _error_redirect("missing_params")

    sealed = request.cookies.get("oauth_state")
    if not sealed:
        return _error_redirect("state_missing")

    unsealed = unseal_state(sealed)
    if unsealed is None:
        return _error_redirect("state_invalid")

    if not hmac_safe_eq(state, unsealed.state):
        return _error_redirect("state_mismatch")

    # Exchange code for tokens. PKCE verifier proves we're the same client
    # that initiated /start. client_secret is the second leg of confidential-
    # client authentication.
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            tok_resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                    "code_verifier": unsealed.verifier,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        logger.error("google_token_exchange_network_error", extra={"err": str(exc)})
        return _error_redirect("token_exchange_failed")

    if tok_resp.status_code != 200:
        # M-4: don't dump the raw response body — Google sometimes echoes
        # request fields (including the auth code) into error responses. Parse
        # JSON and log only the documented OAuth error fields.
        safe_err = {}
        try:
            j = tok_resp.json()
            if isinstance(j, dict):
                for k in ("error", "error_description", "error_uri"):
                    if k in j:
                        safe_err[k] = str(j[k])[:200]
        except Exception:
            safe_err["parse_error"] = "non-json response"
        logger.warning(
            "google_token_exchange_rejected",
            extra={"status": tok_resp.status_code, "err": safe_err},
        )
        return _error_redirect("token_exchange_failed")

    tok = tok_resp.json()
    id_token = tok.get("id_token")
    if not id_token:
        return _error_redirect("no_id_token")

    try:
        claims = await verify_google_id_token(id_token)
    except HTTPException as exc:
        # Most likely WORKSPACE_ONLY rejection — surface as a friendly code.
        # detail is something like "Sender Safety requires a Google Workspace
        # account ...". 401 → bad_token; 403 → not_workspace.
        reason = "not_workspace" if exc.status_code == 403 else "bad_token"
        return _error_redirect(reason)

    # Run the shared login pipeline. We create a synthetic Response, copy
    # the cookies it accumulates onto our RedirectResponse, then 302 to the
    # SPA. (RedirectResponse + set_cookie works fine, but _complete_login
    # raises HTTPException on conflict/service errors — we want those as
    # redirects too, not 500s.)
    response = Response()
    try:
        result = await _complete_login(claims, None, auth, response, background_tasks)
    except HTTPException as exc:
        logger.info("oauth_login_rejected", extra={"status": exc.status_code, "detail": str(exc.detail)})
        if exc.status_code == 409:
            return _error_redirect("domain_conflict")
        return _error_redirect("login_failed")

    # New users land on /setup so they see the platform-specific setup guide
    # (Google Workspace outbound gateway or M365 smart host instructions).
    return_to = unsealed.return_to
    if result.is_new:
        return_to = "/setup"

    redirect = RedirectResponse(url=f"{PUBLIC_ORIGIN}{return_to}", status_code=302)
    # Forward cookies set by _complete_login.
    for hdr_name, hdr_val in response.raw_headers:
        if hdr_name.lower() == b"set-cookie":
            redirect.raw_headers.append((hdr_name, hdr_val))
    redirect.delete_cookie("oauth_state", path="/api/auth/google/callback")
    return redirect



async def _complete_microsoft_login(
    ms_claims: dict,
    auth: AuthService,
    response: Response,
    background_tasks: BackgroundTasks,
):
    microsoft_sub = ms_claims["sub"]
    email = ms_claims["email"]
    name = ms_claims.get("name", "")
    company = name or email.split("@")[0]

    try:
        result = await auth.login_with_microsoft_claims(
            microsoft_sub=microsoft_sub,
            email=email,
            company_name=company,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    token = create_jwt(result.customer_id, result.email)
    _set_session_cookies(response, token)

    if result.is_new:
        background_tasks.add_task(
            send_welcome_email,
            email,
            name or email.split("@")[0],
            email.split("@")[-1],
        )

    return result


@router.get("/microsoft/start", dependencies=[Depends(rate_limit_auth_ip)])
async def auth_microsoft_start(request: Request, return_to: str = "/"):
    """Begin Microsoft Entra ID OAuth redirect flow."""
    if not MICROSOFT_CLIENT_ID or not MICROSOFT_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Microsoft OAuth not configured (MICROSOFT_CLIENT_ID/SECRET missing).",
        )

    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/"

    state = new_state(return_to=return_to)

    params = {
        "client_id": MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": MICROSOFT_REDIRECT_URI,
        "state": state.state,
        "response_mode": "query",
        "prompt": "select_account",
    }

    redirect = RedirectResponse(
        url=f"{MICROSOFT_AUTH_URL}?{urlencode(params)}",
        status_code=302,
    )
    redirect.set_cookie(
        key="ms_oauth_state",
        value=seal_state(state),
        max_age=STATE_TTL_SECONDS,
        path="/api/auth/microsoft/callback",
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
    )
    return redirect


@router.get("/microsoft/callback")
async def auth_microsoft_callback(
    request: Request,
    background_tasks: BackgroundTasks,
    auth: AuthService = Depends(get_auth_service),
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    """Handle Microsoft's authorization-code redirect."""

    def _error_redirect(reason: str) -> RedirectResponse:
        r = RedirectResponse(url=f"{PUBLIC_ORIGIN}/login?error={reason}", status_code=302)
        r.delete_cookie("ms_oauth_state", path="/api/auth/microsoft/callback")
        return r

    if error:
        return _error_redirect(f"ms_{error}")
    if not code or not state:
        return _error_redirect("ms_missing_params")

    sealed = request.cookies.get("ms_oauth_state")
    if not sealed:
        return _error_redirect("ms_state_missing")

    unsealed = unseal_state(sealed)
    if unsealed is None:
        return _error_redirect("ms_state_invalid")

    if not hmac_safe_eq(state, unsealed.state):
        return _error_redirect("ms_state_mismatch")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            tok_resp = await client.post(
                MICROSOFT_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": MICROSOFT_CLIENT_ID,
                    "client_secret": MICROSOFT_CLIENT_SECRET,
                    "redirect_uri": MICROSOFT_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        logger.error("microsoft_token_exchange_network_error", extra={"err": str(exc)})
        return _error_redirect("ms_token_exchange_failed")

    if tok_resp.status_code != 200:
        safe_err = {}
        try:
            j = tok_resp.json()
            if isinstance(j, dict):
                for k in ("error", "error_description"):
                    if k in j:
                        safe_err[k] = str(j[k])[:200]
        except Exception:
            safe_err["parse_error"] = "non-json response"
        logger.warning(
            "microsoft_token_exchange_rejected",
            extra={"status": tok_resp.status_code, "err": safe_err},
        )
        return _error_redirect("ms_token_exchange_failed")

    tok = tok_resp.json()
    access_token = tok.get("access_token")
    if not access_token:
        return _error_redirect("ms_no_access_token")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            ui_resp = await client.get(
                "https://graph.microsoft.com/oidc/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.HTTPError as exc:
        logger.error("microsoft_userinfo_network_error", extra={"err": str(exc)})
        return _error_redirect("ms_userinfo_failed")

    if ui_resp.status_code != 200:
        return _error_redirect("ms_userinfo_failed")

    ui = ui_resp.json()
    email = ui.get("email") or ui.get("preferred_username", "")
    if not email or "@" not in email:
        return _error_redirect("ms_no_email")

    ms_claims = {
        "sub": ui.get("sub", ""),
        "email": email,
        "name": ui.get("name", ""),
    }

    response = Response()
    try:
        result = await _complete_microsoft_login(ms_claims, auth, response, background_tasks)
    except HTTPException as exc:
        logger.info("ms_oauth_login_rejected", extra={"status": exc.status_code, "detail": str(exc.detail)})
        if exc.status_code == 409:
            return _error_redirect("ms_account_conflict")
        return _error_redirect("ms_login_failed")

    # New users land on /setup so they see the M365 smart host setup guide.
    return_to = unsealed.return_to
    if result.is_new:
        return_to = "/setup"

    redirect = RedirectResponse(url=f"{PUBLIC_ORIGIN}{return_to}", status_code=302)
    for hdr_name, hdr_val in response.raw_headers:
        if hdr_name.lower() == b"set-cookie":
            redirect.raw_headers.append((hdr_name, hdr_val))
    redirect.delete_cookie("ms_oauth_state", path="/api/auth/microsoft/callback")
    return redirect


def hmac_safe_eq(a: str, b: str) -> bool:
    """Constant-time string compare. Local helper so we don't import hmac
    in the router just for this single call."""
    import hmac as _hmac
    return _hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


@router.post("/logout", status_code=204)
async def auth_logout(response: Response):
    """Clear the session + csrf cookies. Idempotent."""
    response.delete_cookie("session", path="/")
    response.delete_cookie("csrf_token", path="/")
    return Response(status_code=204)
