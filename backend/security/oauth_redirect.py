"""Server-side OAuth 2.0 redirect flow helpers (F-57).

Replaces Google Identity Services (GIS) popup with a classic redirect flow:
  1. GET /auth/google/start  → mint state + PKCE verifier, set short-lived
     HttpOnly cookie, 302 to Google's authorization endpoint.
  2. Google → GET /auth/google/callback?code=...&state=...
  3. Callback verifies state cookie HMAC-binds the request, exchanges code
     for tokens via the token endpoint (with PKCE), and continues into the
     existing login flow (id_token claims → AuthService).

Why server-side flow:
  - No 3rd-party JS at all (drops GIS <script> tag + CSP allowances for
    accounts.google.com). Eliminates the need for any 'unsafe-inline'
    that was previously rumored to be needed for GIS button rendering.
  - State + PKCE protect against CSRF / authorization-code interception
    without trusting any browser-side secret.
  - The client_secret never leaves the backend.

The state cookie is HttpOnly, Secure, SameSite=Lax, 10-minute TTL. It carries
a JSON blob (state, verifier, return-to URL) signed with HMAC-SHA256 using
JWT_SECRET (already required to be ≥32 bytes). We use HMAC rather than the
JWT machinery to keep this self-contained and free of clock-skew handling
for such a short window — the cookie's max-age IS the expiry.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from security.jwt_tokens import JWT_SECRET  # already validated ≥32 bytes

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# 10 minutes — enough for the user to click through Google's consent screen
# but short enough that a leaked state cookie has minimal value.
STATE_TTL_SECONDS = 600


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True)
class OAuthState:
    state: str        # opaque nonce echoed by Google
    verifier: str     # PKCE code_verifier
    return_to: str    # post-login redirect (defaults to "/")
    issued_at: int    # unix seconds


def new_state(return_to: str = "/") -> OAuthState:
    """Mint a fresh state + PKCE verifier."""
    return OAuthState(
        state=_b64url(secrets.token_bytes(24)),
        verifier=_b64url(secrets.token_bytes(48)),  # 64 chars after b64url
        return_to=return_to,
        issued_at=int(time.time()),
    )


def pkce_challenge(verifier: str) -> str:
    """S256 code challenge from a verifier."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def seal_state(s: OAuthState) -> str:
    """Serialize + HMAC-sign an OAuthState for the oauth_state cookie."""
    payload = json.dumps(
        {"s": s.state, "v": s.verifier, "r": s.return_to, "t": s.issued_at},
        separators=(",", ":"),
    ).encode("utf-8")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
    return _b64url(payload) + "." + _b64url(sig)


def unseal_state(token: str) -> Optional[OAuthState]:
    """Verify HMAC, TTL, and structure. Returns None on any failure."""
    try:
        body_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(body_b64)
        sig = _b64url_decode(sig_b64)
    except (ValueError, AttributeError, base64.binascii.Error):
        return None
    expected = hmac.new(JWT_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        d = json.loads(payload.decode("utf-8"))
        state = OAuthState(
            state=str(d["s"]),
            verifier=str(d["v"]),
            return_to=str(d["r"]),
            issued_at=int(d["t"]),
        )
    except (KeyError, ValueError, TypeError):
        return None
    if int(time.time()) - state.issued_at > STATE_TTL_SECONDS:
        return None
    # return_to must be a same-origin path — never a full URL — to prevent
    # open-redirect via a tampered (but signed) cookie. Belt + suspenders:
    # the HMAC already prevents tampering by an attacker without JWT_SECRET,
    # but the validator runs anyway so a buggy /start call can't poison.
    if not state.return_to.startswith("/") or state.return_to.startswith("//"):
        return None
    return state
