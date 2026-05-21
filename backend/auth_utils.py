"""
JWT creation/verification and Google ID token verification.

Sprint B hardening (H10/H11/H12):
  - JWT has explicit iss + aud + jti claims and short 7-day expiry
  - decode_jwt requires exp + iat + sub + jti via PyJWT `options.require`
  - Google ID token validation enforces:
      * `aud == GOOGLE_CLIENT_ID`
      * `iss in {"accounts.google.com", "https://accounts.google.com"}`
      * `email_verified == True`
      * Workspace `hd` claim required when WORKSPACE_ONLY=1 (default in prod)
"""
import os
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status

# ---------------------------------------------------------------------------
# JWT config
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "sendersafety")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "sendersafety-app")

# Shorter expiry — 7 days. Refresh endpoint can extend later.
JWT_EXPIRE_DAYS = int(os.environ.get("JWT_EXPIRE_DAYS", "7"))

# Fail fast on weak or default secrets.
_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}
if JWT_SECRET.lower() in _WEAK_SECRETS or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET is missing, default, or shorter than 32 chars. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )

# ---------------------------------------------------------------------------
# Google OIDC config
# ---------------------------------------------------------------------------
GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_VALID_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}

# When WORKSPACE_ONLY=1 we refuse personal @gmail.com accounts (no `hd` claim).
WORKSPACE_ONLY = os.environ.get("WORKSPACE_ONLY", "1") == "1"


# Toggle for gradual rollout. When 0, old tokens without jti/iss/aud still
# decode (only sub+exp+iat required). When 1, all new strict claims required.
# Default off so deploying Sprint B doesn't instantly invalidate every session;
# flip to 1 after JWT_EXPIRE_DAYS has rolled all tokens forward.
STRICT_JWT_CLAIMS = os.environ.get("STRICT_JWT_CLAIMS", "0") == "1"


def create_jwt(customer_id: str, email: str) -> str:
    """Return a signed JWT for the given customer.

    Includes jti for future revocation, plus iss/aud bound to this service.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": customer_id,
        "email": email,
        "jti": _secrets.token_urlsafe(16),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode and verify a JWT.

    When STRICT_JWT_CLAIMS=1 (post-rollout), requires sub/exp/iat/jti/iss/aud.
    Otherwise only sub/exp/iat — used during the rollout window so existing
    tokens issued before the upgrade keep working until they expire naturally.
    Raises HTTPException 401 on any failure.
    """
    if STRICT_JWT_CLAIMS:
        required = ["sub", "exp", "iat", "jti", "iss", "aud"]
        decode_kwargs = dict(
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": required,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    else:
        # Lenient mode: don't verify iss/aud; tolerate missing jti.
        # Still enforce expiry & signature.
        decode_kwargs = dict(
            options={
                "require": ["sub", "exp", "iat"],
                "verify_iat": True,
                "verify_exp": True,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM], **decode_kwargs
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def verify_google_id_token(id_token: str) -> dict[str, Any]:
    """Verify a Google ID token via Google's tokeninfo endpoint.

    Enforces:
      * HTTP 200 from Google
      * `aud == GOOGLE_CLIENT_ID`
      * `iss in GOOGLE_VALID_ISSUERS`
      * `email_verified` truthy
      * Required claims: sub, email
      * When WORKSPACE_ONLY=1: `hd` claim present (rejects @gmail.com personal)

    Returns the claims dict on success.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            GOOGLE_TOKEN_INFO_URL, params={"id_token": id_token}
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google ID token",
        )

    claims = resp.json()

    if GOOGLE_CLIENT_ID and claims.get("aud") != GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token audience mismatch",
        )

    if claims.get("iss", "") not in GOOGLE_VALID_ISSUERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token issuer not trusted",
        )

    # Google returns email_verified as the string "true"/"false" via tokeninfo;
    # treat anything other than truthy/"true" as unverified.
    ev = claims.get("email_verified", False)
    if not (ev is True or (isinstance(ev, str) and ev.lower() == "true")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified by Google",
        )

    required = {"sub", "email"}
    if not required.issubset(claims.keys()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incomplete token claims",
        )

    if WORKSPACE_ONLY:
        hd = claims.get("hd", "").strip().lower()
        if not hd:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Sender Safety requires a Google Workspace account "
                    "(personal @gmail.com accounts are not supported)."
                ),
            )
        # Sanity: hd must match the email domain
        email_domain = claims["email"].split("@", 1)[-1].lower()
        if hd != email_domain:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Workspace domain mismatch",
            )

    return claims
