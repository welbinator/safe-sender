"""
POST /auth/google — exchange Google ID token for session JWT.

Flow:
1. Client obtains a Google ID token (via Google Sign-In JS lib).
2. Client POSTs that token here.
3. We verify it with Google's tokeninfo endpoint.
4. We upsert a customer row keyed on google_sub.
5. We return our own JWT session token.
"""
import os
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth_utils import create_jwt, verify_google_id_token
from deps import get_pool

router = APIRouter(prefix="/auth", tags=["auth"])


class GoogleAuthRequest(BaseModel):
    id_token: str
    # Optional: customer's Google Workspace domain (e.g. "acme.com")
    # Sent by the dashboard after user selects their domain on first login.
    domain: Optional[str] = None
    company_name: Optional[str] = None


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    customer_id: str
    email: str
    is_new: bool


@router.post("/google", response_model=AuthResponse)
async def auth_google(
    body: GoogleAuthRequest,
    pool: asyncpg.Pool = Depends(get_pool),
):
    """
    Verify Google ID token, upsert customer, return session JWT.
    """
    # Test-mode bypass: ALLOW_TEST_TOKENS=1 lets tests pass fake claims as
    # JSON-encoded id_token prefixed with "test:".  Never enable in prod.
    if os.environ.get("ALLOW_TEST_TOKENS") == "1" and body.id_token.startswith("test:"):
        import json as _json
        claims = _json.loads(body.id_token[5:])
    else:
        claims = await verify_google_id_token(body.id_token)

    google_sub = claims["sub"]
    email = claims["email"]
    name = claims.get("name", "")
    # Derive domain from email if not explicitly supplied
    domain = body.domain or email.split("@")[-1]
    company_name = body.company_name or name

    async with pool.acquire() as conn:
        # Look up by google_sub first (returning customer)
        row = await conn.fetchrow(
            "SELECT id, email FROM customers WHERE google_sub = $1", google_sub
        )
        if row:
            customer_id = str(row["id"])
            is_new = False
        else:
            # Check if someone already registered this domain under a different Google account
            domain_row = await conn.fetchrow(
                "SELECT id FROM customers WHERE domain = $1", domain.lower()
            )
            if domain_row:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "This domain is already registered. "
                        "Contact support if you believe this is an error."
                    ),
                )

            # New customer — insert
            row = await conn.fetchrow(
                """
                INSERT INTO customers (domain, name, email, google_sub, plan)
                VALUES ($1, $2, $3, $4, 'basic')
                RETURNING id, email
                """,
                domain.lower(),
                company_name,
                email,
                google_sub,
            )
            customer_id = str(row["id"])
            is_new = True

    token = create_jwt(customer_id, email)
    return AuthResponse(
        access_token=token,
        customer_id=customer_id,
        email=email,
        is_new=is_new,
    )
