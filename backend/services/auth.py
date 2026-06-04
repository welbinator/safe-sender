"""Authentication service — Google ID-token login + customer upsert.

Owns:
  - upsert keyed on google_sub (returning vs new)
  - domain-conflict detection (409 — same domain, different Google account)
  - SMTP credential minting for brand-new customers (bcrypt-hashed)

Does NOT own:
  - HTTP cookie semantics (router writes the cookie)
  - Welcome email send (router schedules it via BackgroundTasks)
  - Google ID-token verification (router calls auth_utils + handles test bypass)
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from typing import Optional

import bcrypt

from repositories import CustomerRepository

from .errors import ConflictError


@dataclass
class LoginResult:
    customer_id: str
    email: str
    is_new: bool
    # Only populated on first login — caller may surface the SMTP username so
    # the user knows where to point their gateway; the raw password is held by
    # the router only long enough to schedule a "rotate now" UX.
    smtp_username: Optional[str] = None


class AuthService:
    """Stateless on its own — holds the per-request CustomerRepository."""

    __slots__ = ("customers",)

    def __init__(self, customers: CustomerRepository) -> None:
        self.customers = customers

    @staticmethod
    def _generate_smtp_credentials() -> tuple[str, str, str]:
        """Return (smtp_username, raw_password, password_hash). One-shot — the
        plaintext is discarded after this method returns.

        bcrypt.hashpw is CPU-bound (~250-500ms at default rounds). Callers
        inside async request handlers MUST invoke this via asyncio.to_thread
        to avoid stalling the event loop (audit F-02)."""
        smtp_username = "ss_" + secrets.token_hex(8)
        raw_password = secrets.token_urlsafe(16)
        password_hash = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
        return smtp_username, raw_password, password_hash

    async def login_with_google_claims(
        self,
        *,
        google_sub: str,
        email: str,
        domain: str,
        company_name: str,
    ) -> LoginResult:
        """Upsert keyed on google_sub. Returns LoginResult.

        Raises ConflictError when the domain is already registered under a
        different Google account — that maps to HTTP 409 at the router edge.
        """
        existing = await self.customers.get_by_google_sub(google_sub)
        if existing:
            return LoginResult(
                customer_id=str(existing["id"]),
                email=email,
                is_new=False,
            )

        # New customer path — guard against domain hijack.
        if await self.customers.get_by_domain(domain):
            raise ConflictError(
                "This domain is already registered. "
                "Contact support if you believe this is an error."
            )

        smtp_username, _raw, smtp_password_hash = await asyncio.to_thread(
            self._generate_smtp_credentials
        )
        row = await self.customers.create(
            domain=domain,
            name=company_name,
            email=email,
            google_sub=google_sub,
            smtp_username=smtp_username,
            smtp_password_hash=smtp_password_hash,
        )
        return LoginResult(
            customer_id=str(row["id"]),
            email=email,
            is_new=True,
            smtp_username=smtp_username,
        )

    async def login_with_microsoft_claims(
        self,
        *,
        microsoft_sub: str,
        email: str,
        company_name: str,
    ) -> LoginResult:
        """Upsert keyed on microsoft_sub."""
        existing = await self.customers.get_by_microsoft_sub(microsoft_sub)
        if existing:
            return LoginResult(
                customer_id=str(existing["id"]),
                email=email,
                is_new=False,
            )

        existing_by_email = await self.customers.get_by_email(email)
        if existing_by_email:
            raise ConflictError(
                "This email is already registered with Google sign-in. "
                "Please sign in with Google or contact support."
            )

        smtp_username, _raw, smtp_password_hash = await asyncio.to_thread(
            self._generate_smtp_credentials
        )
        domain = email.split("@")[-1].lower()
        row = await self.customers.create(
            domain=domain,
            name=company_name,
            email=email,
            microsoft_sub=microsoft_sub,
            smtp_username=smtp_username,
            smtp_password_hash=smtp_password_hash,
            auth_provider="microsoft",
        )
        return LoginResult(
            customer_id=str(row["id"]),
            email=email,
            is_new=True,
            smtp_username=smtp_username,
        )
