"""Customer-facing business logic.

Owned operations:
  * Profile read / update
  * DNS-TXT domain verification (init + check)
  * SMTP credential issue / rotation
  * SMTP gateway self-test (send a test email, poll scan_logs)

The router is responsible only for HTTP shape — Pydantic parsing in,
response serialization out, exception translation at the edge.
"""
from __future__ import annotations

import asyncio
import secrets
import smtplib
import time
from email.mime.text import MIMEText
from typing import Any, Optional

import bcrypt
import dns.resolver

from repositories.customers import CustomerRepository
from repositories.scan_logs import ScanLogRepository

from .errors import DomainVerificationNotInitialized, NotFoundError


_VERIFICATION_TXT_PREFIX = "sendersafety-verify="
_VERIFICATION_TXT_LABEL = "_sendersafety"

# Smoke-test config — these mirror the historical router constants.
_SMTP_GATEWAY_HOST = "smtp.sendersafety.com"
_SMTP_GATEWAY_PORT = 587
_TEST_RECIPIENT = "delivery-test@sendersafety.com"
_TEST_SUBJECT = "Sender Safety connection test"
_TEST_POLL_DEADLINE_SECS = 10


class DomainVerificationResult:
    """Tiny value object so the router can branch on verified/message without
    leaking the underlying DNS lookup machinery."""

    __slots__ = ("verified", "message")

    def __init__(self, verified: bool, message: str):
        self.verified = verified
        self.message = message


class TestConnectionResult:
    __slots__ = ("success", "message")

    def __init__(self, success: bool, message: str):
        self.success = success
        self.message = message


class CustomerService:
    """Business operations on a single Customer aggregate."""

    def __init__(
        self,
        customers: CustomerRepository,
        scan_logs: Optional[ScanLogRepository] = None,
    ):
        self.customers = customers
        # scan_logs is only needed for test_connection; injected lazily so the
        # majority of customer endpoints don't pay the wiring cost.
        self.scan_logs = scan_logs

    # ------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------

    async def update_name(
        self, customer_id: Any, name: Optional[str]
    ) -> dict[str, Any]:
        return await self.customers.update_name(customer_id, name)

    # ------------------------------------------------------------------
    # Domain verification
    # ------------------------------------------------------------------

    async def init_domain_verification(
        self, customer: dict[str, Any]
    ) -> dict[str, str]:
        """Generate (or return-existing) a TXT verification token.

        Returns the values the customer needs to add to DNS. If the domain is
        already verified we short-circuit with a sentinel — preserves the
        existing API contract.
        """
        if customer.get("domain_verified"):
            return {
                "token": "already-verified",
                "txt_name": _VERIFICATION_TXT_LABEL,
                "txt_value": "already-verified",
            }

        token = secrets.token_hex(20)
        await self.customers.set_verification_token(customer["id"], token)

        return {
            "token": token,
            "txt_name": _VERIFICATION_TXT_LABEL,
            "txt_value": f"{_VERIFICATION_TXT_PREFIX}{token}",
        }

    async def check_domain_verification(
        self, customer: dict[str, Any]
    ) -> DomainVerificationResult:
        if customer.get("domain_verified"):
            return DomainVerificationResult(
                True, "Domain already verified."
            )

        token = await self.customers.get_verification_token(customer["id"])
        if not token:
            raise DomainVerificationNotInitialized()

        domain = customer["domain"]
        expected = f"{_VERIFICATION_TXT_PREFIX}{token}"

        if await self._dns_txt_contains(
            f"{_VERIFICATION_TXT_LABEL}.{domain}", expected
        ):
            await self.customers.mark_domain_verified(customer["id"])
            return DomainVerificationResult(
                True, "Domain verified successfully!"
            )

        return DomainVerificationResult(
            False,
            (
                f"TXT record not found yet. Make sure you added:\n"
                f"  Name: {_VERIFICATION_TXT_LABEL}.{domain}\n"
                f"  Value: {expected}\n"
                f"DNS changes can take up to 48 hours to propagate."
            ),
        )

    @staticmethod
    async def _dns_txt_contains(name: str, expected: str) -> bool:
        """Resolve `name` (TXT) and return True iff `expected` is present.

        dns.resolver is blocking, so the lookup runs in a worker thread (H13).
        Any exception (NXDOMAIN, timeout, no answer) is treated as "not yet".
        """
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, name, "TXT")
        except Exception:
            return False
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode() == expected:
                    return True
        return False

    # ------------------------------------------------------------------
    # SMTP credentials
    # ------------------------------------------------------------------

    async def get_smtp_credentials(
        self, customer_id: Any
    ) -> dict[str, Any]:
        """Return host/port/username for an existing customer.

        Plaintext password is never returned post-signup — see `rotate_smtp_password`.
        """
        username = await self.customers.get_smtp_username(customer_id)
        if not username:
            raise NotFoundError("SMTP credentials not yet generated")
        return {
            "smtp_host": _SMTP_GATEWAY_HOST,
            "smtp_port": _SMTP_GATEWAY_PORT,
            "smtp_username": username,
        }

    async def rotate_smtp_password(
        self, customer_id: Any
    ) -> dict[str, Any]:
        """Generate a fresh password, persist its bcrypt hash, return plaintext once.

        bcrypt.hashpw is CPU-bound (~250-500ms at default rounds). We offload
        to a worker thread via asyncio.to_thread so concurrent rotations don't
        stall the event loop (audit F-02).
        """
        new_password = secrets.token_urlsafe(16)
        new_hash = (
            await asyncio.to_thread(
                bcrypt.hashpw, new_password.encode(), bcrypt.gensalt()
            )
        ).decode()

        row = await self.customers.update_smtp_password_hash(
            customer_id, new_hash
        )
        if not row:
            raise NotFoundError("Customer not found")

        return {
            "smtp_host": _SMTP_GATEWAY_HOST,
            "smtp_port": _SMTP_GATEWAY_PORT,
            "smtp_username": row["smtp_username"],
            "smtp_password": new_password,
        }

    # ------------------------------------------------------------------
    # Self-test
    # ------------------------------------------------------------------

    async def test_smtp_connection(
        self,
        customer: dict[str, Any],
        *,
        smtp_host: str = _SMTP_GATEWAY_HOST,
        smtp_port: int = _SMTP_GATEWAY_PORT,
        auth_username: str = "",
        auth_password: str = "",
    ) -> TestConnectionResult:
        """Send a test email through the gateway and poll for it in scan_logs.

        Note: requires `self.scan_logs` to be set (raises AttributeError
        otherwise — caller should always inject when using this endpoint).
        """
        if self.scan_logs is None:  # defensive — would be a wiring bug
            raise RuntimeError(
                "CustomerService.test_smtp_connection requires a ScanLogRepository"
            )

        domain = customer["domain"]
        customer_id = customer["id"]
        test_sender = f"sendersafety-test@{domain}"

        before_count = await self.scan_logs.count_for_customer(customer_id)

        try:
            await asyncio.to_thread(
                self._send_test_email_blocking,
                smtp_host,
                smtp_port,
                auth_username,
                auth_password,
                test_sender,
            )
        except Exception as e:
            return TestConnectionResult(
                False, f"Could not connect to SMTP gateway: {e}"
            )

        # Poll for the scan log to appear (event loop friendly — 1s sleeps).
        deadline = time.time() + _TEST_POLL_DEADLINE_SECS
        while time.time() < deadline:
            after_count = await self.scan_logs.count_for_customer(customer_id)
            if after_count > before_count:
                return TestConnectionResult(
                    True,
                    "✅ Success! Your email passed through the Sender Safety "
                    "gateway and appeared in your scan logs.",
                )
            await asyncio.sleep(1)

        return TestConnectionResult(
            False,
            (
                "The test email was sent but didn't appear in scan logs within "
                f"{_TEST_POLL_DEADLINE_SECS} seconds. Your SMTP gateway may "
                "not be configured yet, or DNS propagation is still in "
                "progress."
            ),
        )

    @staticmethod
    def _send_test_email_blocking(
        smtp_host: str,
        smtp_port: int,
        auth_username: str,
        auth_password: str,
        sender: str,
    ) -> None:
        msg = MIMEText(
            "This is an automated connection test from Sender Safety."
        )
        msg["Subject"] = _TEST_SUBJECT
        msg["From"] = sender
        msg["To"] = _TEST_RECIPIENT

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if auth_username and auth_password:
                smtp.login(auth_username, auth_password)
            smtp.sendmail(sender, [_TEST_RECIPIENT], msg.as_string())
