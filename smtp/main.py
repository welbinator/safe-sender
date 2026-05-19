"""
Sender Safety SMTP server — Sprint 2.

Receives email on port 587 (STARTTLS), scans against customer rules fetched
from the backend service, then either:
  - Rejects with 550 5.7.1 (policy violation or unknown domain)
  - Forwards via AWS SES and logs outcome to scan_logs

Privacy guarantee: email body/subject are NEVER written to disk or logged.
The subject is stored only as a SHA-256 hash.
"""

import asyncio
import base64
import email as email_lib
import hashlib
import logging
import os
import re
import ssl
from email import policy as email_policy

import aiohttp
import boto3
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (from environment)
# ---------------------------------------------------------------------------
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "")

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_SOURCE_ARN = os.environ.get("SES_SOURCE_ARN", "")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(address: str) -> str:
    """Return the domain part of an email address like 'user@example.com'."""
    address = address.strip("<>").strip()
    if "@" in address:
        return address.split("@", 1)[1].lower()
    return address.lower()


def _get_text_body(msg) -> str:
    """Extract plain-text body from a parsed email.Message (in-memory only)."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(charset, errors="replace")
        return ""
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        return ""


def _rule_matches(rule: dict, subject: str, body: str) -> bool:
    """Return True if the rule matches the given subject/body."""
    pattern = rule["pattern"]
    match_type = rule.get("match_type", "keyword")
    scope = rule.get("scope", "both")

    # Build the targets to check
    targets = []
    if scope == "subject":
        targets = [subject]
    elif scope == "body":
        targets = [body]
    else:  # "both"
        targets = [subject, body]

    for text in targets:
        if match_type == "keyword":
            if pattern.lower() in text.lower():
                return True
        elif match_type == "regex":
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            except re.error as exc:
                logger.warning("Invalid regex pattern '%s': %s", pattern, exc)
    return False


async def _fetch_rules(domain: str) -> dict | None:
    """
    Fetch customer + rules from backend.
    Returns dict with 'customer_id' and 'rules', or None if domain not found.
    """
    url = f"{BACKEND_URL}/internal/rules/{domain}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status == 404:
                return None
            resp.raise_for_status()
            return await resp.json()


async def _log_scan(
    customer_id: int,
    sender: str,
    recipient: str,
    subject_hash: str,
    matched_rule_id: int | None,
    outcome: str,
) -> None:
    """POST a scan log entry to the backend (fire-and-forget style, but awaited)."""
    url = f"{BACKEND_URL}/internal/scan-log"
    payload = {
        "customer_id": customer_id,
        "sender": sender,
        "recipient": recipient,
        "subject_hash": subject_hash,
        "matched_rule_id": matched_rule_id,
        "outcome": outcome,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    logger.error("scan-log POST failed %d: %s", resp.status, body)
    except Exception as exc:
        logger.error("Failed to post scan log: %s", exc)


def _forward_via_ses(raw_message: bytes, mail_from: str, rcpt_tos: list[str]) -> None:
    """Send raw email via AWS SES (synchronous boto3 call)."""
    client = boto3.client("ses", region_name=AWS_REGION)
    kwargs = {
        "Source": mail_from,
        "Destinations": rcpt_tos,
        "RawMessage": {"Data": raw_message},
    }
    if SES_SOURCE_ARN:
        kwargs["SourceArn"] = SES_SOURCE_ARN
    client.send_raw_email(**kwargs)


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class Authenticator:
    """Simple single-credential AUTH LOGIN/PLAIN authenticator."""

    def __call__(self, server, session, envelope, mechanism, auth_data):
        # auth_data is a LoginPassword namedtuple for LOGIN and PLAIN
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=True)
        username = auth_data.login.decode() if isinstance(auth_data.login, bytes) else auth_data.login
        password = auth_data.password.decode() if isinstance(auth_data.password, bytes) else auth_data.password
        if username == AUTH_USERNAME and password == AUTH_PASSWORD:
            return AuthResult(success=True)
        logger.warning("AUTH failed for user '%s'", username)
        return AuthResult(success=False, handled=True)


# ---------------------------------------------------------------------------
# Main SMTP handler
# ---------------------------------------------------------------------------

class SafeSenderHandler:
    """
    aiosmtpd DATA handler.

    Flow:
      1. Extract sender domain from MAIL FROM.
      2. Fetch customer rules from backend.
      3. Parse email in memory.
      4. Evaluate each rule.
      5. Block (550) or forward via SES.
      6. Log outcome.
    """

    async def handle_RCPT(self, server, session, envelope, address: str, rcpt_options: list) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        mail_from: str = envelope.mail_from or ""
        rcpt_tos: list[str] = envelope.rcpt_tos
        raw_content: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()

        domain = _extract_domain(mail_from)
        logger.info("Incoming email from domain=%s to=%s", domain, rcpt_tos)

        # --- 1. Look up customer + rules ---
        try:
            data = await _fetch_rules(domain)
        except Exception as exc:
            logger.error("Error fetching rules for %s: %s", domain, exc)
            return "451 4.3.0 Temporary server error"

        if data is None:
            logger.info("Unknown domain: %s — rejecting", domain)
            return "550 5.7.1 Domain not registered"

        customer_id: int = data["customer_id"]
        rules: list[dict] = data.get("rules", [])

        # --- 2. Parse email in memory ---
        msg = email_lib.message_from_bytes(raw_content, policy=email_policy.default)
        subject: str = str(msg.get("Subject", ""))
        body: str = _get_text_body(msg)
        subject_hash: str = hashlib.sha256(subject.encode()).hexdigest()

        # --- 3. Evaluate rules ---
        # Separate normal rules from exception rules
        normal_rules = [r for r in rules if not r.get("is_exception", False)]
        exception_rules = [r for r in rules if r.get("is_exception", False)]

        matched_rule = None
        for rule in normal_rules:
            if _rule_matches(rule, subject, body):
                matched_rule = rule
                break

        # Check if an exception rule overrides the match
        if matched_rule:
            for exc_rule in exception_rules:
                if _rule_matches(exc_rule, subject, body):
                    logger.info("Exception rule %d overrides match on rule %d", exc_rule["id"], matched_rule["id"])
                    matched_rule = None
                    break

        # --- 4. Block or forward ---
        recipient = rcpt_tos[0] if rcpt_tos else ""

        if matched_rule:
            logger.info(
                "Blocking email from=%s: matched rule id=%d pattern='%s'",
                mail_from, matched_rule["id"], matched_rule["pattern"],
            )
            await _log_scan(
                customer_id=customer_id,
                sender=mail_from,
                recipient=recipient,
                subject_hash=subject_hash,
                matched_rule_id=matched_rule["id"],
                outcome="blocked",
            )
            return "550 5.7.1 Message rejected: policy violation"

        # Forward via SES
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _forward_via_ses, raw_content, mail_from, rcpt_tos)
            logger.info("Forwarded email from=%s via SES", mail_from)
        except Exception as exc:
            logger.error("SES send failed: %s", exc)
            await _log_scan(
                customer_id=customer_id,
                sender=mail_from,
                recipient=recipient,
                subject_hash=subject_hash,
                matched_rule_id=None,
                outcome="blocked",
            )
            return "451 4.3.0 Delivery failure — please retry"

        await _log_scan(
            customer_id=customer_id,
            sender=mail_from,
            recipient=recipient,
            subject_hash=subject_hash,
            matched_rule_id=None,
            outcome="passed",
        )
        return "250 OK"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_ssl_context() -> ssl.SSLContext | None:
    """Return an SSL context if TLS cert/key paths are configured."""
    if not TLS_CERT_PATH or not TLS_KEY_PATH:
        logger.warning("TLS_CERT_PATH/TLS_KEY_PATH not set — running without TLS")
        return None
    if not os.path.exists(TLS_CERT_PATH) or not os.path.exists(TLS_KEY_PATH):
        logger.warning("TLS cert/key files not found — running without TLS")
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)
    return ctx


if __name__ == "__main__":
    handler = SafeSenderHandler()
    authenticator = Authenticator()

    ssl_context = build_ssl_context()

    controller_kwargs = dict(
        hostname="0.0.0.0",
        port=587,
        authenticator=authenticator,
        auth_required=True,
        auth_require_tls=False,  # Allow AUTH even without TLS (dev mode)
    )
    if ssl_context:
        controller_kwargs["ssl_context"] = ssl_context
        logger.info("TLS enabled with cert: %s", TLS_CERT_PATH)

    controller = Controller(handler, **controller_kwargs)
    controller.start()
    logger.info("Safe Sender SMTP server listening on port 587")

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()
        logger.info("SMTP server stopped")
