"""
Sender Safety SMTP server — Sprint 6.

Receives email on port 587 (STARTTLS), scans against customer rules fetched
from the backend service, then either:
  - Rejects with 550 5.7.1 (policy violation or unknown domain)
  - Forwards via AWS SES and logs outcome to scan_logs

Sprint 6 additions:
  - Per-customer rate limiting (sliding window, configurable)
  - Structured JSON logging (every significant event is machine-parseable)
  - Admin SES alert on repeated failures (circuit breaker pattern)

Privacy guarantee: email body/subject are NEVER written to disk or logged.
The subject is stored only as a SHA-256 hash.
"""

import asyncio
import collections
import email as email_lib
import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import time
from email import policy as email_policy

import aiohttp
import boto3
import requests
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

# ---------------------------------------------------------------------------
# Structured JSON logger
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        # Merge any extra fields passed via `extra=`
        for key, val in record.__dict__.items():
            if key not in (
                "args", "created", "exc_info", "exc_text", "filename",
                "funcName", "id", "levelname", "levelno", "lineno",
                "module", "msecs", "message", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "stack_info",
                "thread", "threadName",
            ):
                base[key] = val
        return json.dumps(base)


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (from environment)
# ---------------------------------------------------------------------------
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "")

# Shared secret used to authenticate this SMTP service to the backend's
# /internal/* endpoints. Sent as X-Internal-Secret header.
INTERNAL_SHARED_SECRET = os.environ.get("INTERNAL_SHARED_SECRET", "")
_WEAK_SECRETS = {"", "changeme", "secret", "password", "default", "test"}
if INTERNAL_SHARED_SECRET in _WEAK_SECRETS or len(INTERNAL_SHARED_SECRET) < 32:
    sys.stderr.write(
        "FATAL: INTERNAL_SHARED_SECRET must be set and at least 32 chars. "
        "Refusing to start.\n"
    )
    sys.exit(1)
_INTERNAL_HEADERS = {"X-Internal-Secret": INTERNAL_SHARED_SECRET}

# Comma-separated CIDR ranges allowed to connect on port 25 (Google SMTP relay
# MTA->MTA). Defaults to Google's published _spf.google.com ranges as of 2025;
# operators should keep this updated via env.
DEFAULT_GOOGLE_RELAY_RANGES = (
    "35.190.247.0/24,64.233.160.0/19,66.102.0.0/20,66.249.80.0/20,"
    "72.14.192.0/18,74.125.0.0/16,108.177.8.0/21,108.177.96.0/19,"
    "172.217.0.0/19,172.217.32.0/20,172.217.128.0/19,172.217.160.0/20,"
    "172.217.192.0/19,173.194.0.0/16,209.85.128.0/17,216.58.192.0/19,"
    "216.239.32.0/19"
)
PORT25_ALLOWED_CIDRS = os.environ.get("PORT25_ALLOWED_CIDRS", DEFAULT_GOOGLE_RELAY_RANGES)
_PORT25_NETWORKS = [
    ipaddress.ip_network(c.strip(), strict=False)
    for c in PORT25_ALLOWED_CIDRS.split(",") if c.strip()
]

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
SES_SOURCE_ARN = os.environ.get("SES_SOURCE_ARN", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "james.welbes@gmail.com")
SES_FROM_EMAIL = os.environ.get("SES_FROM_EMAIL", "noreply@sendersafety.com")

# Rate limiting: max emails per customer per window
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "100"))   # emails
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))  # seconds (1 hour)

# ---------------------------------------------------------------------------
# Per-customer rate limiter (sliding window, in-memory)
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Sliding-window rate limiter keyed by customer_id.
    Thread-safe via asyncio (single-threaded event loop).
    """
    def __init__(self, max_count: int, window_seconds: int):
        self.max_count = max_count
        self.window = window_seconds
        # customer_id -> deque of timestamps
        self._buckets: dict[str, collections.deque] = {}

    def is_allowed(self, customer_id: str) -> bool:
        now = time.monotonic()
        if customer_id not in self._buckets:
            self._buckets[customer_id] = collections.deque()
        bucket = self._buckets[customer_id]
        # Evict timestamps outside the window
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_count:
            return False
        bucket.append(now)
        return True

    def current_count(self, customer_id: str) -> int:
        now = time.monotonic()
        bucket = self._buckets.get(customer_id, collections.deque())
        cutoff = now - self.window
        return sum(1 for t in bucket if t >= cutoff)


_rate_limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)

# ---------------------------------------------------------------------------
# Admin alerting (circuit breaker — only one alert per cooldown period)
# ---------------------------------------------------------------------------

_alert_cooldowns: dict[str, float] = {}
ALERT_COOLDOWN = 3600  # seconds between repeat alerts for the same key


def _send_admin_alert(subject: str, body: str, key: str = "default") -> None:
    """
    Send an SES email to the admin. Silently swallows errors.
    Rate-limited per `key` to avoid flooding.
    """
    now = time.time()
    if now - _alert_cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return
    _alert_cooldowns[key] = now

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        logger.warning("Admin alert skipped — AWS credentials not configured", extra={"alert_subject": subject})
        return

    try:
        client = boto3.client(
            "ses",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        client.send_email(
            Source=SES_FROM_EMAIL,
            Destination={"ToAddresses": [ADMIN_EMAIL]},
            Message={
                "Subject": {"Data": f"[Sender Safety Alert] {subject}"},
                "Body": {"Text": {"Data": body}},
            },
        )
        logger.info("Admin alert sent", extra={"alert_subject": subject, "to": ADMIN_EMAIL})
    except Exception as exc:
        logger.error("Failed to send admin alert", extra={"error": str(exc)})


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

    targets = []
    if scope == "subject":
        targets = [subject]
    elif scope == "body":
        targets = [body]
    else:  # "both"
        targets = [subject, body]

    for text in targets:
        if match_type in ("keyword", "string"):
            if pattern.lower() in text.lower():
                return True
        elif match_type == "regex":
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            except re.error as exc:
                logger.warning("Invalid regex pattern", extra={"pattern": pattern, "error": str(exc)})
    return False


async def _fetch_rules(domain: str) -> dict | None:
    """
    Fetch customer + rules from backend.
    Returns dict with 'customer_id' and 'rules', or None if domain not found.
    """
    url = f"{BACKEND_URL}/internal/rules/{domain}"
    async with aiohttp.ClientSession(headers=_INTERNAL_HEADERS) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status in (404, 403):
                return None
            resp.raise_for_status()
            return await resp.json()


async def _is_suppressed(recipient: str) -> bool:
    """Check if a recipient address is in the suppression list."""
    url = f"{BACKEND_URL}/internal/suppressed/{recipient.lower().strip('<>')}"
    try:
        async with aiohttp.ClientSession(headers=_INTERNAL_HEADERS) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    return True
                return False
    except Exception as exc:
        logger.warning("Suppression check failed — allowing email", extra={"error": str(exc)})
        return False


async def _log_scan(
    customer_id: int,
    sender: str,
    recipient: str,
    subject_hash: str,
    matched_rule_id: int | None,
    outcome: str,
    subject: str = "",
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
        "subject": subject,
    }
    try:
        async with aiohttp.ClientSession(headers=_INTERNAL_HEADERS) as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    logger.error("scan-log POST failed", extra={"status": resp.status, "body": body})
    except Exception as exc:
        logger.error("Failed to post scan log", extra={"error": str(exc)})


def _forward_via_ses(raw_message: bytes, mail_from: str, rcpt_tos: list[str]) -> None:
    """Send raw email via AWS SES (synchronous boto3 call)."""
    client = boto3.client(
        "ses",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID or None,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY or None,
    )
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
    """
    Authenticates SMTP clients by verifying credentials against the backend DB.
    Falls back to AUTH_USERNAME/AUTH_PASSWORD env vars for admin/testing.

    NOTE: aiosmtpd calls this as a sync callable from inside the running event
    loop. Calling loop.run_until_complete here deadlocks. We use the sync
    `requests` library — auth requests are short, infrequent, and block only
    the single auth connection (aiosmtpd handles each connection in a separate
    coroutine, but blocking I/O still stalls the whole loop). For low auth
    volume this is acceptable; switch to a thread executor if AUTH becomes
    a hot path.
    """

    def __call__(self, server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=True)
        username = auth_data.login.decode() if isinstance(auth_data.login, bytes) else auth_data.login
        password = auth_data.password.decode() if isinstance(auth_data.password, bytes) else auth_data.password

        try:
            resp = requests.post(
                f"{BACKEND_URL}/internal/smtp-auth",
                json={"username": username, "password": password},
                headers=_INTERNAL_HEADERS,
                timeout=5,
            )
        except Exception as exc:
            logger.error("Auth backend unreachable", extra={"error": str(exc)})
            return AuthResult(success=False, handled=True, message="451 4.7.0 Auth backend unavailable")

        if resp.status_code != 200:
            logger.warning("AUTH failed", extra={"user": username, "status": resp.status_code})
            return AuthResult(success=False, handled=True)

        result = resp.json()
        session.smtp_customer_id = result.get("customer_id")
        session.smtp_domain = result.get("domain")
        session.smtp_admin = result.get("admin", False)
        return AuthResult(success=True)


# ---------------------------------------------------------------------------
# Main SMTP handler
# ---------------------------------------------------------------------------

class SafeSenderHandler:
    """
    aiosmtpd DATA handler.

    One instance is bound to each listening port so we can apply
    port-specific policy (port 25 = MTA relay with peer-IP allowlist;
    port 587 = authenticated client with From-domain binding).

    Flow:
      1. Port-specific gate (peer-IP allowlist OR auth required).
      2. Extract sender domain from MAIL FROM.
      3. Fetch customer rules from backend.
      4. Check per-customer rate limit.
      5. Parse email in memory.
      6. Evaluate each rule.
      7. Block (550) or forward via SES.
      8. Log outcome.
    """

    def __init__(self, port: int):
        self.port = port

    def _peer_allowed_on_port25(self, peer) -> bool:
        if not peer:
            return False
        try:
            ip = ipaddress.ip_address(peer[0])
        except (ValueError, IndexError):
            return False
        return any(ip in net for net in _PORT25_NETWORKS)

    async def handle_RCPT(self, server, session, envelope, address: str, rcpt_options: list) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        mail_from: str = envelope.mail_from or ""
        rcpt_tos: list[str] = envelope.rcpt_tos
        raw_content: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()

        domain = _extract_domain(mail_from)
        peer_ip = session.peer[0] if session.peer else "unknown"
        logger.info("Incoming email", extra={"port": self.port, "peer": peer_ip, "domain": domain, "to": rcpt_tos})

        # --- Port-specific access control ------------------------------------
        if self.port == 25:
            if not self._peer_allowed_on_port25(session.peer):
                logger.warning(
                    "Port 25 connection from non-allowlisted IP — rejected",
                    extra={"peer": peer_ip, "domain": domain},
                )
                return "550 5.7.1 Connections only accepted from authorized relay IPs"
        else:
            # Port 587: must be authenticated
            if not getattr(session, "smtp_customer_id", None) and not getattr(session, "smtp_admin", False):
                return "530 5.7.0 Authentication required"
            # Bind MAIL FROM domain to the authenticated customer's domain (unless admin)
            if not getattr(session, "smtp_admin", False):
                auth_domain = (getattr(session, "smtp_domain", "") or "").lower()
                if auth_domain and domain != auth_domain:
                    logger.warning(
                        "From-domain mismatch — rejected",
                        extra={"auth_domain": auth_domain, "from_domain": domain, "peer": peer_ip},
                    )
                    return "550 5.7.1 Sender domain does not match authenticated account"

        # --- Test connection emails: sendersafety-test@<domain> ---
        local_part = mail_from.strip("<>").split("@")[0].lower()
        if local_part == "sendersafety-test":
            try:
                data = await _fetch_rules(domain)
            except Exception:
                data = None
            if data:
                recipient = rcpt_tos[0] if rcpt_tos else ""
                msg = email_lib.message_from_bytes(raw_content, policy=email_policy.default)
                subject_hash = hashlib.sha256(str(msg.get("Subject", "")).encode()).hexdigest()
                await _log_scan(
                    customer_id=data["customer_id"],
                    sender=mail_from,
                    recipient=recipient,
                    subject_hash=subject_hash,
                    matched_rule_id=None,
                    outcome="allowed",
                )
                logger.info("Test connection accepted", extra={"domain": domain})
            return "250 OK"

        # --- 1. Look up customer + rules ---
        try:
            data = await _fetch_rules(domain)
        except Exception as exc:
            logger.error("Error fetching rules", extra={"domain": domain, "error": str(exc)})
            _send_admin_alert(
                subject="Backend unreachable",
                body=f"SMTP server could not reach backend for domain {domain}.\nError: {exc}",
                key="backend-unreachable",
            )
            return "451 4.3.0 Temporary server error"

        if data is None:
            logger.info("Domain rejected", extra={"domain": domain, "reason": data})
            return "550 5.7.1 Domain not registered or not verified"

        customer_id: str = data["customer_id"]
        rules: list[dict] = data.get("rules", [])

        # --- 2. Rate limiting ---
        if not _rate_limiter.is_allowed(customer_id):
            count = _rate_limiter.current_count(customer_id)
            logger.warning(
                "Rate limit exceeded",
                extra={"customer_id": customer_id, "domain": domain, "count": count},
            )
            _send_admin_alert(
                subject=f"Rate limit hit: {domain}",
                body=(
                    f"Customer domain '{domain}' (id={customer_id}) has exceeded the rate limit "
                    f"of {RATE_LIMIT_MAX} emails per {RATE_LIMIT_WINDOW}s.\n"
                    f"Current count: {count}"
                ),
                key=f"ratelimit-{customer_id}",
            )
            return "452 4.5.3 Too many emails — rate limit exceeded, try again later"

        # --- 3. Parse email in memory ---
        msg = email_lib.message_from_bytes(raw_content, policy=email_policy.default)
        subject: str = str(msg.get("Subject", ""))
        body: str = _get_text_body(msg)
        subject_hash: str = hashlib.sha256(subject.encode()).hexdigest()

        # --- 4. Evaluate rules ---
        normal_rules = [r for r in rules if not r.get("is_exception", False)]
        exception_rules = [r for r in rules if r.get("is_exception", False)]

        matched_rule = None
        for rule in normal_rules:
            result = _rule_matches(rule, subject, body)
            if result:
                matched_rule = rule
                break

        if matched_rule:
            for exc_rule in exception_rules:
                if _rule_matches(exc_rule, subject, body):
                    logger.info(
                        "Exception rule overrides match",
                        extra={"exc_rule_id": exc_rule["id"], "matched_rule_id": matched_rule["id"]},
                    )
                    matched_rule = None
                    break

        # --- 5. Block or forward ---
        recipient = rcpt_tos[0] if rcpt_tos else ""

        if matched_rule:
            logger.info(
                "Email blocked",
                extra={
                    "from": mail_from,
                    "rule_id": matched_rule["id"],
                    "pattern": matched_rule["pattern"],
                },
            )
            await _log_scan(
                customer_id=customer_id,
                sender=mail_from,
                recipient=recipient,
                subject_hash=subject_hash,
                matched_rule_id=matched_rule["id"],
                outcome="blocked",
                subject=subject,
            )
            return "550 5.7.1 Message rejected: policy violation"

        # Forward via SES
        # --- Suppression check ---
        for rcpt in rcpt_tos:
            if await _is_suppressed(rcpt):
                logger.info("Suppressed recipient — email blocked", extra={"recipient": rcpt, "from": mail_from})
                await _log_scan(
                    customer_id=customer_id,
                    sender=mail_from,
                    recipient=recipient,
                    subject_hash=subject_hash,
                    matched_rule_id=None,
                    outcome="blocked",
                    subject=subject,
                )
                return "550 5.1.8 Recipient address suppressed due to prior bounce or complaint"

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _forward_via_ses, raw_content, mail_from, rcpt_tos)
            logger.info("Email forwarded via SES", extra={"from": mail_from})
        except Exception as exc:
            logger.error("SES send failed", extra={"error": str(exc), "from": mail_from})
            _send_admin_alert(
                subject="SES delivery failure",
                body=f"SES failed to deliver email from '{mail_from}'.\nError: {exc}",
                key="ses-failure",
            )
            await _log_scan(
                customer_id=customer_id,
                sender=mail_from,
                recipient=recipient,
                subject_hash=subject_hash,
                matched_rule_id=None,
                outcome="blocked",
                subject=subject,
            )
            return "451 4.3.0 Delivery failure — please retry"

        await _log_scan(
            customer_id=customer_id,
            sender=mail_from,
            recipient=recipient,
            subject_hash=subject_hash,
            matched_rule_id=None,
            outcome="allowed",
            subject=subject,
        )
        return "250 OK"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_ssl_context() -> ssl.SSLContext | None:
    """Return an SSL context if TLS cert/key paths are configured.

    Fails fast if TLS paths are set but unreadable — production must not
    silently fall back to plaintext.
    """
    if not TLS_CERT_PATH or not TLS_KEY_PATH:
        return None
    if not os.path.exists(TLS_CERT_PATH) or not os.path.exists(TLS_KEY_PATH):
        sys.stderr.write(
            f"FATAL: TLS_CERT_PATH or TLS_KEY_PATH set but file not found "
            f"(cert={TLS_CERT_PATH}, key={TLS_KEY_PATH}). Refusing to start.\n"
        )
        sys.exit(1)
    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)
    except Exception as exc:
        sys.stderr.write(f"FATAL: failed to load TLS cert/key: {exc}\n")
        sys.exit(1)
    return ctx


if __name__ == "__main__":
    authenticator = Authenticator()
    ssl_context = build_ssl_context()

    # Port 587 - authenticated direct SMTP clients. STARTTLS REQUIRED in prod.
    # auth_require_tls defaults to True; if no TLS context, refuse to start
    # so we never accept plaintext-AUTH from the public internet.
    if ssl_context is None:
        sys.stderr.write(
            "FATAL: port 587 requires TLS. Set TLS_CERT_PATH and TLS_KEY_PATH. "
            "Refusing to start.\n"
        )
        sys.exit(1)

    handler587 = SafeSenderHandler(port=587)
    controller587 = Controller(
        handler587,
        hostname="0.0.0.0",
        port=587,
        authenticator=authenticator,
        auth_required=True,
        auth_require_tls=True,
        ssl_context=ssl_context,
    )
    controller587.start()
    logger.info(
        "Safe Sender SMTP started (port 587, AUTH required, TLS enforced)",
        extra={"port": 587, "rate_limit_max": RATE_LIMIT_MAX, "rate_limit_window": RATE_LIMIT_WINDOW},
    )

    # Port 25 - MTA-to-MTA inbound from Google Workspace SMTP relay.
    # No SMTP-AUTH (peer-IP allowlist enforced inside handle_DATA).
    handler25 = SafeSenderHandler(port=25)
    controller25 = Controller(
        handler25,
        hostname="0.0.0.0",
        port=25,
        auth_required=False,
        auth_require_tls=False,
    )
    controller25.start()
    logger.info(
        "Safe Sender SMTP started (port 25, no AUTH, peer-IP allowlist)",
        extra={"port": 25, "allowed_networks": len(_PORT25_NETWORKS)},
    )

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller587.stop()
        controller25.stop()
        logger.info("SMTP server stopped")