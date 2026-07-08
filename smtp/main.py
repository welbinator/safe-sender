"""
Sender Safety SMTP server — Sprint 6.

Receives email on port 587 (STARTTLS), scans against customer rules fetched
from the backend service, then either:
  - Rejects with 550 5.7.1 (policy violation or unknown domain)
  - Forwards via Mailgun SMTP relay and logs outcome to scan_logs

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
import hmac
import ipaddress
import json
import logging
import os
import re as _stdlib_re  # kept ONLY for non-customer code paths
import ssl
import sys
import threading
import time
import unicodedata
from email import policy as email_policy
from email import utils as email_utils

import aiohttp
import requests
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from internal_auth_crypto import WIRE_VERSION, seal_password, verify_test_token

# google-re2 — RE2 has linear-time guarantees and is immune to ReDoS.
# Used for all customer-supplied regex patterns. Stdlib re is unsafe here
# because a single malicious pattern can pin the worker forever (Sprint B C9/H2).
try:
    import re2 as _customer_re  # type: ignore
    _USING_RE2 = True
except ImportError:  # pragma: no cover - dev fallback
    _customer_re = _stdlib_re  # type: ignore
    _USING_RE2 = False

# Defensive cap (backend enforces too).
MAX_PATTERN_LEN = 1000
# Even RE2 is linear in input size; cap the input we feed to it so a
# multi-megabyte body × many rules can't burn CPU.
MAX_REGEX_INPUT_LEN = 65536


# ---------------------------------------------------------------------------
# Subject normalization + HMAC hashing (Sprint B C12, C15)
# ---------------------------------------------------------------------------
#
# C15: subjects are normalized server-side so customers can't dodge logging
#   by inserting zero-width joiners, RTL marks, or stray control characters.
#   Normalization is NFKC + strip bidi/format/control chars + collapse
#   whitespace + lowercase. The result is what gets hashed.
#
# C12: hashing is HMAC-SHA-256 with a per-customer salt fetched from the
#   backend. This means the same subject for two different customers produces
#   two different hashes, so an attacker who dumps scan_logs can't rainbow
#   the whole table against a single dictionary of common subjects.

# Codepoint categories Unicode flags as "Cf" (format), "Cc" (control) etc.
# We strip Cf and Cc (except tab/newline/space which we then collapse).
_KEEP_CONTROL = {"\t", "\n", " "}


def _normalize_subject(subject: str) -> str:
    """Canonicalize a subject for stable hashing.

    Steps:
      1. NFKC unicode normalization (collapses compatibility forms).
      2. Strip format (Cf) codepoints — zero-width joiners, BOM, RLE/LRE,
         LRI/RLI/FSI/PDI, etc. These are pure-display tricks attackers use
         to make two human-equal subjects hash differently.
      3. Strip control (Cc) codepoints except tab/newline/space.
      4. Collapse runs of whitespace, casefold, trim.
    """
    if not subject:
        return ""
    nfkc = unicodedata.normalize("NFKC", subject)
    cleaned_chars = []
    for ch in nfkc:
        cat = unicodedata.category(ch)
        if cat == "Cf":  # format
            continue
        if cat == "Cc" and ch not in _KEEP_CONTROL:
            continue
        cleaned_chars.append(ch)
    cleaned = "".join(cleaned_chars)
    # Collapse any run of whitespace to a single space.
    collapsed = _stdlib_re.sub(r"\s+", " ", cleaned).strip()
    return collapsed.casefold()


def _hash_subject(subject: str, salt: bytes) -> str:
    """Return hex HMAC-SHA-256 of the normalized subject."""
    normalized = _normalize_subject(subject)
    return hmac.new(salt, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def _decode_salt(data: dict | str | None) -> bytes:
    """Decode the HMAC salt returned by the backend.

    F-17: prefers `subject_hash_salt_enc` (Fernet-encrypted via shared-secret-
    derived key). Falls back to plaintext `subject_hash_salt` during the
    rolling-deploy window where backend may still be on the old build.

    Accepts either the full /internal/rules response dict (preferred) or, for
    backwards-compat with callers that already extracted a hex string, the
    string itself.

    Fail closed: if the backend didn't return a salt (legacy code path,
    rolling deploy, etc.) we use the all-zero salt rather than crash.
    Hashes computed this way are still unique per subject but lose the
    cross-customer privacy property until the backend catches up.
    """
    if data is None:
        return b"\x00" * 32

    # Caller passed the full response dict — preferred F-17 path.
    if isinstance(data, dict):
        enc = data.get("subject_hash_salt_enc")
        if enc:
            try:
                from internal_crypto import decrypt_field, InvalidToken
                hex_bytes = decrypt_field(enc)
                return bytes.fromhex(hex_bytes.decode("ascii"))
            except (InvalidToken, ValueError) as exc:
                logger.error(
                    "subject_hash_salt_enc failed to decrypt; "
                    "falling back to plaintext field if present",
                    extra={"error": str(exc)},
                )
        hex_salt = data.get("subject_hash_salt")
    else:
        hex_salt = data

    if not hex_salt:
        return b"\x00" * 32
    try:
        return bytes.fromhex(hex_salt)
    except ValueError:
        logger.warning("subject_hash_salt was not valid hex; using zero salt")
        return b"\x00" * 32

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
        # F-48: surface the per-SMTP-transaction request id when one's in
        # scope so log lines correlate with backend access logs.
        rid = _request_id_ctx.get() if "_request_id_ctx" in globals() else None
        if rid:
            base["request_id"] = rid
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

# F-48 — per-message correlation id. Each SMTP transaction picks a UUID;
# every outbound HTTP call to the backend (rules, suppression, scan-log
# insert) carries it as X-Request-Id, and we include it in our own log
# lines so a delivery problem can be traced from the relay all the way
# through the backend without grepping by timestamp.
import contextvars
import uuid as _uuid

_request_id_ctx: "contextvars.ContextVar[str | None]" = contextvars.ContextVar(
    "request_id", default=None
)


def _current_request_id() -> str | None:
    return _request_id_ctx.get()


def _internal_headers() -> dict[str, str]:
    """_INTERNAL_HEADERS plus X-Request-Id when one is in scope."""
    rid = _current_request_id()
    if rid is None:
        return _INTERNAL_HEADERS
    return {**_INTERNAL_HEADERS, "X-Request-Id": rid}

import spf as _spf  # pyspf — RFC 7208 SPF lookups

# ---------------------------------------------------------------------------
# S-H1 — Port-25 access control: SPF + PTR (replaces static CIDR allowlist)
# ---------------------------------------------------------------------------
#
# PRIMARY GATE: SPF check against the sender's domain.
#   The connecting IP must appear in the SPF record published by the MAIL FROM
#   domain. Since every customer already adds spf.protection.outlook.com or
#   _spf.google.com to their domain SPF record as part of setup, this check
#   is self-maintaining — when Google or Microsoft add new IPs they update
#   their own SPF records, and our check picks it up automatically at runtime.
#
# PTR FALLBACK: for IPs that return SPF `none` / `softfail` (e.g. Microsoft's
#   HighRiskOutboundPool, which is deliberately excluded from published EOP
#   SPF records), we do a reverse-DNS lookup. If the PTR hostname ends in a
#   trusted suffix (.mail.protection.outlook.com or .google.com) we allow it.
#   Microsoft always names their sending infrastructure under these suffixes,
#   regardless of which IP pool they use.
#
# LEGACY CIDR FALLBACK: PORT25_ALLOWED_CIDRS is kept as a third-tier escape
#   hatch. Existing env var config continues to work unchanged, and operators
#   can still add one-off ranges for on-prem relay customers that have no SPF.
#
# Policy summary (SPF result → action):
#   pass                → allow ✓
#   none / neutral      → try PTR fallback, then CIDR fallback, then reject
#   softfail            → try PTR fallback, then CIDR fallback, then allow
#                         (log warning; some legit relays softfail)
#   fail                → reject 550 5.7.23 (verified forgery)
#   temperror           → allow (fail-open; flaky DNS ≠ DoS vector)
#   permerror           → log warning, fall through to PTR/CIDR fallback
#
# Kill-switch: SPF_ENFORCE=0 disables SPF+PTR and falls back to CIDR-only.

SPF_ENFORCE = os.environ.get("SPF_ENFORCE", "1") not in ("0", "false", "False", "")

# Trusted PTR suffixes — any connecting IP whose reverse-DNS hostname ends in
# one of these is treated as an authorized relay even if SPF is none/softfail.
_TRUSTED_PTR_SUFFIXES: tuple[str, ...] = (
    ".mail.protection.outlook.com",     # Microsoft EOP standard pools
    ".outbound.protection.outlook.com", # Microsoft EOP outbound pools (incl. HROP)
    ".google.com",                      # Google Workspace SMTP relay
)

# FQDN validation regex (S-M8 — hardened domain extraction)
_FQDN_RE = _stdlib_re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Z0-9-]{1,63}(?<!-))+$",
    _stdlib_re.IGNORECASE,
)

# Legacy CIDR allowlist — kept as escape hatch for on-prem relay customers.
# Default is empty (SPF+PTR handles Google and Microsoft automatically).
# Set PORT25_ALLOWED_CIDRS in env to add one-off ranges.
PORT25_ALLOWED_CIDRS = os.environ.get("PORT25_ALLOWED_CIDRS", "")
_PORT25_NETWORKS = [
    ipaddress.ip_network(c.strip(), strict=False)
    for c in PORT25_ALLOWED_CIDRS.split(",") if c.strip()
]

MAILGUN_API_KEY = os.environ.get("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.environ.get("MAILGUN_DOMAIN", "mg.sendersafety.com")
MAILGUN_SMTP_HOST = os.environ.get("MAILGUN_SMTP_HOST", "smtp.mailgun.org")
MAILGUN_SMTP_PORT = int(os.environ.get("MAILGUN_SMTP_PORT", "587"))
MAILGUN_SMTP_LOGIN = os.environ.get("MAILGUN_SMTP_LOGIN", "")
MAILGUN_SMTP_PASSWORD = os.environ.get("MAILGUN_SMTP_PASSWORD", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@sendersafety.com")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "james.welbes@gmail.com")

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


# ---------------------------------------------------------------------------
# Mailgun email delivery
# ---------------------------------------------------------------------------

def _send_admin_alert(subject: str, body: str, key: str = "default") -> None:
    """Send admin alert via Mailgun HTTP API. Rate-limited per key."""
    now = time.time()
    if now - _alert_cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return
    _alert_cooldowns[key] = now

    if not MAILGUN_API_KEY:
        logger.warning(
            "Admin alert skipped — MAILGUN_API_KEY not configured",
            extra={"alert_subject": subject},
        )
        return

    try:
        resp = requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": FROM_EMAIL,
                "to": ADMIN_EMAIL,
                "subject": f"[Sender Safety Alert] {subject}",
                "text": body,
            },
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Admin alert sent", extra={"alert_subject": subject, "to": ADMIN_EMAIL})
    except Exception as exc:
        logger.error("Failed to send admin alert", extra={"error": str(exc)})


async def _send_admin_alert_async(subject: str, body: str, key: str = "default") -> None:
    """Async wrapper — offload Mailgun alert to a worker thread."""
    now = time.time()
    if now - _alert_cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return
    await asyncio.to_thread(_send_admin_alert, subject, body, key)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(address: str) -> str:
    """Return the domain part of an email address, lowercased.

    S-M8 — hardened version. Uses email.utils.parseaddr so quoted local-parts
    are honored, then validates the domain against the FQDN regex.  Returns ""
    for any input that fails validation — callers treat "" as reject.
    """
    if not address:
        return ""
    address = address.strip().strip("<>").strip()
    if not address:
        return ""
    _, parsed = email_utils.parseaddr(address)
    if not parsed or "@" not in parsed:
        return ""
    local, _, domain = parsed.rpartition("@")
    if not local or not domain:
        return ""
    domain = domain.lower().rstrip(".")
    if not _FQDN_RE.match(domain):
        return ""
    return domain


def _check_spf_sync(peer_ip: str, mail_from: str, helo: str) -> tuple[str, str]:
    """Synchronous SPF lookup via pyspf.  Returns (result, explanation).

    Wrapped via asyncio.to_thread by the async caller so the event loop is
    never blocked by DNS I/O.
    """
    try:
        result, explanation = _spf.check2(i=peer_ip, s=mail_from, h=helo or "unknown")
        return str(result or "").lower(), str(explanation or "")
    except Exception as exc:
        return "temperror", f"spf-check raised: {exc}"


async def _check_spf(peer_ip: str, mail_from: str, helo: str) -> tuple[str, str]:
    """Async SPF wrapper.  Returns ("", "") when SPF_ENFORCE is off."""
    if not SPF_ENFORCE:
        return ("", "")
    if not mail_from or not peer_ip or peer_ip == "unknown":
        return ("none", "missing peer or sender")
    try:
        ipaddress.ip_address(peer_ip)
    except ValueError:
        return ("none", "peer not an IP literal")
    return await asyncio.to_thread(_check_spf_sync, peer_ip, mail_from, helo)


def _ptr_trusted_sync(peer_ip: str) -> bool:
    """Return True if the reverse-DNS hostname of peer_ip ends in a trusted suffix.

    Runs synchronously — wrap in asyncio.to_thread at call site.
    Swallows all DNS exceptions (NXDOMAIN, timeout, etc.) and returns False.
    """
    try:
        import dns.resolver as _dns_resolver
        import dns.reversename as _dns_rev
        resolver = _dns_resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.lifetime = 5.0
        rev_name = _dns_rev.from_address(peer_ip)
        answers = resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            hostname = str(rdata.target).rstrip(".").lower()
            if any(hostname.endswith(suffix) for suffix in _TRUSTED_PTR_SUFFIXES):
                return True
    except Exception:
        pass
    return False


async def _check_ptr_trusted(peer_ip: str) -> bool:
    """Async wrapper around _ptr_trusted_sync."""
    return await asyncio.to_thread(_ptr_trusted_sync, peer_ip)


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
            if len(pattern) > MAX_PATTERN_LEN:
                logger.warning(
                    "Rejecting oversized regex pattern",
                    extra={"len": len(pattern), "rule_id": rule.get("id")},
                )
                continue
            text_to_scan = text[:MAX_REGEX_INPUT_LEN]
            try:
                if _customer_re.search(pattern, text_to_scan, _customer_re.IGNORECASE):
                    return True
            except Exception as exc:
                # Catch broadly — re2 raises its own error type, not re.error.
                logger.warning(
                    "Invalid regex pattern",
                    extra={"pattern": pattern, "error": str(exc)},
                )
    return False


async def _fetch_rules(domain: str) -> dict | None:
    """
    Fetch customer + rules from backend.
    Returns dict with 'customer_id' and 'rules', or None if domain not found.
    """
    url = f"{BACKEND_URL}/internal/rules/{domain}"
    max_attempts = 4
    for attempt in range(1, max_attempts + 1):
        try:
            async with aiohttp.ClientSession(headers=_internal_headers()) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in (404, 403):
                        return None
                    resp.raise_for_status()
                    return await resp.json()
        except Exception as exc:
            logger.warning(
                "fetch_rules failed, will retry",
                extra={"attempt": attempt, "domain": domain, "error": str(exc)},
            )
            if attempt < max_attempts:
                await asyncio.sleep(2 ** (attempt - 1))  # 1s, 2s, 4s
    logger.error("fetch_rules gave up after %d attempts for domain %s", max_attempts, domain)
    return None


async def _is_suppressed(customer_id: str, recipient: str) -> bool:
    """Check if a recipient address is suppressed for this customer.

    Sprint B C16: scoped per-customer. Backend also returns suppressed=True
    for legacy unscoped rows (customer_id IS NULL) until backfill completes.
    """
    addr = recipient.lower().strip("<>")
    url = f"{BACKEND_URL}/internal/suppressed/{customer_id}/{addr}"
    try:
        async with aiohttp.ClientSession(headers=_internal_headers()) as session:
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
    ai_decision: str | None = None,
    ai_confidence: int | None = None,
    ai_reason: str | None = None,
    processing_ms: int | None = None,
) -> None:
    """POST a scan log entry to the backend (fire-and-forget style, but awaited).

    F-08: the plaintext `subject` is intentionally NOT sent. Only the HMAC
    `subject_hash` is persisted, honoring the privacy guarantee at the top of
    this file.
    """
    url = f"{BACKEND_URL}/internal/scan-log"
    payload = {
        "customer_id": customer_id,
        "sender": sender,
        "recipient": recipient,
        "subject_hash": subject_hash,
        "matched_rule_id": matched_rule_id,
        "outcome": outcome,
        "ai_decision": ai_decision,
        "ai_confidence": ai_confidence,
        "ai_reason": ai_reason,
        "processing_ms": processing_ms,
    }
    max_attempts = 4
    for attempt in range(1, max_attempts + 1):
        try:
            async with aiohttp.ClientSession(headers=_internal_headers()) as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in (200, 201):
                        return
                    body = await resp.text()
                    logger.warning(
                        "scan-log POST non-2xx, will retry",
                        extra={"attempt": attempt, "status": resp.status, "body": body[:200]},
                    )
        except Exception as exc:
            logger.warning(
                "scan-log POST failed, will retry",
                extra={"attempt": attempt, "error": str(exc)},
            )
        if attempt < max_attempts:
            await asyncio.sleep(2 ** (attempt - 1))  # 1s, 2s, 4s
    logger.error("scan-log POST gave up after %d attempts", max_attempts)


def _inject_mailgun_tag(raw_content: bytes, customer_id: str) -> bytes:
    """Inject X-Mailgun-Tag header for bounce/complaint webhook scoping."""
    import email as _email_mod
    msg = _email_mod.message_from_bytes(raw_content)
    if "X-Mailgun-Tag" in msg:
        del msg["X-Mailgun-Tag"]
    msg["X-Mailgun-Tag"] = str(customer_id)
    return msg.as_bytes()


def _forward_via_mailgun_smtp(
    raw_content: bytes,
    mail_from: str,
    rcpt_tos: list[str],
) -> None:
    """Forward raw email via Mailgun SMTP relay (synchronous, run in executor)."""
    import smtplib
    with smtplib.SMTP(MAILGUN_SMTP_HOST, MAILGUN_SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(MAILGUN_SMTP_LOGIN, MAILGUN_SMTP_PASSWORD)
        smtp.sendmail(mail_from, rcpt_tos, raw_content)

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

        # S-H4: seal the password with AES-256-GCM (key derived from
        # INTERNAL_SHARED_SECRET via HKDF). Plaintext password never crosses
        # the docker network. AAD binds the username + wire version, so an
        # intercepted blob cannot be replayed against a different user.
        try:
            auth_blob = seal_password(username, password)
        except Exception as exc:
            logger.error("Failed to seal SMTP auth payload", extra={"error": str(exc)})
            return AuthResult(success=False, handled=True, message="451 4.7.0 Auth backend unavailable")

        try:
            resp = requests.post(
                f"{BACKEND_URL}/internal/smtp-auth",  # nosemgrep: python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http
                json={"v": WIRE_VERSION, "username": username, "auth_blob": auth_blob},
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

    async def _port25_authorized(self, peer_ip: str, mail_from: str, helo: str) -> tuple[bool, str]:
        """Three-tier port-25 authorization.  Returns (allowed, reason_for_log).

        Tier 1 — SPF: check if peer_ip is authorized by the MAIL FROM domain's
                  SPF record.  Self-maintaining: Google/Microsoft keep their own
                  records up to date.  Hard `fail` → reject immediately.

        Tier 2 — PTR: for SPF none/softfail/permerror (e.g. Microsoft HROP,
                  which is excluded from published EOP SPF on purpose), check
                  reverse-DNS.  Trusted suffixes (.mail.protection.outlook.com,
                  .google.com) → allow.

        Tier 3 — CIDR: legacy escape hatch.  PORT25_ALLOWED_CIDRS env var
                  (default empty).  Allows on-prem relay customers that have
                  no SPF record.

        Returns (False, reason) only when all three tiers deny the connection.
        SPF_ENFORCE=0 skips tiers 1+2 and falls straight to tier 3 (CIDR-only,
        legacy behaviour).
        """
        if not SPF_ENFORCE:
            # Kill-switch: fall back to CIDR-only (legacy behaviour).
            try:
                ip = ipaddress.ip_address(peer_ip)
                if any(ip in net for net in _PORT25_NETWORKS):
                    return True, "cidr-match (spf-enforce=off)"
            except ValueError:
                pass
            return False, "no-cidr-match (spf-enforce=off)"

        # Tier 1 — SPF
        spf_result, spf_reason = await _check_spf(peer_ip, mail_from, helo)
        if spf_result == "fail":
            return False, f"spf-fail: {spf_reason}"
        if spf_result == "pass":
            return True, "spf-pass"
        if spf_result == "temperror":
            return True, f"spf-temperror (fail-open): {spf_reason}"

        # Tier 2 — PTR (covers none/neutral/softfail/permerror)
        ptr_trusted = await _check_ptr_trusted(peer_ip)
        if ptr_trusted:
            return True, f"ptr-trusted (spf={spf_result})"

        # Tier 3 — CIDR legacy fallback
        try:
            ip = ipaddress.ip_address(peer_ip)
            if any(ip in net for net in _PORT25_NETWORKS):
                return True, f"cidr-match (spf={spf_result})"
        except ValueError:
            pass

        # softfail: allow but only after PTR+CIDR both missed — log clearly
        if spf_result == "softfail":
            return True, f"spf-softfail allowed (no ptr/cidr match): {spf_reason}"

        return False, f"denied: spf={spf_result}, no ptr/cidr match"

    async def handle_RCPT(self, server, session, envelope, address: str, rcpt_options: list) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        # F-48: mint a correlation id per SMTP transaction. Anything inside
        # this coroutine (helpers, aiohttp calls, log lines) can pick it
        # up via _current_request_id().
        _request_id_ctx.set(_uuid.uuid4().hex)
        _t0 = time.monotonic()
        mail_from: str = envelope.mail_from or ""
        rcpt_tos: list[str] = envelope.rcpt_tos
        raw_content: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()

        domain = _extract_domain(mail_from)

        # M365 connector validation (and DSN/bounce messages) use a null
        # envelope sender: MAIL FROM:<>. In that case fall back to the From:
        # header inside the message body to find the customer's domain.
        # We do a lightweight header-only parse here — before handle_DATA
        # completes no body processing has happened yet.
        if not domain and envelope.content:
            try:
                _raw = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()
                _hdr_msg = email_lib.message_from_bytes(_raw, policy=email_policy.default)
                _from_hdr = _hdr_msg.get("From", "") or ""
                # From header can be "Name <addr>" or bare "addr"
                _, _from_addr = email_utils.parseaddr(_from_hdr)
                domain = _extract_domain(_from_addr)
            except Exception:
                pass
        peer_ip = session.peer[0] if session.peer else "unknown"
        logger.info("Incoming email", extra={"port": self.port, "peer": peer_ip, "domain": domain, "to": rcpt_tos})

        # --- Port-specific access control ------------------------------------
        if self.port == 25:
            helo = getattr(session, "host_name", "") or ""
            allowed, auth_reason = await self._port25_authorized(peer_ip, mail_from, helo)
            if not allowed:
                logger.warning(
                    "Port 25 connection denied",
                    extra={"peer": peer_ip, "domain": domain, "reason": auth_reason},
                )
                return "550 5.7.1 Connections only accepted from authorized relay IPs"
            logger.info(
                "Port 25 connection authorized",
                extra={"peer": peer_ip, "domain": domain, "reason": auth_reason},
            )
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
        # S-H3: bypass requires a valid HMAC token in `X-SenderSafety-TestToken`
        # minted by the backend. Without it, the message falls through to the
        # normal scanning path (no free outcome=allowed log injection).
        local_part = mail_from.strip("<>").split("@")[0].lower()
        if local_part == "sendersafety-test":
            try:
                data = await _fetch_rules(domain)
            except Exception:
                data = None
            test_token_valid = False
            if data:
                try:
                    msg_for_token = email_lib.message_from_bytes(
                        raw_content, policy=email_policy.default
                    )
                    token = msg_for_token.get("X-SenderSafety-TestToken")
                    if token:
                        test_token_valid = verify_test_token(
                            str(token), str(data["customer_id"])
                        )
                except Exception:
                    test_token_valid = False
            if data and test_token_valid:
                recipient = rcpt_tos[0] if rcpt_tos else ""
                msg = email_lib.message_from_bytes(raw_content, policy=email_policy.default)
                _salt = _decode_salt(data)
                subject_hash = _hash_subject(str(msg.get("Subject", "")), _salt)
                await _log_scan(
                    customer_id=data["customer_id"],
                    sender=mail_from,
                    recipient=recipient,
                    subject_hash=subject_hash,
                    matched_rule_id=None,
                    outcome="allowed",
                
                processing_ms=int((time.monotonic() - _t0) * 1000),
            )
                logger.info("Test connection accepted", extra={"domain": domain})
                return "250 OK"
            if data and not test_token_valid:
                logger.warning(
                    "sendersafety-test local-part without valid token — "
                    "falling through to normal scan",
                    extra={"domain": domain, "peer": peer_ip},
                )
            # fall through to normal scan path below

        # --- 1. Look up customer + rules ---
        try:
            data = await _fetch_rules(domain)
        except Exception as exc:
            logger.error("Error fetching rules", extra={"domain": domain, "error": str(exc)})
            await _send_admin_alert_async(
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
        subject_hash_salt: bytes = _decode_salt(data)

        # --- 2. Rate limiting ---
        if not _rate_limiter.is_allowed(customer_id):
            count = _rate_limiter.current_count(customer_id)
            logger.warning(
                "Rate limit exceeded",
                extra={"customer_id": customer_id, "domain": domain, "count": count},
            )
            await _send_admin_alert_async(
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
        subject_hash: str = _hash_subject(subject, subject_hash_salt)

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
            
                processing_ms=int((time.monotonic() - _t0) * 1000),
            )
            return "550 5.7.1 Message rejected: policy violation"

        # --- AI scan (async, runs after keyword rules pass) ---
        ai_result = None
        ai_enabled = data.get("ai_scan_enabled", False)
        ai_policies_list = data.get("ai_policies", [])
        if ai_enabled and ai_policies_list:
            try:
                import ai_scan as _ai_scan
                ai_result = await asyncio.to_thread(
                    _ai_scan.scan_email, subject, body, ai_policies_list
                )
                if ai_result:
                    logger.info(
                        "AI scan result",
                        extra={
                            "decision": ai_result.decision,
                            "confidence": ai_result.confidence,
                            "reason": ai_result.reason,
                        },
                    )
                    if ai_result.decision == "flag" and ai_result.confidence >= 70:
                        await _log_scan(
                            customer_id=customer_id,
                            sender=mail_from,
                            recipient=recipient,
                            subject_hash=subject_hash,
                            matched_rule_id=None,
                            outcome="blocked",
                            ai_decision=ai_result.decision,
                            ai_confidence=ai_result.confidence,
                            ai_reason=ai_result.reason,
                        
                processing_ms=int((time.monotonic() - _t0) * 1000),
            )
                        return "550 5.7.1 Message rejected: AI compliance policy violation"
            except Exception as exc:
                logger.warning("AI scan error — fail open", extra={"error": str(exc)})

        # Forward via Mailgun
        # --- Suppression check ---
        for rcpt in rcpt_tos:
            if await _is_suppressed(customer_id, rcpt):
                logger.info("Suppressed recipient — email blocked", extra={"recipient": rcpt, "from": mail_from})
                await _log_scan(
                    customer_id=customer_id,
                    sender=mail_from,
                    recipient=recipient,
                    subject_hash=subject_hash,
                    matched_rule_id=None,
                    outcome="blocked",
                
                processing_ms=int((time.monotonic() - _t0) * 1000),
            )
                return "550 5.1.8 Recipient address suppressed due to prior bounce or complaint"

        try:
            tagged_content = _inject_mailgun_tag(raw_content, customer_id)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, _forward_via_mailgun_smtp, tagged_content, mail_from, rcpt_tos
            )
            logger.info("Email forwarded via Mailgun", extra={"from": mail_from})
        except Exception as exc:
            logger.error("Mailgun send failed", extra={"error": str(exc), "from": mail_from})
            await _send_admin_alert_async(
                subject="Mailgun delivery failure",
                body=f"Mailgun failed to deliver email from {mail_from!r}.\nError: {exc}",
                key="mailgun-failure",
            )
            await _log_scan(
                customer_id=customer_id,
                sender=mail_from,
                recipient=recipient,
                subject_hash=subject_hash,
                matched_rule_id=None,
                outcome="blocked",
            
                processing_ms=int((time.monotonic() - _t0) * 1000),
            )
            return "451 4.3.0 Delivery failure — please retry"

        await _log_scan(
            customer_id=customer_id,
            sender=mail_from,
            recipient=recipient,
            subject_hash=subject_hash,
            matched_rule_id=None,
            outcome="allowed",
        
                processing_ms=int((time.monotonic() - _t0) * 1000),
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
        hostname="0.0.0.0",  # nosec B104 - SMTP server must bind all container interfaces; exposure controlled by Docker port mapping + Hetzner firewall
        port=587,
        authenticator=authenticator,
        auth_required=True,
        auth_require_tls=True,
        require_starttls=True,
        tls_context=ssl_context,
    )
    controller587.start()
    logger.info(
        "Safe Sender SMTP started (port 587, AUTH required, TLS enforced)",
        extra={"port": 587, "rate_limit_max": RATE_LIMIT_MAX, "rate_limit_window": RATE_LIMIT_WINDOW},
    )

    # Port 25 - MTA-to-MTA inbound from Google Workspace / Microsoft 365 SMTP relay.
    # No SMTP-AUTH (peer-IP allowlist enforced inside handle_DATA).
    # STARTTLS is offered opportunistically — required by M365 smart host connectors.
    handler25 = SafeSenderHandler(port=25)
    controller25 = Controller(
        handler25,
        hostname="0.0.0.0",  # nosec B104 - SMTP server must bind all container interfaces; exposure controlled by Docker port mapping + Hetzner firewall
        port=25,
        auth_required=False,
        auth_require_tls=False,
        tls_context=ssl_context,
    )
    controller25.start()
    logger.info(
        "Safe Sender SMTP started (port 25, no AUTH, peer-IP allowlist)",
        extra={"port": 25, "allowed_networks": len(_PORT25_NETWORKS)},
    )

    try:
        # ------------------------------------------------------------------
        # F-50 — Tiny health endpoint on loopback:9100. The orchestrator (or a
        # docker healthcheck) can hit GET /health and get a 200 if both SMTP
        # controllers are running. Not reachable from outside the container
        # (binds 127.0.0.1) and not behind the firewall on 25/587.
        # ------------------------------------------------------------------
        from aiohttp import web

        async def _health(_req):
            ok = bool(getattr(controller587, "server", None)) and bool(
                getattr(controller25, "server", None)
            )
            status = 200 if ok else 503
            return web.json_response(
                {
                    "status": "ok" if ok else "degraded",
                    "smtp_587": bool(getattr(controller587, "server", None)),
                    "smtp_25": bool(getattr(controller25, "server", None)),
                },
                status=status,
            )

        async def _start_health():
            app = web.Application()
            app.router.add_get("/health", _health)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 9100)
            await site.start()
            logger.info("SMTP health endpoint listening on 127.0.0.1:9100/health")

        loop = asyncio.get_event_loop()
        loop.run_until_complete(_start_health())
        loop.run_forever()
    except KeyboardInterrupt:
        controller587.stop()
        controller25.stop()
        logger.info("SMTP server stopped")