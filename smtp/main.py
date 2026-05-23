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
import boto3
import requests
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer, AuthResult, LoginPassword, MISSING
from base64 import b64decode
from botocore.config import Config as BotoConfig

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
    # S-L3: when no salt is recoverable, derive a deterministic per-customer
    # fallback via HMAC(INTERNAL_SHARED_SECRET, customer_id) so a backend
    # crypto hiccup never collapses every customer into the same hash space.
    # All-zero fallback is only used when we truly have nothing (no customer_id
    # available — caller passed None or a bare hex string with no context).
    def _fallback_salt(customer_id: str | None) -> bytes:
        if not customer_id:
            return b"\x00" * 32
        import hmac as _hmac, hashlib as _hashlib
        key = (INTERNAL_SHARED_SECRET or "salt-fallback").encode()
        return _hmac.new(key, f"salt-fallback-v1|{customer_id}".encode(), _hashlib.sha256).digest()

    if data is None:
        return _fallback_salt(None)

    # Caller passed the full response dict — preferred F-17 path.
    if isinstance(data, dict):
        cust = data.get("customer_id")
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
                    extra={"error": str(exc), "customer_id": cust},
                )
        hex_salt = data.get("subject_hash_salt")
        if not hex_salt:
            return _fallback_salt(cust)
    else:
        hex_salt = data
        cust = None

    if not hex_salt:
        return _fallback_salt(cust)
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
# S-I1: removed dead AUTH_USERNAME/AUTH_PASSWORD env vars — never consulted.
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

    S-M6: this in-memory implementation is per-process (lost on crash, not
    shared across SMTP replicas). Production should prefer
    ``RedisRateLimiter`` when ``REDIS_URL`` is set — selected automatically
    by :func:`_make_rate_limiter`. The in-memory variant remains as the
    fallback for single-node dev/test and as a safety net if Redis becomes
    unreachable at runtime.
    """
    def __init__(self, max_count: int, window_seconds: int):
        self.max_count = max_count
        self.window = window_seconds
        # customer_id -> deque of timestamps
        self._buckets: dict[str, collections.deque] = {}

    def _is_allowed_sync(self, customer_id: str, cost: int = 1) -> bool:
        """Charge `cost` tokens (= number of recipients) against the bucket.

        S-M5: per-message accounting let an attacker amplify by stuffing 100
        recipients into a single envelope. We now reserve one slot per
        recipient — a 100-RCPT message costs 100 against the bucket — and
        only admit the message if the full cost fits in the remaining window.
        """
        now = time.monotonic()
        if cost < 1:
            cost = 1
        if customer_id not in self._buckets:
            self._buckets[customer_id] = collections.deque()
        bucket = self._buckets[customer_id]
        # Evict timestamps outside the window
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) + cost > self.max_count:
            return False
        for _ in range(cost):
            bucket.append(now)
        return True

    def _current_count_sync(self, customer_id: str) -> int:
        now = time.monotonic()
        bucket = self._buckets.get(customer_id, collections.deque())
        cutoff = now - self.window
        return sum(1 for t in bucket if t >= cutoff)

    async def is_allowed(self, customer_id: str, cost: int = 1) -> bool:
        return self._is_allowed_sync(customer_id, cost)

    async def current_count(self, customer_id: str) -> int:
        return self._current_count_sync(customer_id)


# S-M6 — Atomic sliding-window check via Redis sorted sets.
#
# The window is stored as a ZSET keyed by ``ratelimit:{customer_id}`` whose
# members are unique event IDs and whose scores are wall-clock microseconds.
# A single Lua script (a) drops timestamps older than ``now - window``,
# (b) counts what's left, (c) refuses if ``count + cost > max``, otherwise
# (d) inserts ``cost`` fresh members and refreshes TTL. Executing as Lua
# means the read-modify-write happens server-side under Redis's
# single-threaded execution model — no TOCTOU between two SMTP replicas.
#
# Failure mode: any Redis error falls back to the in-memory limiter so a
# Redis outage degrades to single-process limiting rather than open-fail.
_REDIS_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_count = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local cutoff = now - (window * 1000000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local current = redis.call('ZCARD', key)
if current + cost > max_count then
  return {0, current}
end
for i = 1, cost do
  redis.call('ZADD', key, now, now .. '-' .. i .. '-' .. math.random(1, 1000000000))
end
redis.call('EXPIRE', key, window + 1)
return {1, current + cost}
"""

_REDIS_COUNT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cutoff = now - (window * 1000000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
return redis.call('ZCARD', key)
"""


class RedisRateLimiter:
    """Distributed sliding-window limiter using redis.asyncio + Lua atomicity.

    Falls back to a shared in-memory ``RateLimiter`` on any Redis exception
    so the SMTP server keeps enforcing limits even during Redis incidents.
    """

    def __init__(self, redis_url: str, max_count: int, window_seconds: int,
                 fallback: "RateLimiter") -> None:
        # Import lazily so the test suite — which mocks the whole module —
        # doesn't need redis installed in every environment.
        from redis import asyncio as _aredis  # type: ignore
        self._client = _aredis.from_url(
            redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )
        self.max_count = max_count
        self.window = window_seconds
        self._fallback = fallback
        self._allow_sha: str | None = None
        self._count_sha: str | None = None

    async def _ensure_scripts(self) -> None:
        if self._allow_sha is None:
            self._allow_sha = await self._client.script_load(_REDIS_LUA)
        if self._count_sha is None:
            self._count_sha = await self._client.script_load(_REDIS_COUNT_LUA)

    async def is_allowed(self, customer_id: str, cost: int = 1) -> bool:
        if cost < 1:
            cost = 1
        try:
            await self._ensure_scripts()
            now_us = int(time.time() * 1_000_000)
            result = await self._client.evalsha(
                self._allow_sha, 1,
                f"ratelimit:{customer_id}",
                now_us, self.window, self.max_count, cost,
            )
            return int(result[0]) == 1
        except Exception as exc:  # noqa: BLE001 — defensive fallback
            logger.warning(
                "Redis rate-limit check failed; falling back to in-memory",
                extra={"error": str(exc), "customer_id": customer_id},
            )
            return self._fallback._is_allowed_sync(customer_id, cost)

    async def current_count(self, customer_id: str) -> int:
        try:
            await self._ensure_scripts()
            now_us = int(time.time() * 1_000_000)
            result = await self._client.evalsha(
                self._count_sha, 1,
                f"ratelimit:{customer_id}",
                now_us, self.window,
            )
            return int(result)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Redis rate-limit count failed; falling back to in-memory",
                extra={"error": str(exc), "customer_id": customer_id},
            )
            return self._fallback._current_count_sync(customer_id)


REDIS_URL = os.environ.get("REDIS_URL", "").strip()


def _make_rate_limiter() -> "RateLimiter | RedisRateLimiter":
    """Pick the distributed limiter when REDIS_URL is set; otherwise in-memory."""
    memory = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)
    if not REDIS_URL:
        logger.info("Rate limiter: in-memory (REDIS_URL unset)")
        return memory
    try:
        rl = RedisRateLimiter(REDIS_URL, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW, memory)
        logger.info("Rate limiter: redis (sliding window, atomic via Lua)")
        return rl
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Failed to initialise RedisRateLimiter; using in-memory fallback",
            extra={"error": str(exc)},
        )
        return memory


_rate_limiter = _make_rate_limiter()

# ---------------------------------------------------------------------------
# Admin alerting (circuit breaker — only one alert per cooldown period)
# ---------------------------------------------------------------------------

_alert_cooldowns: dict[str, float] = {}
ALERT_COOLDOWN = 3600  # seconds between repeat alerts for the same key


# ---------------------------------------------------------------------------
# Cached SES client (Sprint C2 — audit F-05 / F-07)
#
# Previously every alert + every outbound email constructed a fresh
# boto3.client("ses"), which (a) does TLS handshakes and STS lookups on the
# hot path and (b) had no socket/connect timeouts — a slow SES endpoint
# could pin a thread for the default 60s and stall the SMTP server.
#
# We now build one client per process, with bounded timeouts and standard
# retries. boto3 clients are documented as thread-safe for read-only ops
# like send_email/send_raw_email, so sharing across worker threads is OK.
# ---------------------------------------------------------------------------

_ses_client = None
_ses_client_lock = threading.Lock()


def _get_ses_client():
    """Return the process-wide cached boto3 SES client, building it on first use."""
    global _ses_client
    if _ses_client is not None:
        return _ses_client
    with _ses_client_lock:
        if _ses_client is None:
            _ses_client = boto3.client(
                "ses",
                region_name=AWS_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID or None,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY or None,
                config=BotoConfig(
                    connect_timeout=5,
                    read_timeout=10,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            )
    return _ses_client


def _send_admin_alert(subject: str, body: str, key: str = "default") -> None:
    """
    Send an SES email to the admin. Silently swallows errors.
    Rate-limited per `key` to avoid flooding.

    Sprint C2 (audit F-04 / F-05): the SES client is now cached at module
    scope (`_get_ses_client()`) with bounded connect/read timeouts so a
    stalled SES API call can't pin a thread forever. Call sites inside
    async handlers should use `_send_admin_alert_async` (below) to keep
    the network call off the SMTP event loop.
    """
    now = time.time()
    if now - _alert_cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return
    _alert_cooldowns[key] = now

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        logger.warning("Admin alert skipped — AWS credentials not configured", extra={"alert_subject": subject})
        return

    try:
        client = _get_ses_client()
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


async def _send_admin_alert_async(subject: str, body: str, key: str = "default") -> None:
    """Async wrapper — offload SES alert to a worker thread so the SMTP
    event loop doesn't stall on boto3's blocking HTTP call. Use from any
    async handler; falls through to a no-op fast path when the cooldown
    is active (cheap, runs inline)."""
    now = time.time()
    if now - _alert_cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return
    await asyncio.to_thread(_send_admin_alert, subject, body, key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FQDN_RE = _stdlib_re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Z0-9-]{1,63}(?<!-))+$",
    _stdlib_re.IGNORECASE,
)


def _extract_domain(address: str) -> str:
    """Return the domain part of an email address, lowercased.

    S-M8 — hardened version. The previous implementation used a raw
    ``str.split("@", 1)`` which happily accepted multi-@ addresses, addresses
    with whitespace embedded inside the local-part, addresses whose "domain"
    was a bare label (``user@localhost``) and quoted local-parts
    (``"a@b"@evil.com``). Any of those allowed an attacker to spoof the
    domain the rest of the pipeline (rule lookup, SPF, From-domain bind)
    operated on. We now:

      * Strip RFC-5321 angle brackets and surrounding whitespace.
      * Parse via ``email.utils.parseaddr`` so quoted local-parts are honored.
      * Require exactly one ``@`` outside the (already-parsed) local-part.
      * Require the domain to match an FQDN (≥1 dot, ≤253 chars, labels
        ≤63 chars, no leading/trailing hyphen).

    An empty string is returned for inputs that do not satisfy the rules; the
    caller must treat ``""`` as "reject".
    """
    if not address:
        return ""
    address = address.strip().strip("<>").strip()
    if not address:
        return ""
    # parseaddr handles quoted local-parts: parseaddr('"a@b"@x.com') -> ('','"a@b"@x.com')
    _, parsed = email_utils.parseaddr(address)
    if not parsed or "@" not in parsed:
        return ""
    # Split from the right so quoted local-parts containing '@' stay intact.
    local, _, domain = parsed.rpartition("@")
    if not local or not domain:
        return ""
    domain = domain.lower().rstrip(".")
    if not _FQDN_RE.match(domain):
        return ""
    return domain


# ---------------------------------------------------------------------------
# S-H1 — SPF check for port-25 inbound traffic
# ---------------------------------------------------------------------------
#
# Even with a strict peer-IP allowlist, a trusted relay (e.g. Google's MTA)
# will happily forward mail with a spoofed MAIL FROM if the upstream tenant
# is compromised or misconfigured. SPF gives us a per-message check: does
# the *peer IP we're talking to* appear in the SPF record of the MAIL FROM
# domain? If the domain publishes SPF and the answer is `fail`, that's a
# verified forgery and we drop it.
#
# Policy:
#   * `pass`     → allow (logged at INFO).
#   * `none`     → allow. Domain didn't publish SPF; nothing to verify.
#   * `neutral`  → allow. Domain explicitly opted out of asserting anything.
#   * `softfail` → allow but log a warning (some legitimate relays still
#                  produce softfail; alerting is more useful than rejecting).
#   * `fail`     → REJECT with 550. This is a verified forgery.
#   * `temperror`→ allow (fail-open on DNS hiccups; otherwise a flaky
#                  resolver becomes a DoS vector for legitimate mail).
#   * `permerror`→ allow but log a warning (domain has a broken SPF record;
#                  not our job to police that).
#
# Setting SPF_ENFORCE=0 disables the check (kill-switch). Default ON in
# production because the peer-IP allowlist already restricts the surface;
# SPF is purely defense-in-depth on top of that.

import spf as _spf  # pyspf

SPF_ENFORCE = os.environ.get("SPF_ENFORCE", "1") not in ("0", "false", "False", "")


def _check_spf_sync(peer_ip: str, mail_from: str, helo: str) -> tuple[str, str]:
    """Synchronous SPF lookup. Returns (result, explanation).

    Wrapped via asyncio.to_thread by the async caller so the event loop is
    never blocked by DNS.
    """
    try:
        result, explanation = _spf.check2(i=peer_ip, s=mail_from, h=helo or "unknown")
        return str(result or "").lower(), str(explanation or "")
    except Exception as exc:  # pragma: no cover - defensive
        return "temperror", f"spf-check raised: {exc}"


async def _check_spf(peer_ip: str, mail_from: str, helo: str) -> tuple[str, str]:
    """Async wrapper around pyspf. Returns ("", "") if SPF_ENFORCE is off."""
    if not SPF_ENFORCE:
        return ("", "")
    if not mail_from or not peer_ip or peer_ip == "unknown":
        return ("none", "missing peer or sender")
    try:
        ipaddress.ip_address(peer_ip)
    except ValueError:
        return ("none", "peer not an IP literal")
    return await asyncio.to_thread(_check_spf_sync, peer_ip, mail_from, helo)


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
    async with aiohttp.ClientSession(headers=_internal_headers()) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status in (404, 403):
                return None
            resp.raise_for_status()
            return await resp.json()


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
    }
    try:
        async with aiohttp.ClientSession(headers=_internal_headers()) as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status not in (200, 201):
                    # S-L2: don't ingest backend tracebacks into our stdout.
                    # Status code is enough to alert on; full body stays server-side.
                    snippet = (await resp.text())[:200]
                    logger.error(
                        "scan-log POST failed",
                        extra={"status": resp.status, "body_snippet": snippet},
                    )
    except Exception as exc:
        logger.error("Failed to post scan log", extra={"error": str(exc)})


def _forward_via_ses(
    raw_message: bytes,
    mail_from: str,
    rcpt_tos: list[str],
    customer_id: str | None = None,
) -> None:
    """Send raw email via AWS SES (synchronous boto3 call).

    Sprint B C16: we tag every send with the originating customer_id so SES
    bounce/complaint notifications carry it back to the webhook handler, which
    scopes suppression entries to that customer.

    Sprint C2 (audit F-05 / F-07): now uses the cached, timeout-bounded SES
    client from `_get_ses_client()`; no per-call boto3 client construction.
    """
    client = _get_ses_client()
    kwargs = {
        "Source": mail_from,
        "Destinations": rcpt_tos,
        "RawMessage": {"Data": raw_message},
    }
    if SES_SOURCE_ARN:
        kwargs["SourceArn"] = SES_SOURCE_ARN
    if customer_id:
        # SES Tags: ASCII, [A-Za-z0-9_-] only, ≤256 chars. UUIDs satisfy this.
        kwargs["Tags"] = [{"Name": "customer_id", "Value": str(customer_id)}]
    client.send_raw_email(**kwargs)


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Brute-force tracker (S-M2)
# ---------------------------------------------------------------------------
#
# Per-peer-IP failure counter with exponential backoff and temporary ban.
# Counter resets on a successful AUTH from that peer. State is in-memory
# (one process per SMTP container today); a Redis-backed implementation
# can replace this without touching call sites (S-M6 will generalize the
# rate-limit pattern).
#
# Defaults: after the 5th consecutive failure we start applying backoff
# (1s, 2s, 4s, 8s, 16s, ...) up to BRUTE_BACKOFF_MAX_SECONDS, and after
# BRUTE_BAN_THRESHOLD failures we reject AUTH outright for BRUTE_BAN_SECONDS.
#
# IP allow/deny list (S-M7) also lives here so the connect-time gate has a
# single source of truth.

BRUTE_BACKOFF_START = int(os.environ.get("BRUTE_BACKOFF_START", "5"))
BRUTE_BACKOFF_MAX_SECONDS = int(os.environ.get("BRUTE_BACKOFF_MAX_SECONDS", "30"))
BRUTE_BAN_THRESHOLD = int(os.environ.get("BRUTE_BAN_THRESHOLD", "20"))
BRUTE_BAN_SECONDS = int(os.environ.get("BRUTE_BAN_SECONDS", "900"))  # 15 min


class BruteForceTracker:
    """
    Tracks failed AUTH attempts per peer IP. Thread-safe under asyncio
    (single-threaded event loop) and across handler tasks.
    """
    def __init__(self):
        # ip -> {"fails": int, "banned_until": float}
        self._state: dict[str, dict] = {}
        self._lock = threading.Lock()

    def banned_until(self, ip: str) -> float:
        with self._lock:
            entry = self._state.get(ip)
            if not entry:
                return 0.0
            ban = entry.get("banned_until", 0.0)
            if ban and ban <= time.time():
                # Ban expired — clear it but keep the failure count so a
                # repeat offender re-enters backoff quickly.
                entry["banned_until"] = 0.0
                return 0.0
            return ban

    def backoff_seconds(self, ip: str) -> float:
        """How long this peer should wait before its next AUTH attempt."""
        with self._lock:
            fails = self._state.get(ip, {}).get("fails", 0)
        if fails < BRUTE_BACKOFF_START:
            return 0.0
        # Exponential: 1s after BACKOFF_START, doubling each failure.
        delay = float(1 << min(fails - BRUTE_BACKOFF_START, 10))
        return min(delay, float(BRUTE_BACKOFF_MAX_SECONDS))

    def record_failure(self, ip: str) -> None:
        with self._lock:
            entry = self._state.setdefault(ip, {"fails": 0, "banned_until": 0.0})
            entry["fails"] += 1
            if entry["fails"] >= BRUTE_BAN_THRESHOLD:
                entry["banned_until"] = time.time() + BRUTE_BAN_SECONDS
                logger.warning(
                    "Peer banned for brute-force AUTH",
                    extra={"peer": ip, "fails": entry["fails"], "ban_seconds": BRUTE_BAN_SECONDS},
                )

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._state.pop(ip, None)


_brute = BruteForceTracker()


# ---------------------------------------------------------------------------
# Connect-time IP ACL (S-M7)
# ---------------------------------------------------------------------------
#
# Optional deny/allow lists evaluated in connection_made() — we close the
# socket before any SMTP banner is emitted, so attackers don't even learn
# the server identity. Default allow-list is empty (i.e. allow all);
# default deny-list is empty. Operators set:
#   SMTP_DENY_CIDRS="1.2.3.0/24,5.6.0.0/16"
#   SMTP_ALLOW_CIDRS="" (empty = allow all that aren't denied)
# Port-25 still has its own allowlist enforced inside handle_DATA — this
# ACL is a defense-in-depth layer for both ports.

def _parse_cidr_list(raw: str) -> list:
    out = []
    for c in (raw or "").split(","):
        c = c.strip()
        if not c:
            continue
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError as exc:
            logger.warning("Ignoring invalid CIDR in ACL", extra={"cidr": c, "error": str(exc)})
    return out


_SMTP_DENY_NETWORKS = _parse_cidr_list(os.environ.get("SMTP_DENY_CIDRS", ""))
_SMTP_ALLOW_NETWORKS = _parse_cidr_list(os.environ.get("SMTP_ALLOW_CIDRS", ""))


def _ip_allowed_by_acl(peer) -> tuple[bool, str]:
    """
    Returns (allowed, reason). Reason is for logging only.
    Allowlist (if set) wins: only listed IPs may connect.
    Denylist always rejects, even if also in allowlist.
    """
    if not peer:
        return True, "no_peer"
    try:
        ip = ipaddress.ip_address(peer[0])
    except (ValueError, IndexError):
        # Unknown peer format — don't accidentally close a unix socket etc.
        return True, "unparseable_peer"
    for net in _SMTP_DENY_NETWORKS:
        if ip in net:
            return False, f"deny:{net}"
    if _SMTP_ALLOW_NETWORKS:
        for net in _SMTP_ALLOW_NETWORKS:
            if ip in net:
                return True, f"allow:{net}"
        return False, "not_in_allowlist"
    if _brute.banned_until(str(ip)) > 0:
        return False, "brute_force_ban"
    return True, "default_allow"


# ---------------------------------------------------------------------------
# Authenticator (S-M1, S-M2)
# ---------------------------------------------------------------------------

class Authenticator:
    """
    Authenticates SMTP clients by verifying credentials against the backend
    /internal/smtp-auth endpoint. Password is sealed (AES-256-GCM, S-H4) on
    the wire — plaintext never leaves this process.

    S-M1: the heavy lifting (HKDF seal + HTTP call) runs inside
    `verify_async()`, which uses an aiohttp session so the event loop is
    never blocked. The aiosmtpd `authenticator` hook is sync, so we expose
    `__call__` as a thin shim that schedules the coroutine — but the SMTP
    subclass below (`SafeSenderSMTP`) overrides `auth_PLAIN` / `auth_LOGIN`
    to await `verify_async()` directly. The sync `__call__` remains for
    any caller that bypasses our SMTP subclass.

    S-M2: per-peer-IP brute-force protection is enforced here. On failure
    we record + apply exponential backoff (asyncio.sleep, not blocking).
    On the BRUTE_BAN_THRESHOLD-th failure the peer is banned for
    BRUTE_BAN_SECONDS — subsequent AUTH attempts return 535 immediately
    until the ban expires.
    """

    _BACKEND_TIMEOUT = aiohttp.ClientTimeout(total=5)

    @staticmethod
    def _decode(value) -> str:
        return value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else value

    @staticmethod
    def _user_hash(username: str) -> str:
        return hashlib.sha256(username.encode("utf-8", "replace")).hexdigest()[:16]

    async def verify_async(self, session, auth_data) -> AuthResult:
        peer = getattr(session, "peer", None)
        peer_ip = peer[0] if peer else "unknown"

        # --- S-M2: pre-check ban + apply backoff -----------------------
        ban_until = _brute.banned_until(peer_ip)
        if ban_until > 0:
            logger.warning(
                "AUTH rejected — peer is brute-force banned",
                extra={"peer": peer_ip, "ban_remaining": int(ban_until - time.time())},
            )
            return AuthResult(success=False, handled=True, message="535 5.7.8 Too many failed attempts; try again later")
        delay = _brute.backoff_seconds(peer_ip)
        if delay > 0:
            logger.info("AUTH backoff", extra={"peer": peer_ip, "delay_s": delay})
            await asyncio.sleep(delay)

        if not isinstance(auth_data, LoginPassword):
            _brute.record_failure(peer_ip)
            return AuthResult(success=False, handled=True)

        username = self._decode(auth_data.login)
        password = self._decode(auth_data.password)

        # --- S-H4: seal password ---------------------------------------
        try:
            auth_blob = seal_password(username, password)
        except Exception as exc:
            logger.error("Failed to seal SMTP auth payload", extra={"error": str(exc)})
            return AuthResult(success=False, handled=True, message="451 4.7.0 Auth backend unavailable")

        # --- Backend call (fully async, no event-loop block) -----------
        url = f"{BACKEND_URL}/internal/smtp-auth"
        try:
            async with aiohttp.ClientSession(headers=_INTERNAL_HEADERS, timeout=self._BACKEND_TIMEOUT) as http:
                async with http.post(
                    url,  # nosemgrep: python.lang.security.audit.insecure-transport
                    json={"v": WIRE_VERSION, "username": username, "auth_blob": auth_blob},
                ) as resp:
                    status = resp.status
                    if status == 200:
                        result = await resp.json()
                    else:
                        result = None
        except Exception as exc:
            logger.error("Auth backend unreachable", extra={"error": str(exc)})
            return AuthResult(success=False, handled=True, message="451 4.7.0 Auth backend unavailable")

        if status != 200 or not isinstance(result, dict):
            _brute.record_failure(peer_ip)
            logger.warning(
                "AUTH failed",
                extra={"user_hash": self._user_hash(username), "status": status, "peer": peer_ip},
            )
            return AuthResult(success=False, handled=True)

        _brute.record_success(peer_ip)
        session.smtp_customer_id = result.get("customer_id")
        session.smtp_domain = result.get("domain")
        session.smtp_admin = result.get("admin", False)
        return AuthResult(success=True)

    def __call__(self, server, session, envelope, mechanism, auth_data):
        # Legacy sync entrypoint — used only if SafeSenderSMTP isn't in
        # play. Run the async verify on a fresh loop in a worker thread so
        # we never block the current event loop.
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
        coro = self.verify_async(session, auth_data)
        if loop is None or not loop.is_running():
            return asyncio.run(coro)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()


# ---------------------------------------------------------------------------
# SMTP subclass: native async auth + connect-time ACL (S-M1, S-M7)
# ---------------------------------------------------------------------------

class SafeSenderSMTP(SMTPServer):
    """
    aiosmtpd ships `_authenticate` as sync — credentials get verified on the
    event loop. Override `auth_PLAIN` / `auth_LOGIN` so the backend HTTP
    call can be awaited natively. Also override `connection_made` to drop
    banned / denylisted peers before the banner is sent.
    """

    _authenticator: "Authenticator | None"

    def connection_made(self, transport):  # type: ignore[override]
        peer = transport.get_extra_info("peername") if transport else None
        allowed, reason = _ip_allowed_by_acl(peer)
        if not allowed:
            logger.warning(
                "Connection rejected by ACL",
                extra={"peer": peer[0] if peer else "unknown", "reason": reason},
            )
            try:
                transport.close()
            except Exception:
                pass
            return
        super().connection_made(transport)

    async def auth_PLAIN(self, _, args):  # type: ignore[override]
        if len(args) == 1:
            blob = await self.challenge_auth("")
            if blob is MISSING:
                return AuthResult(success=False)
        else:
            try:
                blob = b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        try:
            _, login, password = blob.split(b"\x00")
        except ValueError:
            await self.push("501 5.5.2 Can't split auth value")
            return AuthResult(success=False, handled=True)
        if self._authenticator is None:
            return AuthResult(success=False, handled=True)
        return await self._authenticator.verify_async(self.session, LoginPassword(login, password))

    async def auth_LOGIN(self, _, args):  # type: ignore[override]
        if len(args) == 1:
            login = await self.challenge_auth(self.AuthLoginUsernameChallenge)
            if login is MISSING:
                return AuthResult(success=False)
        else:
            try:
                login = b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        password = await self.challenge_auth(self.AuthLoginPasswordChallenge)
        if password is MISSING:
            return AuthResult(success=False)
        if self._authenticator is None:
            return AuthResult(success=False, handled=True)
        return await self._authenticator.verify_async(self.session, LoginPassword(login, password))


class SafeSenderController(Controller):
    """Controller that produces SafeSenderSMTP instances."""
    def factory(self):
        return SafeSenderSMTP(self.handler, **self.SMTP_kwargs)


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
        # F-48: mint a correlation id per SMTP transaction. Anything inside
        # this coroutine (helpers, aiohttp calls, log lines) can pick it
        # up via _current_request_id().
        _request_id_ctx.set(_uuid.uuid4().hex)
        mail_from: str = envelope.mail_from or ""
        rcpt_tos: list[str] = envelope.rcpt_tos
        raw_content: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()

        domain = _extract_domain(mail_from)
        peer_ip = session.peer[0] if session.peer else "unknown"
        # S-L1: log recipient *count* and domain only, never full addresses.
        logger.info(
            "Incoming email",
            extra={
                "port": self.port,
                "peer": peer_ip,
                "domain": domain,
                "rcpt_count": len(rcpt_tos),
            },
        )

        # --- Port-specific access control ------------------------------------
        if self.port == 25:
            if not self._peer_allowed_on_port25(session.peer):
                logger.warning(
                    "Port 25 connection from non-allowlisted IP — rejected",
                    extra={"peer": peer_ip, "domain": domain},
                )
                return "550 5.7.1 Connections only accepted from authorized relay IPs"
            # S-M9: even from a trusted relay IP, MAIL FROM must parse to a
            # real sender domain before we pass it to SES as Source=. Empty
            # or malformed addresses get rejected here so SES never sees
            # them and we don't accidentally tag an SES send with a bogus
            # Source that could trigger SES sandbox / reputation flags.
            if not domain or "." not in domain:
                logger.warning(
                    "Port 25: malformed MAIL FROM — rejected",
                    extra={"peer": peer_ip, "domain": domain},
                )
                return "550 5.1.7 Malformed sender address"
            # S-H1: SPF check on the MAIL FROM domain. Even though peer_ip
            # is already on the port-25 allowlist, SPF tells us whether
            # *this peer* is actually authorized to send for *this domain*.
            # A `fail` is a verified forgery; everything else is allowed
            # (with appropriate logging). See helper docstring for policy.
            helo = getattr(session, "host_name", "") or ""
            spf_result, spf_reason = await _check_spf(peer_ip, mail_from, helo)
            if spf_result == "fail":
                logger.warning(
                    "Port 25: SPF fail — rejected as spoofed",
                    extra={
                        "peer": peer_ip,
                        "domain": domain,
                        "spf": spf_result,
                        "spf_reason": spf_reason,
                    },
                )
                return "550 5.7.23 SPF check failed — sender not authorized"
            if spf_result in ("softfail", "permerror"):
                logger.warning(
                    "Port 25: SPF non-pass (allowed)",
                    extra={
                        "peer": peer_ip,
                        "domain": domain,
                        "spf": spf_result,
                        "spf_reason": spf_reason,
                    },
                )
            elif spf_result:
                logger.info(
                    "Port 25: SPF check",
                    extra={"peer": peer_ip, "domain": domain, "spf": spf_result},
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

        # --- 2. Rate limiting (S-M5: cost = recipient count) ---
        rcpt_cost = max(1, len(rcpt_tos))
        if not await _rate_limiter.is_allowed(customer_id, cost=rcpt_cost):
            count = await _rate_limiter.current_count(customer_id)
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
                    "domain": domain,
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
            )
            return "550 5.7.1 Message rejected: policy violation"

        # Forward via SES
        # --- Suppression check ---
        # S-I3: each suppressed recipient gets its own scan-log row, not just rcpt[0].
        for rcpt in rcpt_tos:
            if await _is_suppressed(customer_id, rcpt):
                # S-L1: don't log the recipient address itself.
                logger.info(
                    "Suppressed recipient — email blocked",
                    extra={"domain": domain, "customer_id": customer_id},
                )
                await _log_scan(
                    customer_id=customer_id,
                    sender=mail_from,
                    recipient=rcpt,
                    subject_hash=subject_hash,
                    matched_rule_id=None,
                    outcome="blocked",
                )
                return "550 5.1.8 Recipient address suppressed due to prior bounce or complaint"

        try:
            # S-I2: get_event_loop() is deprecated in 3.12 when no running loop
            # exists. Inside an async handler we always have one — use the
            # canonical accessor.
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, _forward_via_ses, raw_content, mail_from, rcpt_tos, customer_id
            )
            # S-L1: never log raw sender address.
            logger.info("Email forwarded via SES", extra={"domain": domain, "customer_id": customer_id})
        except Exception as exc:
            logger.error(
                "SES send failed",
                extra={"error": str(exc), "domain": domain, "customer_id": customer_id},
            )
            await _send_admin_alert_async(
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
            )
            return "451 4.3.0 Delivery failure — please retry"

        await _log_scan(
            customer_id=customer_id,
            sender=mail_from,
            recipient=recipient,
            subject_hash=subject_hash,
            matched_rule_id=None,
            outcome="allowed",
        )
        return "250 OK"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _drop_privileges() -> None:
    """S-M3 — drop from root to the unprivileged 'app' account.

    Called *after* the SMTP controllers have bound their privileged ports
    and the TLS SSLContext has loaded the private key into memory. The
    long-lived asyncio loop then runs as uid/gid 10001 with no ability
    to re-read /etc/letsencrypt or write to system paths inside the
    container. If we aren't root we no-op (e.g. local dev, or a future
    rootless container runtime that already drops us).
    """
    import pwd

    if os.geteuid() != 0:
        logger.info("Privilege drop skipped (not root)", extra={"uid": os.geteuid()})
        return

    target_user = os.environ.get("SMTP_RUNTIME_USER", "app")
    try:
        pw = pwd.getpwnam(target_user)
    except KeyError:
        logger.critical(
            "SMTP_RUNTIME_USER not found; refusing to run as root",
            extra={"user": target_user},
        )
        raise SystemExit(1)

    # Order matters: groups -> gid -> uid. setuid first would lose the
    # right to setgid.
    try:
        os.setgroups([pw.pw_gid])
    except PermissionError:
        # Not all containers grant CAP_SETGID for supplementary groups; the
        # primary gid switch below is what actually matters.
        pass
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)

    # Defence-in-depth: if any of the calls silently no-op'd we want a
    # loud failure, not a long-running root process.
    if os.geteuid() == 0 or os.getegid() == 0:
        logger.critical("Privilege drop failed; aborting")
        raise SystemExit(1)

    logger.info(
        "Dropped privileges",
        extra={"uid": pw.pw_uid, "gid": pw.pw_gid, "user": target_user},
    )


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
        # S-L8: pin TLS 1.2 floor explicitly. create_default_context already
        # disables SSLv2/v3 + TLS 1.0/1.1, but be explicit so a future OpenSSL
        # default shift can't quietly downgrade us.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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
    # S-M4: cap envelope size at 25 MB (Gmail's outbound limit). aiosmtpd
    # forwards this to the SMTP server which will refuse oversized DATA
    # before we ever allocate the body.
    SMTP_DATA_SIZE_LIMIT = int(os.environ.get("SMTP_DATA_SIZE_LIMIT", str(25 * 1024 * 1024)))
    controller587 = SafeSenderController(
        handler587,
        hostname="0.0.0.0",  # nosec B104 - SMTP server must bind all container interfaces; exposure controlled by Docker port mapping + Hetzner firewall
        port=587,
        authenticator=authenticator,
        auth_required=True,
        auth_require_tls=True,
        require_starttls=True,
        tls_context=ssl_context,
        data_size_limit=SMTP_DATA_SIZE_LIMIT,
    )
    controller587.start()
    logger.info(
        "Safe Sender SMTP started (port 587, AUTH required, TLS enforced)",
        extra={"port": 587, "rate_limit_max": RATE_LIMIT_MAX, "rate_limit_window": RATE_LIMIT_WINDOW},
    )

    # Port 25 - MTA-to-MTA inbound from Google Workspace SMTP relay.
    # No SMTP-AUTH (peer-IP allowlist enforced inside handle_DATA).
    #
    # S-H2: opportunistic STARTTLS. We advertise STARTTLS using the same
    # cert/key as port 587 but do NOT require it (require_starttls=False).
    # Why opportunistic and not mandatory: MTA-to-MTA on port 25 follows
    # RFC 3207 — sending MTAs that don't support STARTTLS would be hard-
    # bounced if we required it. Google's SMTP relay always negotiates
    # STARTTLS when offered, so for our actual peers this becomes de-facto
    # TLS-only without breaking mail from any future allowlisted peer that
    # might not support it.
    handler25 = SafeSenderHandler(port=25)
    controller25 = SafeSenderController(
        handler25,
        hostname="0.0.0.0",  # nosec B104 - SMTP server must bind all container interfaces; exposure controlled by Docker port mapping + Hetzner firewall
        port=25,
        auth_required=False,
        auth_require_tls=False,
        require_starttls=False,
        tls_context=ssl_context,  # S-H2: opportunistic STARTTLS
        data_size_limit=SMTP_DATA_SIZE_LIMIT,  # S-M4
    )
    controller25.start()
    logger.info(
        "Safe Sender SMTP started (port 25, no AUTH, peer-IP allowlist, opportunistic STARTTLS)",
        extra={"port": 25, "allowed_networks": len(_PORT25_NETWORKS), "starttls": "opportunistic"},
    )

    # S-M3 — drop privileges. Sockets 25/587 are bound and the TLS private
    # key is already loaded into the SSLContext above, so the long-lived
    # process no longer needs root. We refuse to start if we're somehow
    # still root after the drop (defence against a misconfigured image).
    _drop_privileges()


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

        # S-I2: use new_event_loop() at module-entry where there is no
        # running loop yet. asyncio.get_event_loop() emits a DeprecationWarning
        # in 3.12 in that situation.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_start_health())
        loop.run_forever()
    except KeyboardInterrupt:
        controller587.stop()
        controller25.stop()
        logger.info("SMTP server stopped")