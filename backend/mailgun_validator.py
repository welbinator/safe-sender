"""
Mailgun webhook signature validator.

Mailgun signs every webhook POST with HMAC-SHA256:
  token     = random nonce (prevents replay)
  timestamp = Unix timestamp (seconds)
  signature = hmac_sha256(signing_key, timestamp + token)

Spec: https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/#webhooks

Security:
  - Signature verified with HMAC-SHA256 using MAILGUN_WEBHOOK_SIGNING_KEY.
  - Timestamp must be within TIMESTAMP_TOLERANCE_SECS of now (replay protection).
  - Tokens are single-use: stored in a short TTL cache to prevent replay.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)

TIMESTAMP_TOLERANCE_SECS = 300  # 5 minutes
_TOKEN_CACHE_MAX = 10_000       # max unique tokens to remember


class MailgunValidationError(Exception):
    """Raised when a Mailgun webhook fails validation."""


# LRU-ish token replay cache: {token: seen_at}
_seen_tokens: OrderedDict[str, float] = OrderedDict()


def _evict_expired(now: float) -> None:
    """Remove tokens older than TIMESTAMP_TOLERANCE_SECS * 2."""
    cutoff = now - TIMESTAMP_TOLERANCE_SECS * 2
    while _seen_tokens:
        token, seen_at = next(iter(_seen_tokens.items()))
        if seen_at < cutoff:
            _seen_tokens.popitem(last=False)
        else:
            break


def verify_mailgun_webhook(
    timestamp: str,
    token: str,
    signature: str,
    signing_key: str,
) -> None:
    """
    Raise MailgunValidationError if the webhook fails any check.
    Returns None on success.
    """
    if not signing_key:
        raise MailgunValidationError("MAILGUN_WEBHOOK_SIGNING_KEY not configured")

    # 1. Timestamp freshness
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        raise MailgunValidationError(f"Invalid timestamp: {timestamp!r}")
    now = time.time()
    if abs(now - ts) > TIMESTAMP_TOLERANCE_SECS:
        raise MailgunValidationError(
            f"Timestamp out of tolerance: {ts} vs now {int(now)}"
        )

    # 2. Replay protection
    _evict_expired(now)
    if token in _seen_tokens:
        raise MailgunValidationError("Token already seen (replay attempt)")
    if len(_seen_tokens) >= _TOKEN_CACHE_MAX:
        _seen_tokens.popitem(last=False)
    _seen_tokens[token] = now

    # 3. HMAC-SHA256 signature
    expected = hmac.new(
        signing_key.encode("utf-8"),
        msg=(timestamp + token).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise MailgunValidationError("Signature verification failed")
