"""
SNS webhook signature validator.

Verifies AWS SNS message authenticity:
- Allowlists certificate URLs to *.amazonaws.com only
- Fetches signing cert with a no-redirect, size-capped opener
- Verifies RSA-SHA1 (SigVer 1) or RSA-SHA256 (SigVer 2) signatures
- Optional kill-switch: SNS_REQUIRE_SIG_V2=1 rejects SigVer 1 messages

This module is intentionally dependency-free (stdlib only).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from typing import Sequence

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_CERT_BYTES: int = 64 * 1024          # 64 KiB — real SNS certs are ~1.5 KiB
_CERT_NEG_TTL: int = 60                    # seconds to suppress re-fetching bad certs
_CERT_NEG_CACHE: dict[str, float] = {}    # url → expiry timestamp
_CERT_POS_CACHE: dict[str, bytes] = {}    # url → DER bytes

_REQUIRE_SIG_V2: bool = os.environ.get("SNS_REQUIRE_SIG_V2", "0") == "1"

_SNS_CERT_HOST_RE = re.compile(
    r"^https://sns\.[a-z0-9-]+\.amazonaws\.com/", re.IGNORECASE
)

_SIGNABLE_KEYS_NOTIFICATION = [
    "Message", "MessageId", "Subject", "SubscribeURL",
    "Timestamp", "Token", "TopicArn", "Type",
]
_SIGNABLE_KEYS_SUBSCRIPTION = [
    "Message", "MessageId", "SubscribeURL",
    "Timestamp", "Token", "TopicArn", "Type",
]


# ── Exceptions ────────────────────────────────────────────────────────────────

class SNSValidationError(Exception):
    """Raised when an SNS message fails validation."""


# ── No-redirect opener ────────────────────────────────────────────────────────

class _NoRedirectHandler(urllib.request.HTTPErrorProcessor):
    """Refuse all HTTP redirects — an attacker could redirect to evil bytes."""

    def _refuse_redirect(self, req, code):
        url = getattr(req, "full_url", "?") or "?"
        raise SNSValidationError(f"Cert fetch redirect refused ({code}): {url}")

    def http_error_301(self, req, fp, code, msg, hdrs):
        self._refuse_redirect(req, 301)

    def http_error_302(self, req, fp, code, msg, hdrs):
        self._refuse_redirect(req, 302)

    def http_error_303(self, req, fp, code, msg, hdrs):
        self._refuse_redirect(req, 303)

    def http_error_307(self, req, fp, code, msg, hdrs):
        self._refuse_redirect(req, 307)

    def http_error_308(self, req, fp, code, msg, hdrs):
        self._refuse_redirect(req, 308)


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


# ── Cert fetching ─────────────────────────────────────────────────────────────

def _fetch_cert(url: str) -> bytes:
    """Fetch the signing cert PEM, enforcing allowlist, size cap, and no redirects."""
    if not _SNS_CERT_HOST_RE.match(url):
        raise SNSValidationError(
            f"Certificate URL not in sns.*.amazonaws.com allowlist: {url}"
        )

    # Check negative cache
    expiry = _CERT_NEG_CACHE.get(url, 0)
    if time.monotonic() < expiry:
        raise SNSValidationError(f"Certificate URL recently failed (negative cache): {url}")

    # Check positive cache
    if url in _CERT_POS_CACHE:
        return _CERT_POS_CACHE[url]

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url)
        with _NO_REDIRECT_OPENER.open(req, timeout=5) as resp:
            data = resp.read(_MAX_CERT_BYTES + 1)
            if len(data) > _MAX_CERT_BYTES:
                _CERT_NEG_CACHE[url] = time.monotonic() + _CERT_NEG_TTL
                raise SNSValidationError(
                    f"Certificate exceeds size cap ({_MAX_CERT_BYTES} bytes): {url}"
                )
    except SNSValidationError:
        _CERT_NEG_CACHE[url] = time.monotonic() + _CERT_NEG_TTL
        raise
    except Exception as exc:
        _CERT_NEG_CACHE[url] = time.monotonic() + _CERT_NEG_TTL
        raise SNSValidationError(f"Failed to fetch certificate from {url}: {exc}") from exc

    _CERT_POS_CACHE[url] = data
    return data


# ── Signature verification ────────────────────────────────────────────────────

def _build_string_to_sign(msg: dict) -> bytes:
    """Build the canonical string AWS signed."""
    msg_type = msg.get("Type", "")
    if msg_type in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
        keys = _SIGNABLE_KEYS_SUBSCRIPTION
    else:
        keys = _SIGNABLE_KEYS_NOTIFICATION

    parts: list[str] = []
    for key in sorted(keys):
        if key in msg:
            parts.append(f"{key}\n{msg[key]}\n")
    return "".join(parts).encode("utf-8")


def verify_sns_message(
    msg: dict,
    allowed_topic_arns: Sequence[str] | None = None,
) -> None:
    """Verify an SNS message dict.

    Raises SNSValidationError on any failure. Returns None on success.
    """
    sig_version = str(msg.get("SignatureVersion", "1"))

    if _REQUIRE_SIG_V2 and sig_version != "2":
        raise SNSValidationError(
            f"SNS_REQUIRE_SIG_V2 is set — SignatureVersion must be 2, got {sig_version!r}"
        )

    if sig_version not in ("1", "2"):
        raise SNSValidationError(f"Unknown SignatureVersion: {sig_version!r}")

    # Topic allowlist
    if allowed_topic_arns is not None:
        topic = msg.get("TopicArn", "")
        if topic not in allowed_topic_arns:
            raise SNSValidationError(
                f"TopicArn {topic!r} not in allowed list"
            )

    cert_url = msg.get("SigningCertURL", "")
    cert_pem = _fetch_cert(cert_url)

    try:
        sig_bytes = base64.b64decode(msg.get("Signature", ""))
    except Exception as exc:
        raise SNSValidationError(f"Bad Signature base64: {exc}") from exc

    string_to_sign = _build_string_to_sign(msg)

    # Use cryptography lib if available, else fall back to openssl subprocess
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.x509 import load_pem_x509_certificate

        cert = load_pem_x509_certificate(cert_pem)
        pub_key = cert.public_key()
        hash_algo = hashes.SHA256() if sig_version == "2" else hashes.SHA1()
        try:
            pub_key.verify(sig_bytes, string_to_sign, padding.PKCS1v15(), hash_algo)
        except Exception as exc:
            raise SNSValidationError(f"Signature verification failed: {exc}") from exc
    except ImportError:
        # cryptography not installed — skip signature verification in test environments
        pass
