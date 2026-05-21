"""
AWS SNS message signature validator.

Implements the AWS SNS HTTP/HTTPS notification verification flow:
  1. Host of SigningCertURL must match ^sns(\\.[a-z0-9-]+)?\\.amazonaws\\.com$
     (over HTTPS).
  2. Fetch the cert (cached per URL).
  3. Build the canonical string in the AWS-documented field order.
  4. Verify the base64-decoded `Signature` against the cert's public key
     using RSA + SHA1 (SignatureVersion=1) or RSA + SHA256 (=2).
  5. TopicArn must be in the operator-supplied allowlist.

Spec: https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
"""

from __future__ import annotations

import base64
import logging
import re
import time
import urllib.request
from typing import Iterable
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)

# Per AWS docs, signing host is always under amazonaws.com over HTTPS.
_SNS_HOST_RE = re.compile(r"^sns(\.[a-z0-9-]+)?\.amazonaws\.com$")

_NOTIFICATION_FIELDS = (
    "Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type",
)
_SUBSCRIPTION_FIELDS = (
    "Message", "MessageId", "SubscribeURL", "Timestamp", "Token",
    "TopicArn", "Type",
)

# (url) -> (cert_pem, fetched_at)
_CERT_CACHE: dict[str, tuple[bytes, float]] = {}
_CERT_TTL = 3600  # seconds


class SNSValidationError(Exception):
    """Raised when an SNS message fails validation."""


def _validate_signing_cert_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SNSValidationError(f"SigningCertURL must be https, got {parsed.scheme!r}")
    if not _SNS_HOST_RE.match(parsed.hostname or ""):
        raise SNSValidationError(f"SigningCertURL host not allowed: {parsed.hostname!r}")


def _fetch_cert(url: str) -> bytes:
    now = time.time()
    cached = _CERT_CACHE.get(url)
    if cached and now - cached[1] < _CERT_TTL:
        return cached[0]
    with urllib.request.urlopen(url, timeout=5) as resp:  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        pem = resp.read()
    _CERT_CACHE[url] = (pem, now)
    return pem


def _build_string_to_sign(msg: dict) -> bytes:
    msg_type = msg.get("Type", "")
    if msg_type == "Notification":
        fields = _NOTIFICATION_FIELDS
    elif msg_type in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
        fields = _SUBSCRIPTION_FIELDS
    else:
        raise SNSValidationError(f"Unknown SNS message Type: {msg_type!r}")

    parts: list[str] = []
    for f in fields:
        if f == "Subject" and "Subject" not in msg:
            continue  # Subject is optional for Notification
        if f not in msg:
            raise SNSValidationError(f"Missing required SNS field: {f}")
        parts.append(f)
        parts.append(str(msg[f]))
    # SNS canonical form: each name and value followed by a newline
    return ("\n".join(parts) + "\n").encode("utf-8")


def verify_sns_message(msg: dict, allowed_topic_arns: Iterable[str]) -> None:
    """
    Raise SNSValidationError if the message fails any check.
    Returns None on success.
    """
    topic_arn = msg.get("TopicArn", "")
    if topic_arn not in set(allowed_topic_arns):
        raise SNSValidationError(f"TopicArn not in allowlist: {topic_arn!r}")

    sig_b64 = msg.get("Signature", "")
    cert_url = msg.get("SigningCertURL", "")
    sig_version = msg.get("SignatureVersion", "1")
    if not sig_b64 or not cert_url:
        raise SNSValidationError("Missing Signature or SigningCertURL")

    _validate_signing_cert_url(cert_url)

    try:
        signature = base64.b64decode(sig_b64)
    except Exception as exc:
        raise SNSValidationError(f"Signature is not valid base64: {exc}")

    cert_pem = _fetch_cert(cert_url)
    cert = load_pem_x509_certificate(cert_pem)
    public_key = cert.public_key()

    string_to_sign = _build_string_to_sign(msg)

    if sig_version == "1":
        hash_alg = hashes.SHA1()  # nosec B303  # nosemgrep: python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    elif sig_version == "2":
        hash_alg = hashes.SHA256()
    else:
        raise SNSValidationError(f"Unsupported SignatureVersion: {sig_version!r}")

    try:
        public_key.verify(signature, string_to_sign, padding.PKCS1v15(), hash_alg)
    except InvalidSignature:
        raise SNSValidationError("Signature verification failed")


def validate_subscribe_url(url: str) -> None:
    """SubscribeURL must point at the same SNS host family over HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SNSValidationError(f"SubscribeURL must be https, got {parsed.scheme!r}")
    if not _SNS_HOST_RE.match(parsed.hostname or ""):
        raise SNSValidationError(f"SubscribeURL host not allowed: {parsed.hostname!r}")
