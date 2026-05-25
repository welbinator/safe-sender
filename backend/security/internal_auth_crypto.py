"""
S-H4 — wire-encryption for the SMTP→backend internal-auth hop.

The SMTP gateway forwards user-supplied SASL credentials to the backend over
the docker network. Historically the body was JSON `{"username":..,"password":..}`
in cleartext, mitigated only by `X-Internal-Secret` (which authenticates the
*caller* but does not encrypt the *payload*).

This module wraps the password (and a unix timestamp, to bind freshness) in
AES-256-GCM using a key derived from `INTERNAL_SHARED_SECRET` via HKDF-SHA256.
Both the SMTP container and the backend container import the same logic. The
backend rejects blobs older than `MAX_AGE_SECONDS` to prevent replay.

Wire format (request body, JSON):
    {
        "v": 1,
        "username": "alice@example.com",
        "auth_blob": "<urlsafe-b64( nonce(12) || ciphertext || tag(16) )>"
    }

AAD binds the username + version, so an intercepted blob cannot be replayed
against a different account or downgraded to a future schema.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from collections import OrderedDict
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WIRE_VERSION = 1
MAX_AGE_SECONDS = 60  # reject blobs older than this (replay window)
_HKDF_INFO = b"sendersafety/smtp-auth/v1"
_AAD_PREFIX = b"v1|"

# ---------------------------------------------------------------------------
# M-5 nonce replay cache — prevents a passively-observed valid blob from
# being re-used within the 60 s freshness window.
# ---------------------------------------------------------------------------
# LRU bounded at 2× peak-QPS × MAX_AGE_SECONDS (generous headroom).
# Single-process in-memory is sufficient until backend is horizontally scaled;
# at that point, migrate to Redis SETNX EX 60 (same migration as M-2).
_REPLAY_CACHE_MAX = 2000  # at 60 s window, this supports ~33 auths/sec sustained
_seen_nonces: OrderedDict[bytes, int] = OrderedDict()  # nonce → expiry timestamp


def _check_and_record_nonce(nonce: bytes, expiry: int) -> bool:
    """Return True if nonce is fresh/unseen, False if it's a replay."""
    now = int(time.time())
    # Evict expired entries (keep cache bounded without a background task).
    # Iterate a snapshot so we can mutate while iterating.
    for k, exp in list(_seen_nonces.items()):
        if exp <= now:
            _seen_nonces.pop(k, None)
        else:
            break  # OrderedDict insertion order == arrival order; rest are newer
    if nonce in _seen_nonces:
        return False
    _seen_nonces[nonce] = expiry
    # Hard cap: drop the oldest entry if we exceed the limit.
    while len(_seen_nonces) > _REPLAY_CACHE_MAX:
        _seen_nonces.popitem(last=False)
    return True


def _derive_key(shared_secret: str) -> bytes:
    if not shared_secret:
        raise ValueError("INTERNAL_SHARED_SECRET is not set")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    )
    return hkdf.derive(shared_secret.encode("utf-8"))


def _aad(username: str) -> bytes:
    return _AAD_PREFIX + username.encode("utf-8")


def seal_password(username: str, password: str, *, shared_secret: str | None = None) -> str:
    """Encrypt `password` + freshness timestamp. Returns urlsafe-b64 blob."""
    secret = shared_secret if shared_secret is not None else os.environ.get("INTERNAL_SHARED_SECRET", "")
    key = _derive_key(secret)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps({"p": password, "ts": int(time.time())}).encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext, _aad(username))
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def open_password(
    username: str,
    auth_blob: str,
    *,
    shared_secret: str | None = None,
    now: int | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
) -> str:
    """Decrypt blob produced by `seal_password`. Raises ValueError on any failure."""
    secret = shared_secret if shared_secret is not None else os.environ.get("INTERNAL_SHARED_SECRET", "")
    key = _derive_key(secret)
    try:
        raw = base64.urlsafe_b64decode(auth_blob.encode("ascii"))
    except Exception as exc:
        raise ValueError("malformed auth_blob") from exc
    if len(raw) < 12 + 16 + 1:
        raise ValueError("auth_blob too short")
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, _aad(username))
    except Exception as exc:
        raise ValueError("auth_blob decryption failed") from exc
    try:
        payload = json.loads(pt)
    except Exception as exc:
        raise ValueError("auth_blob payload not JSON") from exc
    if not isinstance(payload, dict) or "p" not in payload or "ts" not in payload:
        raise ValueError("auth_blob payload missing fields")
    ts = int(payload["ts"])
    current = now if now is not None else int(time.time())
    if current - ts > max_age_seconds:
        raise ValueError("auth_blob expired")
    if ts - current > max_age_seconds:
        raise ValueError("auth_blob from the future")
    # M-5: nonce replay check — reject reuse within the freshness window.
    expiry = ts + max_age_seconds
    if not _check_and_record_nonce(nonce, expiry):
        raise ValueError("auth_blob nonce already used (replay)")
    pw = payload["p"]
    if not isinstance(pw, str):
        raise ValueError("auth_blob password field not a string")
    return pw


# ---------------------------------------------------------------------------
# S-H3 — Test-connection token
# ---------------------------------------------------------------------------
#
# The SMTP gateway recognises `sendersafety-test@<domain>` as a test
# connection and bypasses DLP scanning. Without a signed token, any
# authenticated customer can use this local-part to inject `outcome=allowed`
# rows in their scan log and skip all rules. We require an HMAC token in the
# email subject, minted by the backend with `INTERNAL_SHARED_SECRET`. SMTP
# verifies before activating the bypass; on any failure the message falls
# through to normal scanning.

_TEST_TOKEN_INFO = b"sendersafety/test-token/v1"
TEST_TOKEN_MAX_AGE_SECONDS = 300  # 5 minutes


def _derive_test_token_key(shared_secret: str) -> bytes:
    if not shared_secret:
        raise ValueError("INTERNAL_SHARED_SECRET is not set")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_TEST_TOKEN_INFO,
    )
    return hkdf.derive(shared_secret.encode("utf-8"))


def mint_test_token(customer_id: str, *, shared_secret: str | None = None) -> str:
    """Return a base64url token: `<ts>.<hmac>` binding customer_id + ts."""
    import hmac as _hmac
    import hashlib

    secret = shared_secret if shared_secret is not None else os.environ.get("INTERNAL_SHARED_SECRET", "")
    key = _derive_test_token_key(secret)
    ts = int(time.time())
    msg = f"{customer_id}|{ts}".encode("utf-8")
    mac = _hmac.new(key, msg, hashlib.sha256).digest()
    raw = f"{ts}.".encode("ascii") + base64.urlsafe_b64encode(mac)
    return raw.decode("ascii")


def verify_test_token(
    token: str,
    customer_id: str,
    *,
    shared_secret: str | None = None,
    now: int | None = None,
    max_age_seconds: int = TEST_TOKEN_MAX_AGE_SECONDS,
) -> bool:
    """Constant-time verify a token from `mint_test_token`. Never raises."""
    import hmac as _hmac
    import hashlib

    try:
        if not isinstance(token, str) or "." not in token:
            return False
        ts_str, mac_b64 = token.split(".", 1)
        ts = int(ts_str)
    except Exception:
        return False
    current = now if now is not None else int(time.time())
    if current - ts > max_age_seconds:
        return False
    if ts - current > max_age_seconds:
        return False
    secret = shared_secret if shared_secret is not None else os.environ.get("INTERNAL_SHARED_SECRET", "")
    try:
        key = _derive_test_token_key(secret)
    except Exception:
        return False
    msg = f"{customer_id}|{ts}".encode("utf-8")
    expected = _hmac.new(key, msg, hashlib.sha256).digest()
    try:
        got = base64.urlsafe_b64decode(mac_b64.encode("ascii"))
    except Exception:
        return False
    return _hmac.compare_digest(expected, got)


__all__ = [
    "seal_password",
    "open_password",
    "WIRE_VERSION",
    "MAX_AGE_SECONDS",
    "mint_test_token",
    "verify_test_token",
    "TEST_TOKEN_MAX_AGE_SECONDS",
]
