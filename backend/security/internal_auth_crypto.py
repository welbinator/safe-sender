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
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WIRE_VERSION = 1
MAX_AGE_SECONDS = 60  # reject blobs older than this (replay window)
_HKDF_INFO = b"sendersafety/smtp-auth/v1"
_AAD_PREFIX = b"v1|"


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
    pw = payload["p"]
    if not isinstance(pw, str):
        raise ValueError("auth_blob password field not a string")
    return pw


__all__ = ["seal_password", "open_password", "WIRE_VERSION", "MAX_AGE_SECONDS"]
