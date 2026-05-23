"""
S-H4: AES-GCM wire-encryption for SMTP→backend internal-auth payload.

These tests verify:
  - Round-trip seal/open preserves password
  - AAD binds username (intercept + replay against different user fails)
  - Replay outside max_age_seconds is rejected
  - Tampered ciphertext fails to decrypt
  - Wrong shared secret fails
  - Malformed blobs return ValueError, not crashes
"""
from __future__ import annotations

import base64
import time

import pytest


@pytest.fixture(autouse=True)
def _internal_secret(monkeypatch, client):
    # `client` ensures conftest seed env ran first, but we still pin our own
    # strong secret so tests are hermetic.
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "x" * 64)


def _api():
    """Lazy import — security/__init__ requires env to be set first."""
    from security.internal_auth_crypto import (
        MAX_AGE_SECONDS,
        WIRE_VERSION,
        open_password,
        seal_password,
    )
    return seal_password, open_password, WIRE_VERSION, MAX_AGE_SECONDS


def test_roundtrip_basic():
    seal, openp, *_ = _api()
    blob = seal("alice@example.com", "hunter2-correct-horse")
    assert openp("alice@example.com", blob) == "hunter2-correct-horse"


def test_roundtrip_unicode_and_long_password():
    seal, openp, *_ = _api()
    pw = "πάσσωορδ-" + "a" * 200 + "—🔐"
    blob = seal("用户@例.com", pw)
    assert openp("用户@例.com", blob) == pw


def test_aad_binds_username():
    seal, openp, *_ = _api()
    blob = seal("alice@example.com", "secret")
    with pytest.raises(ValueError, match="decryption"):
        openp("mallory@example.com", blob)


def test_expired_blob_rejected():
    seal, openp, _, MAX_AGE = _api()
    import security.internal_auth_crypto as mod

    real_time = mod.time.time
    mod.time.time = lambda: real_time() - (MAX_AGE + 5)
    try:
        blob = seal("alice", "pw")
    finally:
        mod.time.time = real_time
    with pytest.raises(ValueError, match="expired"):
        openp("alice", blob)


def test_future_blob_rejected():
    seal, openp, _, MAX_AGE = _api()
    import security.internal_auth_crypto as mod

    real_time = mod.time.time
    mod.time.time = lambda: real_time() + (MAX_AGE + 5)
    try:
        blob = seal("alice", "pw")
    finally:
        mod.time.time = real_time
    with pytest.raises(ValueError, match="future"):
        openp("alice", blob)


def test_tampered_ciphertext_rejected():
    seal, openp, *_ = _api()
    blob = seal("alice", "pw")
    raw = base64.urlsafe_b64decode(blob)
    bad = bytearray(raw)
    bad[20] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(bad)).decode("ascii")
    with pytest.raises(ValueError, match="decryption"):
        openp("alice", tampered)


def test_wrong_secret_rejected(monkeypatch):
    seal, openp, *_ = _api()
    blob = seal("alice", "pw")
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "y" * 64)
    with pytest.raises(ValueError, match="decryption"):
        openp("alice", blob)


def test_malformed_base64_rejected():
    _, openp, *_ = _api()
    with pytest.raises(ValueError, match="malformed"):
        openp("alice", "not!!!base64!!!@@@")


def test_short_blob_rejected():
    _, openp, *_ = _api()
    short = base64.urlsafe_b64encode(b"\x00" * 5).decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        openp("alice", short)


def test_missing_secret_raises():
    seal, openp, *_ = _api()
    blob = seal("alice", "pw", shared_secret="x" * 64)
    with pytest.raises(ValueError, match="not set"):
        openp("alice", blob, shared_secret="")


def test_nonce_is_unique_per_seal():
    seal, *_ = _api()
    a = seal("alice", "pw")
    b = seal("alice", "pw")
    assert a != b


def test_wire_version_constant():
    _, _, WIRE_VERSION, _ = _api()
    assert WIRE_VERSION == 1
