"""F-17 (smtp side): _decode_salt prefers encrypted field, falls back to plaintext."""
import os
import sys
import secrets

import pytest


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("DATABASE_URL", "postgresql://x:y@localhost/x")
    monkeypatch.setenv("BACKEND_URL", "http://backend:8000")
    # Force fresh import so HKDF picks up our test secret
    for m in ("internal_crypto", "main"):
        sys.modules.pop(m, None)


def _make_payload(salt_bytes):
    import internal_crypto
    salt_hex = salt_bytes.hex()
    return {
        "subject_hash_salt": salt_hex,
        "subject_hash_salt_enc": internal_crypto.encrypt_field(salt_hex),
    }


def test_decode_salt_prefers_encrypted():
    from main import _decode_salt
    salt = b"\xab" * 32
    payload = _make_payload(salt)
    # Tamper with plaintext to prove encrypted wins
    payload["subject_hash_salt"] = "00" * 32
    assert _decode_salt(payload) == salt


def test_decode_salt_falls_back_to_plaintext():
    from main import _decode_salt
    salt = b"\xcd" * 32
    # No encrypted field — legacy/rolling-deploy path
    assert _decode_salt({"subject_hash_salt": salt.hex()}) == salt


def test_decode_salt_string_legacy_shape():
    """Old call sites passed the hex string directly; keep compat."""
    from main import _decode_salt
    salt = b"\xef" * 32
    assert _decode_salt(salt.hex()) == salt


def test_decode_salt_missing_returns_zero_salt():
    """Fail-closed: missing salt returns zeros (degraded privacy, no crash)."""
    from main import _decode_salt
    assert _decode_salt({}) == b"\x00" * 32
    assert _decode_salt(None) == b"\x00" * 32


def test_decode_salt_corrupt_encrypted_falls_back():
    """If ciphertext is unreadable, fall back to plaintext rather than failing the message."""
    from main import _decode_salt
    salt = b"\x12" * 32
    payload = {
        "subject_hash_salt": salt.hex(),
        "subject_hash_salt_enc": "gAAAAA" + "X" * 80,  # bogus token
    }
    assert _decode_salt(payload) == salt
