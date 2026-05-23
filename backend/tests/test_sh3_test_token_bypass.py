"""
S-H3: HMAC token gating the `sendersafety-test@<domain>` bypass.

Without a valid X-SenderSafety-TestToken header (minted by the backend with
INTERNAL_SHARED_SECRET), the SMTP gateway must NOT skip DLP scanning. These
tests cover the crypto primitives directly; integration with the SMTP path
is covered by the live smoke test post-deploy.

Coverage:
  - Mint/verify round-trip
  - Tampered tokens rejected
  - Wrong customer_id rejected
  - Expired tokens rejected
  - Future-dated tokens rejected
  - Wrong shared secret rejected
  - Malformed inputs return False (never raise)
  - Domain-separated from S-H4 auth-blob keys (different HKDF info)
"""
from __future__ import annotations

import time

import pytest


@pytest.fixture(autouse=True)
def _internal_secret(monkeypatch, client):
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "y" * 64)


def _api():
    from security.internal_auth_crypto import (
        TEST_TOKEN_MAX_AGE_SECONDS,
        mint_test_token,
        verify_test_token,
    )
    return mint_test_token, verify_test_token, TEST_TOKEN_MAX_AGE_SECONDS


def test_mint_verify_roundtrip():
    mint, verify, _ = _api()
    tok = mint("cust-123")
    assert verify(tok, "cust-123") is True


def test_wrong_customer_id_rejected():
    mint, verify, _ = _api()
    tok = mint("cust-123")
    assert verify(tok, "cust-999") is False


def test_tampered_mac_rejected():
    mint, verify, _ = _api()
    tok = mint("cust-123")
    ts, mac = tok.split(".", 1)
    # flip one character in the MAC
    flipped = "A" if mac[0] != "A" else "B"
    bad = f"{ts}.{flipped}{mac[1:]}"
    assert verify(bad, "cust-123") is False


def test_tampered_timestamp_rejected():
    mint, verify, _ = _api()
    tok = mint("cust-123")
    ts, mac = tok.split(".", 1)
    bad = f"{int(ts) + 1}.{mac}"
    assert verify(bad, "cust-123") is False


def test_expired_token_rejected():
    mint, verify, max_age = _api()
    tok = mint("cust-123")
    # simulate verification far in the future
    future = int(time.time()) + max_age + 10
    assert verify(tok, "cust-123", now=future) is False


def test_future_dated_token_rejected():
    mint, verify, max_age = _api()
    tok = mint("cust-123")
    # caller's clock is way behind — also reject
    past = int(time.time()) - max_age - 10
    assert verify(tok, "cust-123", now=past) is False


def test_wrong_shared_secret_rejected(monkeypatch):
    mint, verify, _ = _api()
    tok = mint("cust-123", shared_secret="a" * 64)
    # default env secret is "y"*64 — different — must reject
    assert verify(tok, "cust-123") is False


def test_malformed_token_returns_false():
    _, verify, _ = _api()
    assert verify("", "cust-123") is False
    assert verify("no-dot-here", "cust-123") is False
    assert verify("notanint.YWJj", "cust-123") is False
    assert verify("123.!!!not-base64!!!", "cust-123") is False
    assert verify(None, "cust-123") is False  # type: ignore[arg-type]


def test_domain_separated_from_auth_blob_keys():
    """A test-token MAC must NOT validate as an S-H4 auth-blob, and the
    HKDF keys must differ (defense-in-depth against cross-protocol reuse)."""
    from security.internal_auth_crypto import (
        _derive_key,
        _derive_test_token_key,
    )

    secret = "z" * 64
    assert _derive_key(secret) != _derive_test_token_key(secret)
