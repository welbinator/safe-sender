"""F-57: server-side OAuth redirect flow — unit tests.

Uses the session-scoped `client` fixture (conftest.py) so DATABASE_URL,
JWT_SECRET, etc. are seeded before security/jwt_tokens.py's fail-fast guard
runs at import time. Imports of `security.oauth_redirect` therefore happen
INSIDE test functions, not at module top.
"""
from __future__ import annotations

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import pytest


# ---------------------------------------------------------------------------
# Cryptographic primitives
# ---------------------------------------------------------------------------
def test_pkce_challenge_is_b64url_sha256_of_verifier(client):
    """RFC 7636: code_challenge = BASE64URL(SHA256(verifier))."""
    from security.oauth_redirect import pkce_challenge

    verifier = "test-verifier-123"
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert pkce_challenge(verifier) == expected


def test_new_state_uses_high_entropy_and_unique_values(client):
    from security.oauth_redirect import new_state

    a = new_state()
    b = new_state()
    assert a.state != b.state
    assert a.verifier != b.verifier
    # token_bytes(24) → 32 b64url chars, token_bytes(48) → 64.
    assert len(a.state) == 32
    assert len(a.verifier) == 64


def test_seal_unseal_roundtrips_all_fields(client):
    from security.oauth_redirect import new_state, seal_state, unseal_state

    s = new_state(return_to="/dashboard")
    out = unseal_state(seal_state(s))
    assert out is not None
    assert out.state == s.state
    assert out.verifier == s.verifier
    assert out.return_to == "/dashboard"
    assert out.issued_at == s.issued_at


def test_unseal_rejects_tampered_payload(client):
    from security.oauth_redirect import new_state, seal_state, unseal_state

    token = seal_state(new_state())
    body, sig = token.split(".", 1)
    payload = bytearray(base64.urlsafe_b64decode(body + "=="))
    payload[0] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(payload)).rstrip(b"=").decode()
    assert unseal_state(f"{tampered}.{sig}") is None


def test_unseal_rejects_tampered_signature(client):
    from security.oauth_redirect import new_state, seal_state, unseal_state

    token = seal_state(new_state())
    body, sig = token.split(".", 1)
    bad = sig[:-2] + ("XX" if not sig.endswith("XX") else "YY")
    assert unseal_state(f"{body}.{bad}") is None


def test_unseal_rejects_expired_state(client):
    from security.oauth_redirect import (
        OAuthState,
        STATE_TTL_SECONDS,
        seal_state,
        unseal_state,
    )

    s = OAuthState(
        state="s1",
        verifier="v1",
        return_to="/",
        issued_at=int(time.time()) - STATE_TTL_SECONDS - 1,
    )
    assert unseal_state(seal_state(s)) is None


def test_unseal_rejects_garbage_input(client):
    from security.oauth_redirect import unseal_state

    assert unseal_state("not-a-token") is None
    assert unseal_state("") is None
    assert unseal_state("a.b.c") is None  # wrong segment count


@pytest.mark.parametrize(
    "bad",
    ["//evil.com/x", "https://evil.com", "evil.com", "javascript:alert(1)"],
)
def test_unseal_rejects_open_redirect_return_to(client, bad):
    """Even with a valid HMAC, return_to must be a same-origin path."""
    from security.oauth_redirect import OAuthState, seal_state, unseal_state

    s = OAuthState(state="s", verifier="v", return_to=bad, issued_at=int(time.time()))
    assert unseal_state(seal_state(s)) is None


# ---------------------------------------------------------------------------
# Router-level: GET /auth/google/start
# ---------------------------------------------------------------------------
def test_google_start_returns_302_to_google_with_required_params(client, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")
    # Module captured the env at import — re-bind module attrs for this test.
    import security.oauth_redirect as o
    from routers import auth as auth_router

    monkeypatch.setattr(o, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(o, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")

    r = client.get("/auth/google/start", follow_redirects=False)
    assert r.status_code == 302, r.text
    url = urlparse(r.headers["location"])
    assert url.netloc == "accounts.google.com"
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["scope"] == ["openid email profile"]
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["client_id"][0].endswith(".apps.googleusercontent.com")
    assert len(qs["state"][0]) >= 16
    assert len(qs["code_challenge"][0]) >= 16


def test_google_start_sets_signed_state_cookie(client, monkeypatch):
    import security.oauth_redirect as o
    from routers import auth as auth_router

    monkeypatch.setattr(o, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(o, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")

    r = client.get("/auth/google/start", follow_redirects=False)
    sealed = r.cookies.get("oauth_state")
    assert sealed is not None
    from security.oauth_redirect import unseal_state

    assert unseal_state(sealed) is not None


def test_google_start_normalizes_unsafe_return_to(client, monkeypatch):
    """return_to=//evil.com must be coerced to '/' in the signed cookie —
    the cookie is the source of truth in /callback."""
    import security.oauth_redirect as o
    from routers import auth as auth_router

    monkeypatch.setattr(o, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(o, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_ID", "fake-id.apps.googleusercontent.com")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_SECRET", "GOCSPX-fake-secret")

    r = client.get("/auth/google/start?return_to=//evil.com", follow_redirects=False)
    from security.oauth_redirect import unseal_state

    unsealed = unseal_state(r.cookies["oauth_state"])
    assert unsealed is not None
    assert unsealed.return_to == "/"


def test_google_start_500_when_oauth_unconfigured(client, monkeypatch):
    """Missing creds must fail loud — not silently redirect users into a
    broken Google flow."""
    import security.oauth_redirect as o
    from routers import auth as auth_router

    monkeypatch.setattr(o, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(o, "GOOGLE_CLIENT_SECRET", "")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(auth_router, "GOOGLE_CLIENT_SECRET", "")

    r = client.get("/auth/google/start", follow_redirects=False)
    assert r.status_code == 500
    assert "not configured" in r.json()["detail"]
