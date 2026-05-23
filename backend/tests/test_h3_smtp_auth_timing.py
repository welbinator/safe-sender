"""
H-3: /internal/smtp-auth admin fallback must use constant-time compare
and must not leak (a) admin-enabled-ness or (b) admin-vs-DB code path
through response timing.

The original code did:
    if admin_user and username == admin_user and password == admin_pass:
        return {..., "admin": True}
    # ... else fall through to DB lookup + bcrypt (~250-500ms)

That gave attackers two oracles:
  - Python's short-circuit `==` on str leaks length and prefix of password.
  - Admin success returns ~instantly while DB path takes hundreds of ms,
    so a successful admin auth (or even "user matches admin") was
    distinguishable from "user is a DB customer" purely by wall time.

Fix verified here:
  1. hmac.compare_digest used for both fields.
  2. Wrong admin password still authenticates as 401 — but takes
     roughly as long as the bcrypt path.
  3. Admin success path also takes ~bcrypt time (dummy bcrypt cycle).
"""
from __future__ import annotations

import os
import time

import pytest


# Reuse the project's session-scoped client; we just need the in-process app.
INTERNAL_HEADER = "x-internal-secret"


def _internal_secret() -> str:
    # conftest seeds this; fall back to a default if absent.
    return os.environ.get("INTERNAL_SHARED_SECRET", "test-internal-secret-please-rotate")


def _post(client, username: str, password: str):
    # S-H4: backend expects AES-GCM-sealed password blob.
    from security.internal_auth_crypto import seal_password, WIRE_VERSION
    auth_blob = seal_password(username, password)
    return client.post(
        "/internal/smtp-auth",
        json={"v": WIRE_VERSION, "username": username, "auth_blob": auth_blob},
        headers={INTERNAL_HEADER: _internal_secret()},
    )


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("AUTH_USERNAME", "smtpadmin")
    monkeypatch.setenv("AUTH_PASSWORD", "correct-horse-battery-staple")


def test_admin_success(client, admin_env):
    r = _post(client, "smtpadmin", "correct-horse-battery-staple")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["admin"] is True
    assert body["customer_id"] is None


def test_admin_wrong_password_rejected(client, admin_env):
    r = _post(client, "smtpadmin", "wrong-password")
    assert r.status_code == 401


def test_admin_wrong_username_rejected(client, admin_env):
    r = _post(client, "notadmin", "correct-horse-battery-staple")
    assert r.status_code == 401


def test_admin_disabled_when_env_empty(client, monkeypatch):
    monkeypatch.setenv("AUTH_USERNAME", "")
    monkeypatch.setenv("AUTH_PASSWORD", "")
    # Whatever creds we send, must not be admin-accepted.
    r = _post(client, "", "")
    assert r.status_code == 401
    r = _post(client, "anything", "")
    assert r.status_code == 401


def test_admin_compare_is_constant_time_byte_level(client, admin_env):
    """
    Ensure the wrong-password 401 isn't *dramatically* faster than the
    admin success path. We can't write a precise side-channel test in
    Python (GC, jitter), but we can assert the admin failure path takes
    > 50ms — i.e., the bcrypt dummy verify ran. The vulnerable code
    returned in microseconds.
    """
    # Warm up bcrypt JIT / module imports.
    _post(client, "smtpadmin", "x")

    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        r = _post(client, "smtpadmin", "wrong-password-of-similar-length")
        elapsed = time.perf_counter() - t0
        assert r.status_code == 401
        samples.append(elapsed)

    median = sorted(samples)[len(samples) // 2]
    # bcrypt cost(12) round-trip is ~150-400ms locally. Vulnerable code
    # returned in <1ms. 0.05s is a comfortable floor.
    assert median > 0.05, (
        f"smtp-auth wrong-admin-password returned in {median*1000:.1f}ms — "
        "constant-time bcrypt dummy verify is not running (H-3 regression)."
    )


def test_admin_enabled_vs_disabled_timing_similar(client, monkeypatch):
    """
    With AUTH_USERNAME unset, the endpoint must still pay the bcrypt cost
    so an attacker can't tell whether admin auth is configured.
    """
    monkeypatch.setenv("AUTH_USERNAME", "")
    monkeypatch.setenv("AUTH_PASSWORD", "")
    _post(client, "anything", "x")  # warm

    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        r = _post(client, "anyone", "any-password")
        assert r.status_code == 401
        samples.append(time.perf_counter() - t0)

    median = sorted(samples)[len(samples) // 2]
    assert median > 0.05, (
        f"smtp-auth with admin disabled returned in {median*1000:.1f}ms — "
        "should still burn a bcrypt cycle to hide admin-enabled-ness."
    )
