"""
Code Audit Two H-1 regression: client-IP derivation must resist spoofing.

Threat: an attacker sets `X-Forwarded-For: <random>` on every login attempt.
If we naively read the LEFTMOST XFF token, the per-IP auth-rate-limit bucket
is keyed on attacker-controlled garbage and never trips, allowing unlimited
credential-stuffing from a single source IP.

Defense (deps._client_ip):
  1. Prefer `X-Real-IP` (nginx overwrites this with $remote_addr — not
     client-settable).
  2. Fall back to the RIGHTMOST `X-Forwarded-For` token (nginx appends, so
     the rightmost value is the segment nginx itself wrote).
  3. Fall back to `request.client.host` (direct connection).

These tests exercise the helper directly with synthetic Request objects —
no FastAPI client, no rate limiter, no Redis. They depend on the session
`_seed_env` fixture from conftest.py to satisfy the startup secret guards
that fire at `deps` import time.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def client_ip(_seed_env):
    """Import `deps._client_ip` lazily so env vars are seeded first."""
    from deps import _client_ip
    return _client_ip


def _req(headers: dict[str, str], client_host: str | None = "203.0.113.9"):
    """Minimal stub that quacks like starlette.Request for _client_ip."""
    norm = {k.lower(): v for k, v in headers.items()}
    client = SimpleNamespace(host=client_host) if client_host else None
    return SimpleNamespace(
        headers=SimpleNamespace(get=lambda k, default="": norm.get(k.lower(), default)),
        client=client,
    )


class TestClientIpHappyPaths:
    def test_x_real_ip_wins_when_present(self, client_ip):
        r = _req({
            "X-Real-IP": "198.51.100.7",
            "X-Forwarded-For": "198.51.100.7",
        })
        assert client_ip(r) == "198.51.100.7"

    def test_rightmost_xff_when_no_real_ip(self, client_ip):
        # No X-Real-IP. Rightmost XFF is the segment nginx itself appended.
        r = _req({"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 198.51.100.7"})
        assert client_ip(r) == "198.51.100.7"

    def test_direct_connection_no_headers(self, client_ip):
        r = _req({}, client_host="127.0.0.1")
        assert client_ip(r) == "127.0.0.1"

    def test_unknown_when_no_headers_and_no_client(self, client_ip):
        r = _req({}, client_host=None)
        assert client_ip(r) == "unknown"


class TestClientIpSpoofResistance:
    """The actual H-1 regression suite — these would have FAILED before the fix."""

    def test_spoofed_left_xff_token_is_ignored(self, client_ip):
        # Attacker sends `X-Forwarded-For: 1.2.3.4`. Nginx appends real IP,
        # so backend sees `1.2.3.4, <real_ip>`. OLD code returned "1.2.3.4".
        r = _req({
            "X-Real-IP": "198.51.100.7",
            "X-Forwarded-For": "1.2.3.4, 198.51.100.7",
        })
        ip = client_ip(r)
        assert ip == "198.51.100.7"
        assert ip != "1.2.3.4", "must not honor attacker-set leftmost XFF"

    def test_spoofed_chain_does_not_pollute_key(self, client_ip):
        r = _req({
            "X-Real-IP": "198.51.100.7",
            "X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3, 198.51.100.7",
        })
        assert client_ip(r) == "198.51.100.7"

    def test_attacker_cannot_rotate_bucket_key(self, client_ip):
        """Two requests with different spoofed XFF, same real source, must
        produce the SAME key — otherwise per-IP rate limiting is bypassable."""
        a = _req({
            "X-Real-IP": "198.51.100.7",
            "X-Forwarded-For": "1.1.1.1, 198.51.100.7",
        })
        b = _req({
            "X-Real-IP": "198.51.100.7",
            "X-Forwarded-For": "9.9.9.9, 198.51.100.7",
        })
        assert client_ip(a) == client_ip(b) == "198.51.100.7"

    def test_attacker_without_real_ip_still_blocked_via_rightmost_xff(self, client_ip):
        r = _req({"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
        assert client_ip(r) == "198.51.100.7"

    def test_xff_with_spaces_is_trimmed(self, client_ip):
        r = _req({"X-Forwarded-For": "1.2.3.4,   198.51.100.7   "})
        assert client_ip(r) == "198.51.100.7"

    def test_empty_real_ip_falls_through_to_xff(self, client_ip):
        # Whitespace-only X-Real-IP must not short-circuit.
        r = _req({
            "X-Real-IP": "   ",
            "X-Forwarded-For": "1.2.3.4, 198.51.100.7",
        })
        assert client_ip(r) == "198.51.100.7"
