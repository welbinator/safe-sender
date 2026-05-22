"""
F-49 — per-customer rate limiting tests.

Strategy: do NOT spin up a real Redis. Instead, replace the rate_limit
module's redis client with an in-memory fake that mimics the GCRA EVAL
semantics. This keeps the test suite hermetic (still no docker needed),
runs in milliseconds, and exercises the FastAPI integration + dependency
wiring end-to-end.

Coverage:
  1. Under-limit requests pass with 2xx.
  2. Over-limit requests return 429 with a Retry-After header.
  3. Two different customers don't interfere with each other.
  4. Read and write limits are independent (one bucket per).
  5. Auth endpoint is rate-limited per IP (no session required).
  6. Fail-open: when the redis client raises, requests still succeed.
  7. Disabled mode (RATE_LIMIT_ENABLED=0): no limit applied.
"""
from __future__ import annotations

import time
import uuid

import pytest

from test_sprint3 import register_customer, auth_headers, fake_google_token


# ---------------------------------------------------------------------------
# Fake redis client — implements just enough of the asyncio API used by the
# rate_limit module (the `eval` method) to drive the GCRA logic faithfully.
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory stand-in for `redis.asyncio.Redis`.

    Mirrors the Lua GCRA script's semantics in Python so the FastAPI handler
    sees identical behavior. Storage is a dict of {key: tat_ms}.
    """

    def __init__(self) -> None:
        self.store: dict[str, float] = {}
        self.raise_on_eval: bool = False

    async def eval(self, script: str, numkeys: int, *args) -> list[int]:
        if self.raise_on_eval:
            raise RuntimeError("simulated redis failure")
        # args layout matches rate_limit._GCRA_LUA: key, emission_ms, burst_ms, ttl_s
        key = args[0]
        emission = float(args[1])
        burst = float(args[2])
        # ttl ignored — fake never expires within a test
        now_ms = time.time() * 1000.0
        tat = self.store.get(key, now_ms)
        if tat < now_ms:
            tat = now_ms
        new_tat = tat + emission
        allow_at = new_tat - burst
        if now_ms < allow_at:
            return [0, int(allow_at - now_ms), 0]
        self.store[key] = new_tat
        return [1, 0, max(0, int(burst - (new_tat - now_ms)))]

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fake_redis(monkeypatch):
    """Install a fake Redis client and enable rate limiting for the test."""
    from security import rate_limit as rl_mod

    fake = _FakeRedis()
    # Bypass the lazy get_redis() factory — pre-populate the module global.
    monkeypatch.setattr(rl_mod, "_redis_client", fake)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "1")
    yield fake
    # Cleanup — clear module-level cached client so other tests aren't
    # contaminated.
    monkeypatch.setattr(rl_mod, "_redis_client", None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRateLimitRead:
    def test_under_limit_passes(self, client, fake_redis, monkeypatch):
        # 60 req/min, 50% burst — lots of headroom for a single call.
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "60")
        cust = register_customer(client)
        r = client.get("/rules", headers=auth_headers(cust["token"]))
        assert r.status_code == 200

    def test_over_limit_returns_429_with_retry_after(self, client, fake_redis, monkeypatch):
        # Tight budget so we trip the limit in a handful of calls.
        # 6/min steady-state, 50% burst → burst pool ≈ 3 instant calls then 429.
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "6")
        monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "0.5")
        cust = register_customer(client)
        headers = auth_headers(cust["token"])

        statuses = [client.get("/rules", headers=headers).status_code for _ in range(15)]
        assert any(s == 429 for s in statuses), f"expected at least one 429, got {statuses}"
        # First 429 must carry Retry-After
        first_429 = next(
            (client.get("/rules", headers=headers) for _ in range(5)
             if client.get("/rules", headers=headers).status_code == 429),
            None,
        )
        # Cheap re-issue to guarantee at least one 429 response object:
        resp = client.get("/rules", headers=headers)
        # Loop until a 429 (already saturated, so should be immediate)
        for _ in range(5):
            if resp.status_code == 429:
                break
            resp = client.get("/rules", headers=headers)
        assert resp.status_code == 429
        assert "retry-after" in {h.lower() for h in resp.headers.keys()}
        assert int(resp.headers["retry-after"]) >= 1

    def test_separate_customers_have_separate_buckets(self, client, fake_redis, monkeypatch):
        # Saturate customer A, customer B should still pass.
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "4")
        monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "0.25")
        a = register_customer(client)
        b = register_customer(client)

        # Burn A's bucket
        for _ in range(20):
            client.get("/rules", headers=auth_headers(a["token"]))
        a_resp = client.get("/rules", headers=auth_headers(a["token"]))
        assert a_resp.status_code == 429, "A should be rate-limited after saturating"

        # B is untouched
        b_resp = client.get("/rules", headers=auth_headers(b["token"]))
        assert b_resp.status_code == 200, f"B should pass; got {b_resp.status_code}"


class TestRateLimitWrite:
    def test_write_bucket_independent_from_read(self, client, fake_redis, monkeypatch):
        # Generous read budget, tight write budget.
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "120")
        monkeypatch.setenv("RATE_LIMIT_WRITE_PER_MIN", "4")
        monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "0.25")
        cust = register_customer(client)
        headers = auth_headers(cust["token"])

        # Lots of reads — should never 429
        for _ in range(10):
            r = client.get("/rules", headers=headers)
            assert r.status_code == 200

        # Saturate writes — POST /rules has its own bucket
        body = {"name": "x", "match_type": "string", "pattern": "abc", "action": "block"}
        statuses = []
        for i in range(15):
            body_i = {**body, "name": f"x-{i}"}
            statuses.append(client.post("/rules", json=body_i, headers=headers).status_code)
        assert any(s == 429 for s in statuses), f"writes should hit 429: {statuses}"


class TestRateLimitAuth:
    def test_auth_endpoint_limited_by_ip(self, client, fake_redis, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MIN", "3")
        monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "0.33")

        statuses = []
        for i in range(20):
            tok = fake_google_token(f"sub-{i}-{uuid.uuid4().hex}", f"u{i}@auth-rl.example.com")
            r = client.post("/auth/google", json={"id_token": tok, "company_name": "X"})
            statuses.append(r.status_code)
            client.cookies.clear()
        assert any(s == 429 for s in statuses), f"auth should hit 429: {statuses}"


class TestRateLimitFailOpen:
    def test_redis_error_does_not_break_requests(self, client, fake_redis, monkeypatch):
        """Critical safety property: a broken Redis must not 500/429 every request."""
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "1000")
        cust = register_customer(client)

        # Flip the fake into failure mode
        fake_redis.raise_on_eval = True

        # Many requests, all must succeed (fail-open)
        for _ in range(10):
            r = client.get("/rules", headers=auth_headers(cust["token"]))
            assert r.status_code == 200, f"expected 200 when Redis is down, got {r.status_code}"


class TestRateLimitDisabled:
    def test_disabled_means_no_limit(self, client, monkeypatch):
        # Don't install fake_redis; ensure RATE_LIMIT_ENABLED=0 short-circuits
        # before any Redis call.
        from security import rate_limit as rl_mod
        monkeypatch.setattr(rl_mod, "_redis_client", None)
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "0")
        monkeypatch.setenv("RATE_LIMIT_READ_PER_MIN", "1")  # would be tight if active

        cust = register_customer(client)
        # 30 fast reads — would 429 instantly if limiter were active.
        for _ in range(30):
            r = client.get("/rules", headers=auth_headers(cust["token"]))
            assert r.status_code == 200
