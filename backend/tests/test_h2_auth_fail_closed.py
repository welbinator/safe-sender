"""H-2: auth-by-IP rate limiter must not fail-open when Redis is unavailable.

Original bug: a Redis outage (or simply Redis not installed) silently allowed
unlimited auth attempts because check_limit returned allowed=True on any
"client is None" / exception path. Combined with H-1 (XFF spoofing) this made
credential stuffing trivial.

Fix: check_auth_by_ip now passes local_fallback=True, which routes the
request to a per-process in-memory GCRA bucket when Redis is unreachable.
Customer R/W limiters keep their fail-open behaviour (QoS, not security).
"""
from __future__ import annotations

import asyncio
import os
import pytest


@pytest.fixture(autouse=True)
def _seed_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost/db")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "1")  # conftest disables globally; we test the limiter itself
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MIN", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "1.0")  # full burst of 2, then steady
    yield


@pytest.fixture
def rl(monkeypatch):
    """Import rate_limit fresh and force Redis-unavailable state."""
    from security import rate_limit as rl
    rl._redis_client = None
    rl._reset_local_buckets_for_tests()

    async def _no_redis():
        return None
    monkeypatch.setattr(rl, "get_redis", _no_redis)
    return rl


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


# ---------------------------------------------------------------------------
# Core H-2: auth limiter is fail-closed-to-local when Redis is unavailable.
# ---------------------------------------------------------------------------

def test_auth_fail_closed_when_redis_unavailable(rl):
    """Budget=2, burst=1.0 → 2 allowed, then reject."""
    async def go():
        r1 = await rl.check_auth_by_ip("1.2.3.4")
        r2 = await rl.check_auth_by_ip("1.2.3.4")
        r3 = await rl.check_auth_by_ip("1.2.3.4")
        return r1, r2, r3
    r1, r2, r3 = _run(go())
    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is False
    assert r3.retry_after_seconds > 0


def test_auth_fail_closed_isolates_by_ip(rl):
    """Different IPs get separate buckets even in local mode."""
    async def go():
        a = await rl.check_auth_by_ip("1.1.1.1")
        b = await rl.check_auth_by_ip("2.2.2.2")
        return a, b
    a, b = _run(go())
    assert a.allowed is True
    assert b.allowed is True


def test_auth_local_caps_credential_stuffing(rl, monkeypatch):
    """5/min cap means a flood of 20 attempts from one IP is bounded."""
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MIN", "5")
    monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "1.0")  # allow full burst of 5

    async def go():
        results = []
        for _ in range(20):
            results.append(await rl.check_auth_by_ip("9.9.9.9"))
        return results

    results = _run(go())
    allowed = sum(1 for r in results if r.allowed)
    # Burst=1.0 with 5/min → ~5 requests allowed in a tight loop, not 20.
    assert allowed <= 6, f"Expected ~5 allowed, got {allowed} — fail-open regression"
    assert allowed >= 1


# ---------------------------------------------------------------------------
# Customer R/W limits MUST stay fail-open (QoS, not security).
# ---------------------------------------------------------------------------

def test_customer_read_still_fail_open(rl):
    async def go():
        results = []
        for _ in range(50):
            results.append(await rl.check_customer_read("cust-uuid"))
        return results
    results = _run(go())
    assert all(r.allowed for r in results), "Customer R/W must fail-open during Redis outage"


def test_customer_write_still_fail_open(rl):
    async def go():
        results = []
        for _ in range(50):
            results.append(await rl.check_customer_write("cust-uuid"))
        return results
    results = _run(go())
    assert all(r.allowed for r in results)


# ---------------------------------------------------------------------------
# Local bucket internals: LRU bound, reject on exhausted budget.
# ---------------------------------------------------------------------------

def test_local_check_rejects_when_budget_exhausted(rl):
    from security.rate_limit import LimitConfig, _local_check
    cfg = LimitConfig(name="auth", per_minute=2, burst_ratio=1.0)
    r1 = _local_check(cfg, "ip:1.1.1.1")
    r2 = _local_check(cfg, "ip:1.1.1.1")
    r3 = _local_check(cfg, "ip:1.1.1.1")
    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is False


def test_local_bucket_lru_bound(rl):
    from security import rate_limit as rl_mod
    from security.rate_limit import LimitConfig, _local_check
    cfg = LimitConfig(name="auth", per_minute=1, burst_ratio=1.0)
    # Temporarily shrink the bound for the test.
    original = rl_mod._LOCAL_MAX_ENTRIES
    rl_mod._LOCAL_MAX_ENTRIES = 50
    try:
        for i in range(200):
            _local_check(cfg, f"ip:10.0.0.{i}")
        assert len(rl_mod._local_buckets) <= 50
    finally:
        rl_mod._LOCAL_MAX_ENTRIES = original


# ---------------------------------------------------------------------------
# Explicit Redis-error path also routes to local for auth.
# ---------------------------------------------------------------------------

def test_auth_redis_error_routes_to_local(monkeypatch):
    from security import rate_limit as rl
    rl._redis_client = None
    rl._reset_local_buckets_for_tests()
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MIN", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST_RATIO", "1.0")

    class _BoomClient:
        async def eval(self, *a, **kw):
            raise RuntimeError("redis dead")

    async def _boom_redis():
        return _BoomClient()
    monkeypatch.setattr(rl, "get_redis", _boom_redis)

    async def go():
        r1 = await rl.check_auth_by_ip("3.3.3.3")
        r2 = await rl.check_auth_by_ip("3.3.3.3")
        r3 = await rl.check_auth_by_ip("3.3.3.3")
        return r1, r2, r3
    r1, r2, r3 = _run(go())
    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is False, "Auth must remain bounded even when Redis raises mid-call"
