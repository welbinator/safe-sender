"""S-M6 — distributed rate limiter coverage.

Verifies:
  * The async wrappers on the in-memory ``RateLimiter`` keep the existing
    cost-per-recipient behaviour (S-M5 regression).
  * ``RedisRateLimiter`` degrades to the in-memory fallback when Redis
    raises — open-fail would be worse than per-process limits during an
    incident.
  * ``_make_rate_limiter`` picks in-memory when ``REDIS_URL`` is unset.
"""

from __future__ import annotations

import os
import sys
import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    # Reload main with a clean env so module-level REDIS_URL is correct.
    if "main" in sys.modules:
        del sys.modules["main"]
    yield


def _import_main():
    import main  # noqa: WPS433 — module under test
    return main


@pytest.mark.asyncio
async def test_in_memory_async_wrapper_respects_cost():
    main = _import_main()
    rl = main.RateLimiter(max_count=5, window_seconds=60)
    assert await rl.is_allowed("c1", cost=3) is True
    assert await rl.current_count("c1") == 3
    # Next 3 would overflow (3 + 3 > 5)
    assert await rl.is_allowed("c1", cost=3) is False
    # But cost=2 fits exactly
    assert await rl.is_allowed("c1", cost=2) is True
    assert await rl.current_count("c1") == 5


@pytest.mark.asyncio
async def test_redis_limiter_falls_back_on_error(monkeypatch):
    main = _import_main()
    memory = main.RateLimiter(max_count=2, window_seconds=60)

    class _ExplodingClient:
        async def script_load(self, *_a, **_k):
            raise RuntimeError("redis is down")

        async def evalsha(self, *_a, **_k):
            raise RuntimeError("redis is down")

    rl = object.__new__(main.RedisRateLimiter)
    rl._client = _ExplodingClient()
    rl.max_count = 2
    rl.window = 60
    rl._fallback = memory
    rl._allow_sha = None
    rl._count_sha = None

    # First two allowed by fallback, third blocked.
    assert await rl.is_allowed("c2", cost=1) is True
    assert await rl.is_allowed("c2", cost=1) is True
    assert await rl.is_allowed("c2", cost=1) is False
    assert await rl.current_count("c2") == 2


def test_make_rate_limiter_no_redis_returns_in_memory(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    if "main" in sys.modules:
        del sys.modules["main"]
    import main
    assert isinstance(main._rate_limiter, main.RateLimiter)
