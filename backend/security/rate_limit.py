"""
Per-customer rate limiting backed by Redis (F-49).

Why Redis: in-memory token buckets are per-process and break the moment we
scale to >1 uvicorn worker or >1 backend container. Redis gives us atomic
multi-process coordination with a single round-trip per request, and keeps
the door open for future shared state (idempotency keys, SES throttle, etc.).

Algorithm: GCRA-style sliding-window token bucket implemented as an atomic
Lua script. Each key holds a single float — the "theoretical arrival time"
(TAT) of the next allowed request. On each call:
    now = redis time
    tat = max(stored_tat or now, now)
    new_tat = tat + emission_interval        # cost of this request
    allow_at = new_tat - burst_tolerance     # earliest the request is allowed
    if now < allow_at:  reject, retry_after = allow_at - now
    else:               accept, store new_tat with TTL

This is one Redis call (EVAL), atomic across all workers/containers, no
race conditions. Cost: one round-trip (~0.2ms on the same host).

Fail-open policy: if Redis is unreachable or the call errors, we LOG and
ALLOW. Rate limiting is a quality-of-service feature — it must never take
down the app. Hard-fail rate limiting would let a Redis outage cascade into
a full backend outage.

Environment:
    REDIS_URL                       — connection string (default redis://redis:6379/0)
    RATE_LIMIT_ENABLED              — "0" disables; default "1"
    RATE_LIMIT_READ_PER_MIN         — per-customer GET budget (default 120)
    RATE_LIMIT_WRITE_PER_MIN        — per-customer POST/PUT/DELETE budget (default 30)
    RATE_LIMIT_AUTH_PER_MIN         — per-IP auth attempts (default 20)
    RATE_LIMIT_BURST_RATIO          — burst tolerance as fraction of rate
                                      (default 0.5 → allow ~half the budget
                                      as instant burst, then steady-state)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("sender_safety.ratelimit")

# Lua script: GCRA sliding-window token bucket. Atomic via EVAL.
#
#   KEYS[1] — the bucket key, e.g. "rl:read:cust:<uuid>"
#   ARGV[1] — emission_interval in milliseconds (1000ms * 60 / rate_per_min)
#   ARGV[2] — burst_tolerance in milliseconds
#   ARGV[3] — key TTL in seconds (auto-expire idle buckets)
#
# Returns: { allowed (0|1), retry_after_ms, remaining_burst_ms }
_GCRA_LUA = """
local key = KEYS[1]
local emission = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local now_pair = redis.call('TIME')
local now_ms = (tonumber(now_pair[1]) * 1000) + math.floor(tonumber(now_pair[2]) / 1000)

local tat = tonumber(redis.call('GET', key))
if tat == nil or tat < now_ms then
    tat = now_ms
end

local new_tat = tat + emission
local allow_at = new_tat - burst

if now_ms < allow_at then
    return {0, allow_at - now_ms, 0}
end

redis.call('SET', key, new_tat, 'PX', ttl * 1000)
local remaining = burst - (new_tat - now_ms)
if remaining < 0 then remaining = 0 end
return {1, 0, remaining}
"""


@dataclass(frozen=True)
class LimitConfig:
    name: str           # used in the Redis key prefix
    per_minute: int     # steady-state budget
    burst_ratio: float  # burst as fraction of per_minute

    @property
    def emission_ms(self) -> float:
        return 60_000.0 / max(self.per_minute, 1)

    @property
    def burst_ms(self) -> float:
        # Burst tolerance in "ms of accumulated allowance" — i.e. how far
        # below the steady-state TAT a request can still be served.
        return self.emission_ms * max(self.per_minute, 1) * self.burst_ratio


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    retry_after_seconds: float  # 0.0 when allowed


_redis_client = None


def _make_config(name: str, env_var: str, default: int, burst_ratio: float) -> LimitConfig:
    raw = os.environ.get(env_var, str(default))
    try:
        per_minute = max(int(raw), 1)
    except ValueError:
        logger.warning("Invalid %s=%r, falling back to default %d", env_var, raw, default)
        per_minute = default
    return LimitConfig(name=name, per_minute=per_minute, burst_ratio=burst_ratio)


def _burst_ratio() -> float:
    raw = os.environ.get("RATE_LIMIT_BURST_RATIO", "0.5")
    try:
        return max(0.0, min(float(raw), 5.0))
    except ValueError:
        return 0.5


# Lazily-built configs (re-read env on each access so tests can monkeypatch).
def get_read_config() -> LimitConfig:
    return _make_config("read", "RATE_LIMIT_READ_PER_MIN", 120, _burst_ratio())


def get_write_config() -> LimitConfig:
    return _make_config("write", "RATE_LIMIT_WRITE_PER_MIN", 30, _burst_ratio())


def get_auth_config() -> LimitConfig:
    return _make_config("auth", "RATE_LIMIT_AUTH_PER_MIN", 20, _burst_ratio())


def is_enabled() -> bool:
    return os.environ.get("RATE_LIMIT_ENABLED", "1") != "0"


async def get_redis():
    """Lazy global redis client. None if disabled or unavailable at import."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not is_enabled():
        return None
    try:
        import redis.asyncio as redis_async  # type: ignore
    except ImportError:
        logger.warning("redis package not installed; rate limiting disabled")
        return None
    url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    _redis_client = redis_async.from_url(
        url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    return _redis_client


async def close_redis() -> None:
    global _redis_client
    if _redis_client is None:
        return
    try:
        await _redis_client.aclose()
    except Exception:
        pass
    _redis_client = None


# TTL: bucket auto-expires after enough idle time that any cached state is
# stale anyway. 5 minutes is plenty — way longer than any burst window.
_KEY_TTL_SECONDS = 300


async def check_limit(config: LimitConfig, subject_key: str) -> LimitResult:
    """Consume one token from the bucket. Fail-open on Redis errors.

    `subject_key` is the per-subject identifier (customer UUID for customer
    limits, IP for auth limits). The full Redis key is `rl:<name>:<subject>`.
    """
    client = await get_redis()
    if client is None:
        return LimitResult(allowed=True, retry_after_seconds=0.0)

    key = f"rl:{config.name}:{subject_key}"
    try:
        result = await client.eval(  # type: ignore[attr-defined]
            _GCRA_LUA,
            1,
            key,
            int(config.emission_ms),
            int(config.burst_ms),
            _KEY_TTL_SECONDS,
        )
    except Exception as e:  # pragma: no cover — exercised in fail-open test
        logger.warning("Rate-limit Redis call failed (%s); allowing request", e)
        return LimitResult(allowed=True, retry_after_seconds=0.0)

    # Lua returns ints (or floats coerced). result[0] = allowed flag.
    allowed = int(result[0]) == 1
    retry_ms = float(result[1])
    return LimitResult(
        allowed=allowed,
        retry_after_seconds=retry_ms / 1000.0,
    )


# Convenience helpers used by FastAPI dependencies.

async def check_customer_read(customer_id: str) -> LimitResult:
    return await check_limit(get_read_config(), f"cust:{customer_id}")


async def check_customer_write(customer_id: str) -> LimitResult:
    return await check_limit(get_write_config(), f"cust:{customer_id}")


async def check_auth_by_ip(ip: str) -> LimitResult:
    return await check_limit(get_auth_config(), f"ip:{ip}")
