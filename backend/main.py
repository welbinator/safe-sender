"""
Sender Safety API — Sprint 3.

Adds customer-facing endpoints on top of Sprint 2's internal SMTP endpoints:

  Auth:
    POST /auth/google          — exchange Google ID token for session JWT

  Customers:
    GET  /customers/me         — current customer profile
    PATCH /customers/me        — update name

  Rules:
    GET    /rules              — list rules
    POST   /rules              — create rule
    PUT    /rules/{id}         — update rule
    DELETE /rules/{id}         — delete rule

  Logs:
    GET  /logs                 — paginated scan logs

Internal (SMTP service only, not exposed via nginx):
  GET  /internal/rules/{domain}
  POST /internal/scan-log
"""
import asyncio
import hashlib
import hmac
import logging
import os
import time as _time
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

# ---------------------------------------------------------------------------
# Sprint C1: Fail-fast on missing/weak DATABASE_URL (audit H-3).
# Runs BEFORE other imports so the guard fires even if internal_auth or
# downstream modules have their own (less specific) startup checks.
# ---------------------------------------------------------------------------
_WEAK_DB_PASSWORDS = {"changeme", "secret", "password", "default", "test", ""}

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required. Refusing to start with an insecure default. "
        "Set DATABASE_URL in the environment (see .env.example)."
    )
_db_password = (urlparse(DATABASE_URL).password or "").lower()
if _db_password in _WEAK_DB_PASSWORDS:
    raise RuntimeError(
        "DATABASE_URL contains a weak/default password "
        f"({_db_password!r}). Set a strong password before starting."
    )
from logging_config import configure_logging, RequestIdMiddleware  # noqa: E402

configure_logging()
logger = logging.getLogger("sender_safety.backend")

logger.info("DATABASE_URL host portion: ...@%s", DATABASE_URL.split("@")[-1])

# ---------------------------------------------------------------------------
# Sprint C1 HOTFIX (audit C-1): Refuse to start if test-token bypass is
# enabled in production. ALLOW_TEST_TOKENS=1 lets `auth/google` accept
# `test:<json>` strings as a valid Google ID token — fine for CI, catastrophic
# in prod (anyone can mint a session for any email).
# ---------------------------------------------------------------------------
_ENV = os.environ.get("ENV", "").lower()
_ALLOW_TEST_TOKENS = os.environ.get("ALLOW_TEST_TOKENS") == "1"
if _ENV in ("production", "prod") and _ALLOW_TEST_TOKENS:
    raise RuntimeError(
        "FATAL: ALLOW_TEST_TOKENS=1 is set while ENV=production. "
        "This would let anyone forge a session JWT by POSTing a fake "
        "Google ID token. Unset ALLOW_TEST_TOKENS (or set it to 0) "
        "before starting. Refusing to start."
    )

import asyncpg
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from internal_auth import require_internal_secret
from db import close_pool, get_pool, set_pool
from routers import internal_scan, internal_suppression, internal_smtp_auth

app = FastAPI(title="Sender Safety API", version="0.3.0")
app.add_middleware(RequestIdMiddleware)
app.include_router(internal_scan.router)
app.include_router(internal_suppression.router)
app.include_router(internal_smtp_auth.router)

# ---------------------------------------------------------------------------
# F-45 — Prometheus instrumentation.
# We use prometheus_client directly rather than prometheus-fastapi-
# instrumentator because that wrapper caps starlette<1.0.0, and starlette
# 0.52.x has PYSEC-2026-161. Direct exposition is small and gives us the same
# three signals (request count, latency, in-progress) plus full control.
#
# Nothing in nginx.conf forwards /metrics, so the endpoint is reachable only
# from inside the Docker network (scraped by a sidecar / Prometheus container,
# not the public internet).
# ---------------------------------------------------------------------------
from prometheus_client import (  # noqa: E402
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.requests import Request as _PromRequest  # noqa: E402
from starlette.responses import Response as _PromResponse  # noqa: E402


def _get_or_create(metric_cls, name, *args, **kwargs):
    """Return existing metric on re-import (tests reload `main`) instead of
    raising ``Duplicated timeseries in CollectorRegistry``.
    """
    existing = REGISTRY._names_to_collectors.get(name)
    if existing is not None:
        return existing
    return metric_cls(name, *args, **kwargs)


_PROM_REQUESTS = _get_or_create(
    Counter,
    "http_requests_total",
    "Total HTTP requests",
    ["method", "handler", "status"],
)
_PROM_LATENCY = _get_or_create(
    Histogram,
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "handler"],
)
_PROM_INPROGRESS = _get_or_create(
    Gauge,
    "http_requests_in_progress",
    "HTTP requests currently being processed",
    ["method", "handler"],
)
_PROM_EXCLUDED = {"/health", "/healthz", "/metrics"}


@app.middleware("http")
async def _prometheus_middleware(request: _PromRequest, call_next):
    path = request.url.path
    if path in _PROM_EXCLUDED:
        return await call_next(request)
    # Use the matched route template ("/rules/{id}") rather than the raw path
    # so high-cardinality URLs don't explode the metric series.
    route = request.scope.get("route")
    handler = getattr(route, "path", path) if route else path
    method = request.method
    _PROM_INPROGRESS.labels(method, handler).inc()
    start = _time.perf_counter()
    status = "500"
    try:
        response = await call_next(request)
        status = str(response.status_code)
        return response
    finally:
        _PROM_LATENCY.labels(method, handler).observe(_time.perf_counter() - start)
        _PROM_REQUESTS.labels(method, handler, status).inc()
        _PROM_INPROGRESS.labels(method, handler).dec()


@app.get("/metrics", include_in_schema=False)
async def _metrics() -> _PromResponse:
    return _PromResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
# ---------------------------------------------------------------------------
# Database connection pool (created on startup; lives in db.py — F-13)
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup():
    import asyncio
    import socket as _socket

    loop = asyncio.get_running_loop()

    # WSL2 Docker bug: thread-pool executor threads cannot call getaddrinfo.
    # Patch loop.getaddrinfo to run synchronously in the event loop thread.
    async def _sync_getaddrinfo(host, port, *args, **kwargs):
        return _socket.getaddrinfo(host, port, *args, **kwargs)

    loop.getaddrinfo = _sync_getaddrinfo

    last_err = None
    for attempt in range(10):
        try:
            # Parse the URL into explicit kwargs to avoid asyncpg calling
            # loop.getaddrinfo() — which hangs in executor threads on this
            # Docker/WSL2 kernel combo even for raw IPs.
            from urllib.parse import urlparse
            _u = urlparse(DATABASE_URL)
            pool = await asyncio.wait_for(
                asyncpg.create_pool(
                    host=_u.hostname,
                    port=_u.port or 5432,
                    user=_u.username,
                    password=_u.password,
                    database=_u.path.lstrip("/"),
                    min_size=2,
                    max_size=10,
                    # M-7: DB SSL is opt-in via DB_SSL=1. Default off keeps
                    # local dev / docker compose working (no cert on the pg
                    # container). Prod must set DB_SSL=require (passed
                    # through to asyncpg) once the managed DB cert is wired.
                    ssl=os.environ.get("DB_SSL") or False,
                    timeout=10,
                ),
                timeout=15,
            )
            set_pool(pool)
            return
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            logger.warning("DB connect attempt %d failed: %s. Retrying in %ds...", attempt + 1, e, wait)
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect to database after 10 attempts: {last_err}")


@app.on_event("shutdown")
async def shutdown():
    await close_pool()
    # F-49 — close the rate-limit Redis client cleanly so we don't leak the
    # connection on container restart.
    try:
        from security import close_redis as _close_redis
        await _close_redis()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Register Sprint 3 routers
# ---------------------------------------------------------------------------
from routers import admin, ai_policies, auth, customers, logs, rules, webhooks  # noqa: E402

app.include_router(auth.router)
app.include_router(customers.router)
app.include_router(rules.router)
app.include_router(logs.router)
app.include_router(webhooks.router)
app.include_router(admin.router)
app.include_router(ai_policies.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    """Liveness + DB readiness probe (F-47, F-46).

    A 200 here means the process is up AND can round-trip a query to Postgres
    within 1 second. A pure liveness check (always-200) misled the loadbalancer
    during DB outages — requests landed on backends that immediately 500'd. Now
    if PG is unreachable, or the asyncpg pool is fully saturated (every conn
    busy + every waiter timing out), we return 503 and the proxy can route
    around us. Pool stats are echoed so Prometheus / `/metrics` consumers can
    alert on chronic saturation before it tips over.
    """
    try:
        pool = get_pool()
        # F-46: acquire with a hard 1s timeout. If the pool is exhausted long
        # enough that we can't even get a connection inside a second, that's a
        # saturation signal and we want the LB to shed load, not queue it.
        async with asyncio.timeout(1):
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
    except (asyncio.TimeoutError, TimeoutError) as exc:
        logger.warning(
            "health: pool exhausted (size=%s free=%s): %s",
            pool.get_size() if "pool" in locals() else "?",
            pool.get_idle_size() if "pool" in locals() else "?",
            exc,
        )
        raise HTTPException(status_code=503, detail="pool_exhausted")
    except Exception as exc:
        logger.warning("health: DB ping failed: %s", exc)
        raise HTTPException(status_code=503, detail="db_unavailable")
    return {
        "status": "ok",
        "db": "ok",
        "pool": {
            "size": pool.get_size(),
            "idle": pool.get_idle_size(),
            "max": pool.get_max_size(),
            "min": pool.get_min_size(),
        },
    }


@app.get("/healthz")
async def healthz() -> dict:
    """Pure liveness probe — no DB, never blocks on outages.

    Use this for k8s/docker liveness restarts (process is alive). Use /health
    for readiness (process can serve traffic).
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /internal/rules/{domain}
# ---------------------------------------------------------------------------

@app.get("/internal/rules/{domain}", dependencies=[Depends(require_internal_secret)])
async def get_rules(domain: str):
    """
    Return customer_id and active rules for a given sender domain.
    Returns 404 if domain is not registered.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        # Post multi-domain migration (20260528_0001) the source of truth for
        # verification is customer_domains.verified.  The legacy
        # customers.domain_verified column is left in place for backward-compat
        # but is no longer updated by the verification flow — so we join both
        # tables and treat the domain as verified when *either* flag is true.
        customer = await conn.fetchrow(
            """
            SELECT c.id, c.subject_hash_salt,
                   (COALESCE(cd.verified, FALSE) OR COALESCE(c.domain_verified, FALSE)) AS is_verified
            FROM customers c
            LEFT JOIN customer_domains cd
                   ON cd.customer_id = c.id AND cd.domain = $1
            WHERE c.domain = $1
            """,
            domain.lower(),
        )
        if not customer:
            raise HTTPException(status_code=404, detail="Domain not registered")
        if not customer["is_verified"]:
            raise HTTPException(status_code=403, detail="Domain not verified")

        customer_id = customer["id"]
        rows = await conn.fetch(
            """
            SELECT id, pattern, match_type, scope, is_exception, applies_to_email
            FROM rules
            WHERE customer_id = $1 AND active = true
            """,
            customer_id,
        )

    rules_list = [
        {
            "id": str(r["id"]),
            "pattern": r["pattern"],
            "match_type": r["match_type"],
            "scope": r["scope"] or "both",
            "is_exception": r["is_exception"],
            "applies_to_user": r["applies_to_email"],
        }
        for r in rows
    ]

    # C12: hand the SMTP service this customer's HMAC key for subject hashing.
    # F-17: the salt is the keying material that protects subject-hash privacy.
    # Encrypt it with the shared-secret-derived key so a tcpdump on the Docker
    # bridge can't lift it in plaintext. SMTP decrypts with the mirror module.
    #
    # Transition: we return BOTH `subject_hash_salt` (legacy plaintext) and
    # `subject_hash_salt_enc` so backend + smtp can be deployed independently.
    # The plaintext field is dropped in a follow-up commit once smtp is
    # confirmed pulling from `_enc`.
    from internal_crypto import encrypt_field
    salt_hex = bytes(customer["subject_hash_salt"]).hex()
    salt_encrypted = encrypt_field(salt_hex)

    async with pool.acquire() as conn2:
        ai_row = await conn2.fetchrow(
            "SELECT ai_scan_enabled FROM customers WHERE id = $1",
            customer_id,
        )
        ai_policy_rows = await conn2.fetch(
            "SELECT policy_text FROM ai_policies WHERE customer_id = $1 ORDER BY created_at",
            customer_id,
        )

    return {
        "customer_id": str(customer_id),
        "rules": rules_list,
        "subject_hash_salt": salt_hex,
        "subject_hash_salt_enc": salt_encrypted,
        "ai_scan_enabled": bool(ai_row["ai_scan_enabled"]) if ai_row else False,
        "ai_policies": [r["policy_text"] for r in ai_policy_rows],
    }
