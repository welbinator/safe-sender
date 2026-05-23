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

app = FastAPI(title="Sender Safety API", version="0.3.0")
app.add_middleware(RequestIdMiddleware)

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
                    ssl=False,
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
from routers import admin, auth, customers, logs, rules, webhooks  # noqa: E402

app.include_router(auth.router)
app.include_router(customers.router)
app.include_router(rules.router)
app.include_router(logs.router)
app.include_router(webhooks.router)
app.include_router(admin.router)


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
        customer = await conn.fetchrow(
            "SELECT id, domain_verified, subject_hash_salt FROM customers WHERE domain = $1",
            domain.lower(),
        )
        if not customer:
            raise HTTPException(status_code=404, detail="Domain not registered")
        if not customer["domain_verified"]:
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

    return {
        "customer_id": str(customer_id),
        "rules": rules_list,
        "subject_hash_salt": salt_hex,
        "subject_hash_salt_enc": salt_encrypted,
    }


# ---------------------------------------------------------------------------
# POST /internal/scan-log
# ---------------------------------------------------------------------------

class ScanLogRequest(BaseModel):
    customer_id: str = Field(..., max_length=64)
    sender: str = Field(..., max_length=320)        # RFC 5321
    recipient: str = Field(..., max_length=320)
    subject_hash: str = Field(..., max_length=128)  # hex SHA-256
    matched_rule_id: Optional[str] = Field(default=None, max_length=64)
    outcome: str = Field(..., max_length=16)
    # F-08: plaintext `subject` removed — only the HMAC `subject_hash` is stored.
    # Accept-and-discard remains for one rollout window so an older SMTP worker
    # POSTing the field doesn't 422; safe to delete after all SMTP workers ship.
    subject: Optional[str] = Field(default=None, max_length=998, deprecated=True)

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, v: str) -> str:
        if v not in ("allowed", "blocked"):
            raise ValueError("outcome must be 'allowed' or 'blocked'")
        return v


@app.post("/internal/scan-log", status_code=201, dependencies=[Depends(require_internal_secret)])
async def create_scan_log(body: ScanLogRequest):
    """Insert a scan log row. Email content is never stored."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scan_logs
                (customer_id, sender, recipient, subject_hash, matched_rule_id, outcome)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            body.customer_id,
            body.sender,
            body.recipient,
            body.subject_hash,
            body.matched_rule_id,
            body.outcome,
        )
    return {"status": "logged"}

# ---------------------------------------------------------------------------
# GET /internal/suppressed/{customer_id}/{email}
# ---------------------------------------------------------------------------
#
# Sprint B C16: per-customer suppression isolation. A hard bounce on
# alice@example.com for customer A must not block customer B from sending to
# the same address. We treat legacy rows (customer_id IS NULL) as still global
# until backfill completes, so existing suppressions don't quietly stop
# working during rollout.


@app.get(
    "/internal/suppressed/{customer_id}/{email}",
    dependencies=[Depends(require_internal_secret)],
)
async def check_suppressed(customer_id: str, email: str):
    """Returns 200 if address is suppressed for this customer, 404 if not."""
    pool = get_pool()
    addr = email.lower().strip()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT email FROM suppressed_addresses
            WHERE email = $1
              AND (customer_id = $2::uuid OR customer_id IS NULL)
            LIMIT 1
            """,
            addr,
            customer_id,
        )
    if row:
        return {"suppressed": True}
    raise HTTPException(status_code=404, detail="Not suppressed")


# ---------------------------------------------------------------------------
# POST /internal/smtp-auth  — called by SMTP server to verify credentials
# ---------------------------------------------------------------------------

class SmtpAuthRequest(BaseModel):
    """
    S-H4: wire format for /internal/smtp-auth.

    The password is delivered as an AES-256-GCM blob (`auth_blob`) keyed off
    `INTERNAL_SHARED_SECRET` via HKDF. The blob carries a unix timestamp so
    the backend can reject replays older than `MAX_AGE_SECONDS`.
    """
    v: int = 1
    username: str
    auth_blob: str


# H-3: precomputed bcrypt hash of a random secret, used as a "dummy verify"
# target to equalize timing on the admin and unknown-user code paths in
# /internal/smtp-auth. Generated once at module import.
def _make_dummy_bcrypt_hash() -> bytes:
    import bcrypt as _b
    import secrets as _s
    return _b.hashpw(_s.token_bytes(16), _b.gensalt(12))


_DUMMY_BCRYPT_HASH = _make_dummy_bcrypt_hash()


@app.post("/internal/smtp-auth", dependencies=[Depends(require_internal_secret)])
async def smtp_auth(body: SmtpAuthRequest):
    """
    Verify SMTP credentials. Returns customer info on success, 401 on failure.
    Also accepts global AUTH_USERNAME/AUTH_PASSWORD env vars as admin fallback.

    Body is POSTed (not query params) so credentials never appear in access logs.
    """
    username = body.username
    # S-H4: decrypt the AES-GCM-sealed password blob. open_password() enforces
    # AAD (binds username + version), MAC, and a 60s freshness window. Any
    # failure is treated as an auth failure (no user-visible distinction).
    from security.internal_auth_crypto import open_password as _open_password
    try:
        password = _open_password(username, body.auth_blob)
    except ValueError as exc:
        logger.warning("smtp-auth: rejected sealed payload", extra={"reason": str(exc)})
        # Still pay the bcrypt cost to keep timing flat with the success path.
        import bcrypt as _bcrypt
        await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # H-3: Admin/test fallback — constant-time + bcrypt-equivalent timing.
    #
    # Original code did `username == admin_user and password == admin_pass`,
    # which (a) leaked password length/prefix via Python's short-circuit
    # string compare, and (b) returned immediately, while the DB+bcrypt
    # path below takes ~250-500ms. Both gaps gave a remote attacker an
    # oracle to (i) enumerate the admin username and (ii) brute force the
    # password byte-by-byte.
    #
    # Fix:
    #   1. Use hmac.compare_digest for byte-level constant-time compare.
    #   2. Always do *both* compares even when admin_user is empty (dummy
    #      values), so attackers can't tell whether admin auth is enabled
    #      from timing.
    #   3. Always pay an asyncio.to_thread(bcrypt.checkpw) cost on the
    #      admin path (against a fixed precomputed hash), so the admin
    #      branch's wall time matches the DB-customer branch.
    # ------------------------------------------------------------------
    import bcrypt as _bcrypt

    admin_user = os.environ.get("AUTH_USERNAME", "")
    admin_pass = os.environ.get("AUTH_PASSWORD", "")

    # Constant-time compare both fields. If admin isn't configured, compare
    # against a fixed dummy so the timing profile is identical.
    cmp_user_a = admin_user.encode("utf-8") if admin_user else b"\x00" * 32
    cmp_user_b = username.encode("utf-8").ljust(len(cmp_user_a), b"\x00")[: len(cmp_user_a)]
    cmp_pass_a = admin_pass.encode("utf-8") if admin_pass else b"\x00" * 32
    cmp_pass_b = password.encode("utf-8").ljust(len(cmp_pass_a), b"\x00")[: len(cmp_pass_a)]

    user_match = hmac.compare_digest(cmp_user_a, cmp_user_b) and bool(admin_user)
    pass_match = hmac.compare_digest(cmp_pass_a, cmp_pass_b) and bool(admin_pass)

    # Always burn a bcrypt cycle so admin-path timing ≈ DB-path timing.
    # _DUMMY_BCRYPT_HASH is a precomputed bcrypt hash of a random string;
    # the actual outcome is discarded.
    await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)

    if user_match and pass_match:
        return {"customer_id": None, "domain": None, "admin": True}

    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, domain, smtp_password_hash FROM customers WHERE smtp_username = $1",
            username,
        )
    if not row or not row["smtp_password_hash"]:
        # Still burn a bcrypt cycle so unknown-user vs wrong-password
        # have indistinguishable timing.
        await asyncio.to_thread(_bcrypt.checkpw, b"x" * 16, _DUMMY_BCRYPT_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Sprint C2 (audit F-02): bcrypt.checkpw is CPU-bound (~250-500ms).
    # This endpoint sits on the SMTP auth hot path — every inbound message
    # hits it. Offload to a worker thread so we don't stall the FastAPI
    # event loop under concurrent SMTP authentication.
    valid = await asyncio.to_thread(
        _bcrypt.checkpw, password.encode(), row["smtp_password_hash"].encode()
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"customer_id": str(row["id"]), "domain": row["domain"], "admin": False}