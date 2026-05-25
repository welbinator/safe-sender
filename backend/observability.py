"""
Sentry initialization for the backend service.

Reads:
  SENTRY_DSN            — DSN URL. If unset/empty, init_sentry() is a no-op.
  SENTRY_ENVIRONMENT    — e.g. "production", "staging", "local". Default: "local".
  SENTRY_RELEASE        — git SHA injected at container build (see Dockerfile).
  SENTRY_TRACES_SAMPLE_RATE — float 0.0-1.0. Default 0.05 (5%).

Behavior:
  - No DSN → no-op. Safe to call from any service. No network, no overhead.
  - With DSN → captures unhandled exceptions, FastAPI request errors, asyncpg
    pool errors. Filters known noise (healthchecks, expected 4xx).
  - Never sends request bodies or headers that could contain PII.
"""
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Endpoints / status codes we don't want to alert on.
_NOISY_PATHS = {"/health", "/healthz", "/metrics", "/readyz"}
_EXPECTED_STATUS = {401, 403, 404, 429}


def _before_send(event: Dict[str, Any], hint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Drop noise before it ever leaves the process."""
    # Drop healthcheck / metrics request errors.
    request = event.get("request") or {}
    url = request.get("url") or ""
    for noisy in _NOISY_PATHS:
        if url.endswith(noisy):
            return None

    # Drop expected HTTP status errors (4xx that the app handles).
    exc_info = hint.get("exc_info")
    if exc_info:
        exc = exc_info[1]
        status_code = getattr(exc, "status_code", None)
        if status_code in _EXPECTED_STATUS:
            return None

    # Strip cookies and Authorization header just in case.
    headers = request.get("headers") or {}
    if isinstance(headers, dict):
        headers.pop("cookie", None)
        headers.pop("Cookie", None)
        headers.pop("authorization", None)
        headers.pop("Authorization", None)
    return event


def init_sentry(service_name: str = "backend") -> bool:
    """
    Initialize Sentry if SENTRY_DSN is set. Returns True if initialized.

    Idempotent: safe to call multiple times. Returns False on no-op (no DSN).
    """
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        logger.info("sentry: SENTRY_DSN unset, skipping init")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
    except ImportError:
        logger.warning("sentry: sentry-sdk not installed, skipping init")
        return False

    environment = os.environ.get("SENTRY_ENVIRONMENT", "local")
    release = os.environ.get("SENTRY_RELEASE") or None
    try:
        traces_sample_rate = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.05"))
    except ValueError:
        traces_sample_rate = 0.05

    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        release=release,
        traces_sample_rate=traces_sample_rate,
        # Never auto-capture request bodies — they may contain email addresses
        # or rule patterns that count as customer data.
        send_default_pii=False,
        max_request_body_size="never",
        attach_stacktrace=True,
        integrations=[
            StarletteIntegration(transaction_style="endpoint"),
            FastApiIntegration(transaction_style="endpoint"),
            AsyncioIntegration(),
        ],
        before_send=_before_send,
    )
    sentry_sdk.set_tag("service", service_name)
    logger.info(
        "sentry: initialized service=%s environment=%s release=%s traces=%s",
        service_name, environment, release or "(unset)", traces_sample_rate,
    )
    return True
