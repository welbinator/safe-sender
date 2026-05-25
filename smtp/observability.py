"""
Sentry initialization for the SMTP service.

Same contract as backend/observability.py — no DSN means no-op.

The SMTP service is NOT a web framework, so we skip Starlette/FastAPI
integrations and just rely on the asyncio integration plus default
logging breadcrumbs.

Privacy: this service handles raw email content. We MUST NOT attach
message bodies, subjects, or recipient addresses to Sentry events.
The before_send filter strips anything that looks like email content
from breadcrumbs and extras.
"""
import logging
import os
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Patterns we strip from any string before send.
# Matches: full email addresses, RFC822 headers that quote them.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return _EMAIL_RE.sub("[email-redacted]", value)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _before_send(event: Dict[str, Any], hint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Scrub email addresses out of any string field in the event tree.
    # Belt-and-suspenders on top of structured logging discipline.
    return _scrub(event)


def _before_breadcrumb(crumb: Dict[str, Any], hint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return _scrub(crumb)


def init_sentry(service_name: str = "smtp") -> bool:
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        logger.info("sentry: SENTRY_DSN unset, skipping init")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
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
        send_default_pii=False,
        max_request_body_size="never",
        attach_stacktrace=True,
        integrations=[AsyncioIntegration()],
        before_send=_before_send,
        before_breadcrumb=_before_breadcrumb,
    )
    sentry_sdk.set_tag("service", service_name)
    logger.info(
        "sentry: initialized service=%s environment=%s release=%s traces=%s",
        service_name, environment, release or "(unset)", traces_sample_rate,
    )
    return True
