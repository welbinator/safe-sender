"""
Shared structured logging + request-correlation for the backend.

F-30 / F-48:
  - JsonFormatter: lifted from smtp/main.py so backend and SMTP emit
    identical machine-parseable lines (correlation across services).
  - request_id contextvar: per-request UUID injected into every log record
    via RequestIdFilter; set by RequestIdMiddleware and propagated to SMTP
    on every internal HTTP call via the X-Request-Id header.
"""
from __future__ import annotations

import contextvars
import json
import logging
import uuid
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ContextVar so concurrent requests don't clobber each other's id.
_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="-"
)


def get_request_id() -> str:
    """Return the current request's correlation id, or '-' if none."""
    return _request_id_var.get()


def set_request_id(value: str) -> contextvars.Token:
    """Set the current request id. Returns a token for resetting."""
    return _request_id_var.set(value)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line. Compatible with smtp/main.py."""

    _RESERVED = {
        "args", "created", "exc_info", "exc_text", "filename",
        "funcName", "id", "levelname", "levelno", "lineno",
        "module", "msecs", "message", "msg", "name", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        for key, val in record.__dict__.items():
            if key not in self._RESERVED and key not in base:
                try:
                    json.dumps(val)
                    base[key] = val
                except (TypeError, ValueError):
                    base[key] = repr(val)
        return json.dumps(base)


class RequestIdFilter(logging.Filter):
    """Inject the current contextvar request_id onto every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id()
        return True


_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent root-logger setup. Safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    # Drop any pre-existing handlers (e.g. uvicorn's default) so we don't
    # double-log. Uvicorn access logs still work via its own logger config.
    root.handlers = [handler]
    root.setLevel(level)
    # Quiet noisy libraries.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _CONFIGURED = True


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Read X-Request-Id from inbound request (or generate a new uuid4),
    bind to contextvar, echo on response. Downstream service calls should
    forward get_request_id() as X-Request-Id.
    """

    HEADER = "X-Request-Id"

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming = request.headers.get(self.HEADER) or uuid.uuid4().hex
        token = set_request_id(incoming)
        try:
            response = await call_next(request)
        finally:
            _request_id_var.reset(token)
        response.headers[self.HEADER] = incoming
        return response
