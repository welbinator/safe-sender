"""
Email-dispatch service (Sprint C3 F-27).

Owns the *transport* concern for outbound emails: SES client lifecycle, retry
config, structured logging, error swallowing. Templates live in
`services.email_templates`; this module just sends.

Before: router-level helpers `_send_welcome_email_sync` / `_get_ses_client`
mixed FastAPI handler code with boto3 wiring. Hard to unit-test, hard to reuse
for future emails (verification, password-reset, billing). This module
isolates the transport so the router stays an HTTP boundary only.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import boto3
from botocore.config import Config as BotoConfig

from services.email_templates import render_welcome_email

logger = logging.getLogger(__name__)

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_SOURCE_ARN = os.environ.get("SES_SOURCE_ARN", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@sendersafety.com")

# Cached at module scope: boto3 clients cost ~100ms to construct (creds
# discovery + endpoint resolution). Reuse one across requests; pin tight
# timeouts so a stalled SES call cannot pin a worker thread forever (F-05, F-07).
_BOTO_CONFIG = BotoConfig(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2, "mode": "standard"},
)
_ses_client = None


def _get_ses_client():
    global _ses_client
    if _ses_client is None:
        _ses_client = boto3.client("ses", region_name=AWS_REGION, config=_BOTO_CONFIG)
    return _ses_client


def _send_email_sync(
    *,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str,
) -> None:
    """Blocking SES send. Errors are logged with traceback and swallowed —
    callers schedule this off the request path so the user response is not
    coupled to SES availability."""
    try:
        ses = _get_ses_client()
        kwargs: dict = dict(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": body_text, "Charset": "UTF-8"},
                    "Html": {"Data": body_html, "Charset": "UTF-8"},
                },
            },
        )
        if SES_SOURCE_ARN:
            kwargs["SourceArn"] = SES_SOURCE_ARN
        ses.send_email(**kwargs)
    except Exception as exc:  # noqa: BLE001
        # F-29: log full traceback so background failures aren't invisible.
        logger.exception(
            "email_send_failed",
            extra={"to_email": to_email, "subject": subject, "error": str(exc)},
        )


async def send_welcome_email(to_email: str, name: str, domain: str) -> None:
    """Async wrapper used as a FastAPI BackgroundTask."""
    subject, body_text, body_html = render_welcome_email(name=name, domain=domain)
    await asyncio.to_thread(
        _send_email_sync,
        to_email=to_email,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )
