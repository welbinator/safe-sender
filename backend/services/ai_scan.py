"""
AI scan service — calls local Ollama to evaluate an email against
plain-English policies defined by the customer.

Privacy guarantee: email body/subject are NEVER written to disk or logged.
They exist in memory only for the duration of this call.

Returns AIScanResult(decision, confidence, reason) or None on error/timeout.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host-gateway:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))

SYSTEM_PROMPT = (
    "You are a strict outbound email compliance scanner for a financial/professional services firm. "
    "You will be given a set of plain-English compliance policies and an email to review. "
    "Respond ONLY with a JSON object — no explanation, no markdown, just JSON. "
    'Format: {"decision": "pass" or "flag", "confidence": 0-100, "reason": "one sentence"}'
)


class AIScanResult:
    __slots__ = ("decision", "confidence", "reason")

    def __init__(self, decision: str, confidence: int, reason: str):
        self.decision = decision        # "pass" | "flag"
        self.confidence = confidence    # 0-100
        self.reason = reason            # human-readable explanation


def scan_email(
    subject: str,
    body: str,
    policies: list[str],
) -> AIScanResult | None:
    """
    Synchronous — run via asyncio.to_thread() from the SMTP handler.

    Returns None on timeout, connection error, or unparseable response.
    Fail-open: if AI is unavailable the email still passes keyword scan.
    """
    if not policies:
        return None

    policies_block = "\n".join(f"- {p}" for p in policies)
    prompt = (
        f"COMPLIANCE POLICIES:\n{policies_block}\n\n"
        f"EMAIL TO REVIEW:\n"
        f"Subject: {subject[:500]}\n"
        f"Body: {body[:3000]}\n\n"
        "Respond with JSON only."
    )

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "keep_alive": "10m",
        "options": {"temperature": 0},
    }).encode()

    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            raw = json.load(resp)["response"]
    except urllib.error.URLError as exc:
        logger.warning("Ollama unreachable — AI scan skipped", extra={"error": str(exc)})
        return None
    except Exception as exc:
        logger.warning("Ollama error — AI scan skipped", extra={"error": str(exc)})
        return None

    try:
        cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
        data = json.loads(cleaned)
        decision = str(data.get("decision", "pass")).lower()
        if decision not in ("pass", "flag"):
            decision = "pass"
        confidence = min(100, max(0, int(data.get("confidence", 50))))
        reason = str(data.get("reason", ""))[:500]
        return AIScanResult(decision=decision, confidence=confidence, reason=reason)
    except Exception as exc:
        logger.warning("AI response parse failed", extra={"error": str(exc), "raw": raw[:200]})
        return None
