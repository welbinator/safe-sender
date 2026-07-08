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
import re
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host-gateway:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))

SYSTEM_PROMPT = (
    "You are a precise outbound email compliance reviewer. "
    "Your job is to decide whether an email clearly violates a compliance policy. "
    "You must reason carefully before deciding. "
    "IMPORTANT RULES:\n"
    "- Only flag an email if you find EXPLICIT, UNAMBIGUOUS evidence of a violation in the email text itself.\n"
    "- Do NOT make assumptions or inferences beyond what is directly stated.\n"
    "- A common first name (e.g. 'Joe', 'Mike', 'Donald') without additional context identifying that person "
    "as a political figure is NOT a violation.\n"
    "- When in doubt, pass. A false positive that blocks a legitimate email is worse than a false negative.\n"
    "- Minor misspellings of a clearly identifiable name (e.g. 'Joe Byden') still count as that name.\n"
    "Respond in this exact format:\n"
    "REASONING: <think through each policy against the email — cite specific words or phrases that are or are not violations>\n"
    "VERDICT: <'flag' or 'pass'>\n"
    "CONFIDENCE: <0-100 — use 100 only for unambiguous violations, lower for anything borderline>\n"
    "REASON: <one sentence explaining the verdict>"
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
        "Review the email against each policy. Show your reasoning, then give your verdict."
    )

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        # NOTE: no "format": "json" — that suppresses chain-of-thought reasoning.
        # We parse the structured text response ourselves below.
        "keep_alive": "1h",
        "options": {"temperature": 0, "num_ctx": 4096},
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

    logger.debug("AI raw response", extra={"response": raw[:500]})

    try:
        # Parse structured text response
        verdict_match = re.search(r"VERDICT:\s*(flag|pass)", raw, re.IGNORECASE)
        confidence_match = re.search(r"CONFIDENCE:\s*(\d+)", raw, re.IGNORECASE)
        reason_match = re.search(r"REASON:\s*(.+?)(?:\n|$)", raw, re.IGNORECASE)

        if not verdict_match:
            logger.warning("AI response missing VERDICT field", extra={"raw": raw[:300]})
            return None

        decision = verdict_match.group(1).lower()
        confidence = min(100, max(0, int(confidence_match.group(1)))) if confidence_match else 50
        reason = reason_match.group(1).strip()[:500] if reason_match else ""

        return AIScanResult(decision=decision, confidence=confidence, reason=reason)

    except Exception as exc:
        logger.warning("AI response parse failed", extra={"error": str(exc), "raw": raw[:300]})
        return None
