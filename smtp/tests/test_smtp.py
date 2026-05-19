"""
Tests for the Safe Sender SMTP handler (Sprint 2).

Uses unittest.mock to isolate:
  - HTTP calls to backend (_fetch_rules, _log_scan)
  - AWS SES (_forward_via_ses)

Run with:  python -m pytest tests/ -v
"""
import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import the module under test
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import SafeSenderHandler, _rule_matches


# ---------------------------------------------------------------------------
# Unit tests for _rule_matches helper
# ---------------------------------------------------------------------------

class TestRuleMatches:
    def test_keyword_match_subject(self):
        rule = {"pattern": "bitcoin", "match_type": "keyword", "scope": "subject", "is_exception": False}
        assert _rule_matches(rule, "Buy Bitcoin Now", "Hello world") is True

    def test_keyword_no_match_wrong_scope(self):
        """Subject-only rule should NOT trigger on a body match."""
        rule = {"pattern": "bitcoin", "match_type": "keyword", "scope": "subject", "is_exception": False}
        assert _rule_matches(rule, "Hello", "Buy Bitcoin Now") is False

    def test_keyword_body_scope(self):
        rule = {"pattern": "urgent", "match_type": "keyword", "scope": "body", "is_exception": False}
        assert _rule_matches(rule, "Normal subject", "This is urgent please act") is True

    def test_keyword_both_scope(self):
        rule = {"pattern": "spam", "match_type": "keyword", "scope": "both", "is_exception": False}
        assert _rule_matches(rule, "Normal", "This is spam content") is True

    def test_regex_match(self):
        rule = {"pattern": r"\d{4}-\d{4}", "match_type": "regex", "scope": "both", "is_exception": False}
        assert _rule_matches(rule, "Card: 1234-5678", "body") is True

    def test_regex_no_match(self):
        rule = {"pattern": r"\d{4}-\d{4}", "match_type": "regex", "scope": "both", "is_exception": False}
        assert _rule_matches(rule, "Hello world", "No numbers here") is False

    def test_case_insensitive_keyword(self):
        rule = {"pattern": "SPAM", "match_type": "keyword", "scope": "both", "is_exception": False}
        assert _rule_matches(rule, "spam subject", "body") is True


# ---------------------------------------------------------------------------
# Integration-style tests for SafeSenderHandler.handle_DATA
# ---------------------------------------------------------------------------

def _make_envelope(mail_from: str, rcpt_tos: list, content: bytes):
    """Create a minimal mock envelope."""
    env = MagicMock()
    env.mail_from = mail_from
    env.rcpt_tos = rcpt_tos
    env.content = content
    return env


RAW_EMAIL = (
    b"From: sender@example.com\r\n"
    b"To: dest@example.com\r\n"
    b"Subject: Hello\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"This is a clean email body."
)

RULES_CLEAN = {
    "customer_id": 1,
    "rules": [
        {"id": 10, "pattern": "bitcoin", "match_type": "keyword", "scope": "both", "is_exception": False, "applies_to_user": None},
    ],
}

RULES_KEYWORD_BLOCK = {
    "customer_id": 1,
    "rules": [
        {"id": 11, "pattern": "bitcoin", "match_type": "keyword", "scope": "both", "is_exception": False, "applies_to_user": None},
    ],
}

RULES_REGEX_BLOCK = {
    "customer_id": 1,
    "rules": [
        {"id": 12, "pattern": r"buy\s+now", "match_type": "regex", "scope": "both", "is_exception": False, "applies_to_user": None},
    ],
}

RULES_EXCEPTION_OVERRIDE = {
    "customer_id": 1,
    "rules": [
        {"id": 13, "pattern": "bitcoin", "match_type": "keyword", "scope": "both", "is_exception": False, "applies_to_user": None},
        {"id": 14, "pattern": "bitcoin", "match_type": "keyword", "scope": "both", "is_exception": True, "applies_to_user": None},
    ],
}

RULES_SUBJECT_ONLY = {
    "customer_id": 1,
    "rules": [
        {"id": 15, "pattern": "bitcoin", "match_type": "keyword", "scope": "subject", "is_exception": False, "applies_to_user": None},
    ],
}


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSafeSenderHandler:

    def setup_method(self):
        self.handler = SafeSenderHandler()
        self.server = MagicMock()
        self.session = MagicMock()

    @patch("main._log_scan", new_callable=AsyncMock)
    @patch("main._forward_via_ses")
    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_clean_email_passes(self, mock_fetch, mock_ses, mock_log):
        """Clean email should be forwarded via SES with outcome=passed."""
        mock_fetch.return_value = RULES_CLEAN
        envelope = _make_envelope("sender@example.com", ["dest@example.com"], RAW_EMAIL)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        assert result == "250 OK"
        mock_ses.assert_called_once()
        mock_log.assert_called_once()
        assert mock_log.call_args.kwargs["outcome"] == "allowed"

    @patch("main._log_scan", new_callable=AsyncMock)
    @patch("main._forward_via_ses")
    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_keyword_match_blocks(self, mock_fetch, mock_ses, mock_log):
        """Email containing keyword should be blocked."""
        mock_fetch.return_value = RULES_KEYWORD_BLOCK
        raw = (
            b"From: sender@example.com\r\nTo: dest@example.com\r\n"
            b"Subject: Buy Bitcoin\r\nContent-Type: text/plain\r\n\r\nCheck this out."
        )
        envelope = _make_envelope("sender@example.com", ["dest@example.com"], raw)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        assert "550" in result
        mock_ses.assert_not_called()
        assert mock_log.call_args.kwargs["outcome"] == "blocked"

    @patch("main._log_scan", new_callable=AsyncMock)
    @patch("main._forward_via_ses")
    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_regex_match_blocks(self, mock_fetch, mock_ses, mock_log):
        """Email matching regex rule should be blocked."""
        mock_fetch.return_value = RULES_REGEX_BLOCK
        raw = (
            b"From: sender@example.com\r\nTo: dest@example.com\r\n"
            b"Subject: Great deal\r\nContent-Type: text/plain\r\n\r\nBuy Now for a limited time!"
        )
        envelope = _make_envelope("sender@example.com", ["dest@example.com"], raw)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        assert "550" in result
        mock_ses.assert_not_called()
        assert mock_log.call_args.kwargs["outcome"] == "blocked"

    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_unknown_domain_rejected(self, mock_fetch):
        """Unknown domain should return 550 without calling SES."""
        mock_fetch.return_value = None
        envelope = _make_envelope("user@unknown-domain.io", ["dest@example.com"], RAW_EMAIL)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        assert "550" in result
        assert "not registered" in result.lower()

    @patch("main._log_scan", new_callable=AsyncMock)
    @patch("main._forward_via_ses")
    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_subject_only_rule_not_triggered_by_body(self, mock_fetch, mock_ses, mock_log):
        """Subject-scope rule must NOT fire when match is only in body."""
        mock_fetch.return_value = RULES_SUBJECT_ONLY
        raw = (
            b"From: sender@example.com\r\nTo: dest@example.com\r\n"
            b"Subject: Normal subject\r\nContent-Type: text/plain\r\n\r\nBuy bitcoin here."
        )
        envelope = _make_envelope("sender@example.com", ["dest@example.com"], raw)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        # Should pass — keyword is in body but rule scope is subject-only
        assert result == "250 OK"
        mock_ses.assert_called_once()
        assert mock_log.call_args.kwargs["outcome"] == "allowed"

    @patch("main._log_scan", new_callable=AsyncMock)
    @patch("main._forward_via_ses")
    @patch("main._fetch_rules", new_callable=AsyncMock)
    def test_exception_rule_overrides_match(self, mock_fetch, mock_ses, mock_log):
        """Exception rule that also matches should override the normal block."""
        mock_fetch.return_value = RULES_EXCEPTION_OVERRIDE
        raw = (
            b"From: sender@example.com\r\nTo: dest@example.com\r\n"
            b"Subject: Bitcoin news\r\nContent-Type: text/plain\r\n\r\nHello."
        )
        envelope = _make_envelope("sender@example.com", ["dest@example.com"], raw)

        result = run(self.handler.handle_DATA(self.server, self.session, envelope))

        # Exception rule overrides — should pass
        assert result == "250 OK"
        mock_ses.assert_called_once()
        assert mock_log.call_args.kwargs["outcome"] == "allowed"
