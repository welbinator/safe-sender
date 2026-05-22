"""Unit tests for services/_webhook_helpers — small pure helpers, easy targets."""
from __future__ import annotations

from services._webhook_helpers import emails_and_reason, extract_customer_id_tag


class TestExtractCustomerIdTag:
    UUID = "11111111-2222-3333-4444-555555555555"

    def test_list_form(self):
        assert extract_customer_id_tag({"tags": {"customer_id": [self.UUID]}}) == self.UUID

    def test_string_form(self):
        assert extract_customer_id_tag({"tags": {"customer_id": self.UUID}}) == self.UUID

    def test_camelcase_fallback(self):
        assert extract_customer_id_tag({"tags": {"customerId": [self.UUID]}}) == self.UUID

    def test_missing_returns_none(self):
        assert extract_customer_id_tag({}) is None
        assert extract_customer_id_tag({"tags": {}}) is None

    def test_malformed_returns_none(self):
        # Not a UUID — downgrade to None so we still write a legacy row.
        assert extract_customer_id_tag({"tags": {"customer_id": ["not-a-uuid"]}}) is None

    def test_empty_string(self):
        assert extract_customer_id_tag({"tags": {"customer_id": ""}}) is None


class TestEmailsAndReason:
    def test_permanent_bounce(self):
        body = {
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bounceSubType": "General",
                "bouncedRecipients": [{"emailAddress": "A@Example.com"}],
            },
        }
        emails, reason, detail, recognized = emails_and_reason(body)
        assert recognized is True
        assert emails == ["a@example.com"]
        assert reason == "bounce"
        assert detail == "Permanent/General"

    def test_transient_bounce_does_not_suppress(self):
        body = {
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Transient",
                "bounceSubType": "MailboxFull",
                "bouncedRecipients": [{"emailAddress": "a@example.com"}],
            },
        }
        emails, _, _, recognized = emails_and_reason(body)
        assert recognized is True
        # Soft bounce — recognized but no addresses suppressed.
        assert emails == []

    def test_complaint(self):
        body = {
            "notificationType": "Complaint",
            "complaint": {
                "complaintFeedbackType": "abuse",
                "complainedRecipients": [{"emailAddress": "B@example.com"}],
            },
        }
        emails, reason, detail, recognized = emails_and_reason(body)
        assert recognized is True
        assert emails == ["b@example.com"]
        assert reason == "complaint"
        assert detail == "abuse"

    def test_unknown_type(self):
        emails, reason, detail, recognized = emails_and_reason(
            {"notificationType": "Delivery"}
        )
        assert recognized is False
        assert emails == []
        assert reason == ""
