"""Batch H — backend medium-severity audit fixes (M-1..M-7).

Unit-level checks for the kill-switch / hardening logic. Integration
coverage for suppression and scan-log endpoints already exists in
test_sprint_b_*.py.
"""
import importlib
import inspect
import os
from uuid import uuid4

import pytest


# Force env-seeding (and the pgserver) before any of our imports touch
# main/routers — they fail-fast at import time on weak JWT/INTERNAL secrets.
@pytest.fixture(autouse=True)
def _ensure_env(_seed_env, client):  # noqa: ARG001 -- request fixtures only
    yield


# ---------------------------------------------------------------------------
# M-1 — SNS cert fetch hardening (size cap, no redirects, negative cache)
# ---------------------------------------------------------------------------

def test_m1_cert_fetcher_uses_no_redirect_opener():
    """A custom opener must be installed that refuses HTTP redirects."""
    import sns_validator as sv
    handler_types = [type(h).__name__ for h in sv._NO_REDIRECT_OPENER.handlers]
    assert "_NoRedirectHandler" in handler_types, (
        "M-1: SNS cert fetch must use the no-redirect handler — a redirect "
        "to attacker-controlled bytes would bypass the amazonaws.com allowlist."
    )


def test_m1_cert_size_cap_constant_present():
    import sns_validator as sv
    # Plenty of headroom over a real ~1.5 KiB SNS signing cert.
    assert 1024 <= sv._MAX_CERT_BYTES <= 1024 * 1024


def test_m1_negative_cache_present():
    import sns_validator as sv
    assert isinstance(sv._CERT_NEG_CACHE, dict)
    assert sv._CERT_NEG_TTL > 0


def test_m1_no_redirect_handler_raises():
    """The redirect handler must raise SNSValidationError, not follow."""
    import sns_validator as sv
    h = sv._NoRedirectHandler()
    with pytest.raises(sv.SNSValidationError):
        h.http_error_301(None, None, 301, "moved", {})
    with pytest.raises(sv.SNSValidationError):
        h.http_error_302(None, None, 302, "found", {})


# ---------------------------------------------------------------------------
# M-2 — SHA-1 SigVer 1 kill switch
# ---------------------------------------------------------------------------

def test_m2_require_sig_v2_rejects_sha1(monkeypatch):
    """When SNS_REQUIRE_SIG_V2=1, a SignatureVersion=1 message is refused."""
    monkeypatch.setenv("SNS_REQUIRE_SIG_V2", "1")
    import sns_validator as sv
    sv = importlib.reload(sv)
    msg = {
        "Type": "Notification",
        "MessageId": "x",
        "TopicArn": "arn:aws:sns:us-east-2:1:t",
        "Subject": "s",
        "Message": "m",
        "Timestamp": "2026-01-01T00:00:00.000Z",
        "SignatureVersion": "1",
        "Signature": "AAA",
        "SigningCertURL": "https://sns.us-east-2.amazonaws.com/x.pem",
    }
    with pytest.raises(sv.SNSValidationError, match="SNS_REQUIRE_SIG_V2"):
        sv.verify_sns_message(msg, ["arn:aws:sns:us-east-2:1:t"])
    monkeypatch.delenv("SNS_REQUIRE_SIG_V2", raising=False)
    importlib.reload(sv)


def test_m2_default_is_off_for_backward_compat(monkeypatch):
    monkeypatch.delenv("SNS_REQUIRE_SIG_V2", raising=False)
    import sns_validator as sv
    sv = importlib.reload(sv)
    assert sv._REQUIRE_SIG_V2 is False


# ---------------------------------------------------------------------------
# M-3 — SNS subscription-confirm task strong references
# ---------------------------------------------------------------------------

def test_m3_background_task_set_exists():
    from routers import webhooks
    assert hasattr(webhooks, "_BACKGROUND_TASKS")
    assert isinstance(webhooks._BACKGROUND_TASKS, set)


def test_m3_create_task_is_tracked():
    """Source-level: the create_task call site must add to the strong-ref set."""
    from routers import webhooks
    src = inspect.getsource(webhooks)
    assert "_BACKGROUND_TASKS.add" in src
    assert "add_done_callback(_BACKGROUND_TASKS.discard)" in src


# ---------------------------------------------------------------------------
# M-4 — Google OAuth error logging redaction
# ---------------------------------------------------------------------------

def test_m4_oauth_error_log_does_not_include_raw_body():
    """The warning at google_token_exchange_rejected must not log the raw body."""
    from routers import auth as auth_mod
    src = inspect.getsource(auth_mod)
    idx = src.find("google_token_exchange_rejected")
    assert idx > 0, "expected the rejection log site to exist"
    window = src[idx: idx + 1000]
    assert "tok_resp.text" not in window, (
        "M-4: Google's token endpoint can echo request fields (including the "
        "auth code) in error bodies — log only parsed `error` / "
        "`error_description` fields."
    )


# ---------------------------------------------------------------------------
# M-5 — ScanLogRequest.customer_id is a UUID; sender↔customer binding
# ---------------------------------------------------------------------------

def test_m5_scan_log_customer_id_rejects_garbage():
    from routers.internal_scan import ScanLogRequest
    with pytest.raises(Exception):
        ScanLogRequest(
            customer_id="not-a-uuid",
            sender="a@example.com",
            recipient="b@example.com",
            subject_hash="0" * 64,
            outcome="allowed",
        )


def test_m5_scan_log_customer_id_accepts_uuid():
    from routers.internal_scan import ScanLogRequest
    cid = uuid4()
    req = ScanLogRequest(
        customer_id=str(cid),
        sender="a@example.com",
        recipient="b@example.com",
        subject_hash="0" * 64,
        outcome="allowed",
    )
    assert str(req.customer_id) == str(cid)


def test_m5_scan_log_handler_has_bind_check():
    """The /internal/scan-log handler must read SCAN_LOG_BIND_SENDER."""
    import main
    from routers import internal_scan; src = inspect.getsource(internal_scan.create_scan_log)
    assert "SCAN_LOG_BIND_SENDER" in src
    assert "scan_log_sender_customer_mismatch" in src


# ---------------------------------------------------------------------------
# M-6 — SUPPRESSION_LEGACY_NULL kill switch
# ---------------------------------------------------------------------------

def test_m6_suppression_endpoint_has_kill_switch():
    from routers import internal_suppression
    src = inspect.getsource(internal_suppression.check_suppressed)
    assert "SUPPRESSION_LEGACY_NULL" in src
    # Legacy path must still allow NULL rows; strict path must not.
    legacy, _, strict = src.partition("else:")
    assert "customer_id IS NULL" in legacy
    assert "customer_id IS NULL" not in strict


# ---------------------------------------------------------------------------
# M-7 — DB SSL opt-in
# ---------------------------------------------------------------------------

def test_m7_db_ssl_env_var_wired():
    import main
    src = inspect.getsource(main)
    assert 'os.environ.get("DB_SSL")' in src, (
        "M-7: asyncpg pool must read DB_SSL env so prod can require TLS."
    )
