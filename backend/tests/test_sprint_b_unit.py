"""Sprint B unit smoke tests — no DB, no network.

Covers:
  - JWT round-trip + iss/aud/jti claim presence (H10/H11/H12)
  - Strict-mode JWT decode rejects old tokens without jti
  - re2 engine compiles a safe pattern and refuses to compile catastrophic backreferences
  - Rule pattern length cap is enforced
"""
import os
import sys
import time
import uuid

import jwt as pyjwt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def test_jwt_roundtrip_has_strict_claims(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("STRICT_JWT_CLAIMS", "0")
    # reload module to pick env
    import importlib, auth_utils
    importlib.reload(auth_utils)

    tok = auth_utils.create_jwt("cust_123", "alice@example.com")
    claims = auth_utils.decode_jwt(tok)
    assert claims["sub"] == "cust_123"
    assert claims["email"] == "alice@example.com"
    assert claims["iss"] == "sendersafety"
    assert claims["aud"] == "sendersafety-app"
    assert "jti" in claims and len(claims["jti"]) >= 16


def test_jwt_strict_mode_rejects_old_token(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("STRICT_JWT_CLAIMS", "1")
    import importlib, auth_utils
    importlib.reload(auth_utils)

    # Forge an "old style" token — has sub/exp/iat but no jti/iss/aud.
    now = int(time.time())
    legacy = pyjwt.encode(
        {"sub": "cust_xxx", "email": "e@e.com", "exp": now + 3600, "iat": now},
        "x" * 48,
        algorithm="HS256",
    )
    with pytest.raises(Exception):
        auth_utils.decode_jwt(legacy)


def test_jwt_rejects_tampered_signature(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("STRICT_JWT_CLAIMS", "0")
    import importlib, auth_utils
    importlib.reload(auth_utils)

    tok = auth_utils.create_jwt("cust_123", "a@b.com")
    tampered = tok[:-4] + "AAAA"
    with pytest.raises(Exception):
        auth_utils.decode_jwt(tampered)


# ---------------------------------------------------------------------------
# re2 / rule pattern validation
# ---------------------------------------------------------------------------

def test_re2_compiles_safe_pattern():
    import re2
    p = re2.compile(r"(?i)\bcompetitor[a-z]+\b")
    assert p.search("call our COMPETITORX hotline") is not None


def test_re2_rejects_catastrophic_backref():
    # RE2 does not support backreferences — pattern like (.+)+\1 fails compile.
    import re2
    with pytest.raises(re2.error):
        re2.compile(r"(a+)+\1")


def test_rule_pattern_length_cap_enforced(monkeypatch):
    """Length cap is enforced by the Pydantic schema (Field max_length),
    not by _assert_valid_regex. Confirm RuleCreate rejects an oversized pattern.
    """
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    from pydantic import ValidationError
    from routers import rules as rules_mod
    long_pat = "a" * (rules_mod.MAX_PATTERN_LEN + 1)
    with pytest.raises(ValidationError):
        rules_mod.RuleCreate(pattern=long_pat, match_type="regex")


def test_rule_invalid_regex_rejected():
    """RuleService.assert_valid_regex raises InvalidRegexPattern on bad regex."""
    from services import InvalidRegexPattern
    from services.rules import RuleService
    with pytest.raises(InvalidRegexPattern):
        RuleService.assert_valid_regex("(unclosed", "regex")


def test_rule_keyword_skips_regex_validation():
    from services.rules import RuleService
    # Should not raise — keyword type bypasses regex compile.
    RuleService.assert_valid_regex("any string at all (^.+$)", "keyword")


@pytest.mark.asyncio
async def test_rule_create_blocked_at_active_cap(monkeypatch):
    """F-52 — create raises TooManyRules when at the per-customer cap."""
    from services import TooManyRules
    from services.rules import RuleService
    import services.rules as rules_mod

    # Shrink the cap so the test is cheap and obvious.
    monkeypatch.setattr(rules_mod, "MAX_ACTIVE_RULES_PER_CUSTOMER", 3)

    class _FakeRepo:
        async def count_active_for_customer(self, _cid):
            return 3  # already at cap

        async def create(self, **_kw):  # pragma: no cover - should not run
            raise AssertionError("create() must not be called when at cap")

    svc = RuleService(_FakeRepo())
    with pytest.raises(TooManyRules):
        await svc.create(
            customer_id=1, name="x", pattern="foo", match_type="string",
            scope="external", applies_to_email=None, is_exception=False,
            description=None,
        )


@pytest.mark.asyncio
async def test_rule_create_allowed_below_cap(monkeypatch):
    """F-52 — create still works when under the cap."""
    from services.rules import RuleService
    import services.rules as rules_mod

    monkeypatch.setattr(rules_mod, "MAX_ACTIVE_RULES_PER_CUSTOMER", 3)
    created = {}

    class _FakeRepo:
        async def count_active_for_customer(self, _cid):
            return 2

        async def create(self, **kw):
            created.update(kw)
            return {"id": 99, **kw}

    svc = RuleService(_FakeRepo())
    row = await svc.create(
        customer_id=1, name="x", pattern="foo", match_type="string",
        scope="external", applies_to_email=None, is_exception=False,
        description=None,
    )
    assert row["id"] == 99
    assert created["pattern"] == "foo"
