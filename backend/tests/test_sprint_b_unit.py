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
    """_assert_valid_regex raises 422 on a regex re2 can't compile."""
    from fastapi import HTTPException
    from routers import rules as rules_mod
    with pytest.raises(HTTPException) as exc:
        rules_mod._assert_valid_regex("(unclosed", "regex")
    assert exc.value.status_code == 422


def test_rule_keyword_skips_regex_validation():
    from routers import rules as rules_mod
    # Should not raise — keyword type bypasses regex compile.
    rules_mod._assert_valid_regex("any string at all (^.+$)", "keyword")
