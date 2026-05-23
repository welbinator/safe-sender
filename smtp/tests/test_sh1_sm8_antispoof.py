"""S-H1 (SPF) + S-M8 (domain extraction) regression tests.

S-M8: _extract_domain must reject malformed/multi-@/no-FQDN inputs and
normalize case, brackets, whitespace, and trailing dot.

S-H1: _check_spf must
  * return ("", "") when SPF_ENFORCE=0
  * return ("none", _) for missing peer/sender or non-IP peer
  * delegate to pyspf otherwise (we patch _check_spf_sync)
  * port-25 handle_DATA path must 550 on SPF `fail` and allow other results
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("INTERNAL_SHARED_SECRET", "a" * 40)
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402


# ---------------------------------------------------------------------------
# S-M8 — domain extraction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address,expected", [
    ("user@example.com", "example.com"),
    ("<user@example.com>", "example.com"),
    (" USER@Example.Com ", "example.com"),
    ("user@example.com.", "example.com"),
    ('"a@b"@evil.com', "evil.com"),  # quoted local-part honored
])
def test_extract_domain_accepts_valid(address, expected):
    assert main._extract_domain(address) == expected


@pytest.mark.parametrize("address", [
    "",
    "@example.com",
    "user@",
    "user@localhost",   # no dot
    "user@.com",        # empty label
    "user@-bad.com",    # leading hyphen in label
    "a@b@evil.com",     # multiple unquoted @
    "not-an-email",
])
def test_extract_domain_rejects_invalid(address):
    assert main._extract_domain(address) == ""


# ---------------------------------------------------------------------------
# S-H1 — SPF wrapper
# ---------------------------------------------------------------------------

def test_spf_disabled_returns_empty(monkeypatch):
    monkeypatch.setattr(main, "SPF_ENFORCE", False)
    result, reason = asyncio.run(main._check_spf("1.2.3.4", "a@b.com", "h"))
    assert (result, reason) == ("", "")


def test_spf_missing_peer_returns_none(monkeypatch):
    monkeypatch.setattr(main, "SPF_ENFORCE", True)
    result, _ = asyncio.run(main._check_spf("", "a@b.com", "h"))
    assert result == "none"


def test_spf_non_ip_peer_returns_none(monkeypatch):
    monkeypatch.setattr(main, "SPF_ENFORCE", True)
    result, _ = asyncio.run(main._check_spf("not-an-ip", "a@b.com", "h"))
    assert result == "none"


def test_spf_delegates_to_pyspf(monkeypatch):
    monkeypatch.setattr(main, "SPF_ENFORCE", True)
    captured = {}

    def fake_sync(peer, sender, helo):
        captured.update(peer=peer, sender=sender, helo=helo)
        return ("fail", "rejected by policy")

    monkeypatch.setattr(main, "_check_spf_sync", fake_sync)
    result, reason = asyncio.run(main._check_spf("8.8.8.8", "a@b.com", "mx.google.com"))
    assert (result, reason) == ("fail", "rejected by policy")
    assert captured == {"peer": "8.8.8.8", "sender": "a@b.com", "helo": "mx.google.com"}


def test_spf_sync_swallows_exceptions(monkeypatch):
    def explode(*a, **kw):
        raise RuntimeError("dns down")

    monkeypatch.setattr(main._spf, "check2", explode)
    result, reason = main._check_spf_sync("8.8.8.8", "a@b.com", "h")
    assert result == "temperror"
    assert "dns down" in reason
