"""F-26: dual-secret rotation for the internal shared secret."""
import importlib
import secrets
import sys

import hmac
import pytest
from fastapi import HTTPException


def _reload(monkeypatch, *, current: str, previous: str | None) -> object:
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", current)
    if previous is None:
        monkeypatch.delenv("INTERNAL_SHARED_SECRET_PREVIOUS", raising=False)
    else:
        monkeypatch.setenv("INTERNAL_SHARED_SECRET_PREVIOUS", previous)
    sys.modules.pop("internal_auth", None)
    return importlib.import_module("internal_auth")


@pytest.mark.asyncio
async def test_current_secret_accepted(monkeypatch):
    s = secrets.token_urlsafe(48)
    mod = _reload(monkeypatch, current=s, previous=None)
    await mod.require_internal_secret(x_internal_secret=s)  # no raise


@pytest.mark.asyncio
async def test_previous_secret_accepted_during_rotation(monkeypatch):
    s1 = secrets.token_urlsafe(48)
    s2 = secrets.token_urlsafe(48)
    mod = _reload(monkeypatch, current=s2, previous=s1)
    # Both work — that's the whole point of dual-slot rotation.
    await mod.require_internal_secret(x_internal_secret=s2)
    await mod.require_internal_secret(x_internal_secret=s1)


@pytest.mark.asyncio
async def test_dropped_previous_secret_rejected(monkeypatch):
    s1 = secrets.token_urlsafe(48)
    s2 = secrets.token_urlsafe(48)
    mod = _reload(monkeypatch, current=s2, previous=None)
    with pytest.raises(HTTPException) as exc:
        await mod.require_internal_secret(x_internal_secret=s1)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_random_secret_rejected(monkeypatch):
    s = secrets.token_urlsafe(48)
    mod = _reload(monkeypatch, current=s, previous=None)
    with pytest.raises(HTTPException):
        await mod.require_internal_secret(x_internal_secret="nope" * 16)


def test_previous_same_as_current_refuses_startup(monkeypatch):
    s = secrets.token_urlsafe(48)
    with pytest.raises(RuntimeError, match="equals INTERNAL_SHARED_SECRET"):
        _reload(monkeypatch, current=s, previous=s)


def test_weak_previous_secret_refuses_startup(monkeypatch):
    s = secrets.token_urlsafe(48)
    with pytest.raises(RuntimeError, match="PREVIOUS"):
        _reload(monkeypatch, current=s, previous="changeme")
