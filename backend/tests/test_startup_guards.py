"""Startup-time configuration guards (Sprint C1, audit H-3)."""
import importlib
import sys

import pytest


def _reload_main(monkeypatch, env):
    """Clear cached module and re-import main with patched env."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # Seed unrelated required secrets so downstream imports (internal_auth,
    # auth_utils, routers.admin) don't raise before our DB guard does.
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "x" * 48)
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("ADMIN_API_KEY", "x" * 48)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for mod in ("main", "internal_auth", "auth_utils"):
        sys.modules.pop(mod, None)
    return importlib.import_module("main")


def test_missing_database_url_raises(monkeypatch):
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        _reload_main(monkeypatch, {})


def test_weak_database_url_raises(monkeypatch):
    with pytest.raises(RuntimeError, match="weak"):
        _reload_main(
            monkeypatch,
            {"DATABASE_URL": "postgresql://u:changeme@h/d"},
        )


def test_valid_database_url_accepted(monkeypatch):
    mod = _reload_main(
        monkeypatch,
        {"DATABASE_URL": "postgresql://u:S3cur3-x9!@h/d"},
    )
    assert mod.DATABASE_URL.endswith("/d")
