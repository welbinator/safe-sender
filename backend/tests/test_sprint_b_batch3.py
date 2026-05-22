"""Sprint B Batch 3 unit tests — C13 cookie auth fallback to header.

We don't spin up the FastAPI app here (no DB available in unit tests).
Instead we exercise the pure transport-extraction logic in deps.py.
"""
import importlib
import sys
import types

import pytest
from fastapi import HTTPException


def _load_deps_module():
    """Import deps.py with the minimum stub modules it needs.

    deps imports auth_utils.decode_jwt and asyncpg, but for transport-extraction
    tests we never call decode_jwt — we just call the helper that pulls the raw
    token string from the request.
    """
    sys.path.insert(0, '/home/highprrrr/safe-sender/backend')
    # auth_utils refuses to import without a strong JWT_SECRET. Provide one.
    import os
    os.environ.setdefault("JWT_SECRET", "x" * 48)
    import auth_utils  # noqa: F401
    if 'deps' in sys.modules:
        return importlib.reload(sys.modules['deps'])
    return importlib.import_module('deps')


def _make_request(*, cookie_token=None, auth_header=None):
    """Build a minimal object that quacks like fastapi.Request for our helper."""
    cookies = {}
    if cookie_token is not None:
        cookies['session'] = cookie_token
    headers = {}
    if auth_header is not None:
        headers['authorization'] = auth_header

    class Req:
        pass
    r = Req()
    r.cookies = cookies
    # Starlette Headers is case-insensitive; dict.get is good enough here
    # because _extract_token() looks up "authorization" (already lowercase).
    r.headers = headers
    # Sprint C1 C-3 hotfix: _extract_token() inspects request.method on the
    # cookie path to enforce CSRF on mutating verbs. These tests focus on the
    # cookie/header precedence rules, so default to GET.
    r.method = "GET"
    return r


def test_extract_token_prefers_cookie():
    deps = _load_deps_module()
    req = _make_request(auth_header="Bearer HEADER_JWT")
    assert deps._extract_token(req, "COOKIE_JWT") == "COOKIE_JWT"


def test_extract_token_falls_back_to_bearer_header():
    deps = _load_deps_module()
    req = _make_request(auth_header="Bearer HEADER_JWT")
    assert deps._extract_token(req, None) == "HEADER_JWT"


def test_extract_token_accepts_bearer_case_insensitive():
    deps = _load_deps_module()
    req = _make_request(auth_header="bearer HEADER_JWT")
    assert deps._extract_token(req, None) == "HEADER_JWT"


def test_extract_token_401_when_no_credentials():
    deps = _load_deps_module()
    req = _make_request()
    with pytest.raises(HTTPException) as exc:
        deps._extract_token(req, None)
    assert exc.value.status_code == 401


def test_extract_token_401_when_malformed_auth_header():
    deps = _load_deps_module()
    req = _make_request(auth_header="Basic abc")
    with pytest.raises(HTTPException) as exc:
        deps._extract_token(req, None)
    assert exc.value.status_code == 401


def test_extract_token_ignores_bearer_when_disabled(monkeypatch):
    """When ALLOW_BEARER_AUTH=0, only the cookie is honored."""
    monkeypatch.setenv("ALLOW_BEARER_AUTH", "0")
    deps = _load_deps_module()
    req = _make_request(auth_header="Bearer HEADER_JWT")
    with pytest.raises(HTTPException) as exc:
        deps._extract_token(req, None)
    assert exc.value.status_code == 401
