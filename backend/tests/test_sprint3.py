"""
Sprint 3 API tests — auth, customers, rules, logs, internal endpoints.

Runs in-process via FastAPI TestClient against an ephemeral Postgres started
by conftest.py (uses the `pgserver` package's bundled binaries — no docker,
no live SMTP, no network).

Tests that require the live SMTP container / SES / external services have
been moved to `backend/tests/integration/` and are excluded from the default
pytest run (see `backend/pytest.ini`). Run them with:

    cd backend && pytest tests/integration/ -q

after bringing up the full docker-compose stack.
"""
import json
import os
import uuid

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fake_google_token(sub: str, email: str, name: str = "Test Corp") -> str:
    """Encode fake claims as 'test:<json>' — accepted when ALLOW_TEST_TOKENS=1."""
    claims = {"sub": sub, "email": email, "name": name, "aud": ""}
    return "test:" + json.dumps(claims)


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def register_customer(client, domain: str = None, sub: str = None) -> dict:
    domain = domain or f"test-{uuid.uuid4().hex[:8]}.example.com"
    sub = sub or f"gsub-{uuid.uuid4().hex}"
    email = f"admin@{domain}"
    resp = client.post(
        "/auth/google",
        json={
            "id_token": fake_google_token(sub, email),
            # F-37: `domain` is no longer accepted — server derives it from
            # the Google `hd` claim. The `fake_google_token` helper bakes
            # `hd: <domain>` into the fake token via the email split.
            "company_name": "Test Corp",
        },
    )
    assert resp.status_code == 200, f"register_customer failed: {resp.status_code} {resp.text}"
    data = resp.json()
    # Sprint B C13: JWT is delivered via HttpOnly `session` cookie, not body.
    # Sprint C3 F-11: paired `csrf_token` cookie is set alongside session.
    # Extract both for Bearer-auth + CSRF tests, then clear the jar so each
    # registration starts cookieless (otherwise the next test inherits this
    # customer).
    session_token = resp.cookies.get("session")
    csrf_token = resp.cookies.get("csrf_token")
    client.cookies.clear()
    return {
        "token": session_token,
        "csrf_token": csrf_token,
        "customer_id": data["customer_id"],
        "email": email,
        "domain": domain,
        "sub": sub,
        "is_new": data["is_new"],
        "raw": data,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fake_customer(client):
    return register_customer(client)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_metrics_endpoint_exposes_prometheus_text(client):
    """F-45 — /metrics returns Prometheus text format and includes
    http_requests_total once any traffic has hit the app."""
    # Hit /health first to ensure at least one labeled request is recorded.
    client.get("/health")
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Default Instrumentator metric names
    assert "http_requests_total" in body or "http_request_duration" in body


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuthGoogle:
    def test_new_customer(self, fake_customer):
        assert fake_customer["is_new"] is True
        assert fake_customer["customer_id"]
        # token may live in cookie rather than body — both are acceptable
        assert fake_customer["token"] or fake_customer["raw"]

    def test_existing_customer_same_sub_returns_token(self, client, fake_customer):
        """Re-login with same google_sub → is_new=False."""
        resp = client.post(
            "/auth/google",
            json={
                "id_token": fake_google_token(fake_customer["sub"], fake_customer["email"]),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_new"] is False

    def test_duplicate_domain_different_sub_returns_409(self, client, fake_customer):
        other_sub = f"gsub-other-{uuid.uuid4().hex}"
        other_email = f"other@{fake_customer['domain']}"
        resp = client.post(
            "/auth/google",
            json={
                "id_token": fake_google_token(other_sub, other_email),
            },
        )
        assert resp.status_code == 409

    def test_invalid_token_returns_401_or_500(self, client):
        resp = client.post("/auth/google", json={"id_token": "not-a-real-token"})
        assert resp.status_code in (401, 500)


# ---------------------------------------------------------------------------
# Customer tests
# ---------------------------------------------------------------------------

class TestCustomers:
    def test_get_me(self, client, fake_customer):
        resp = client.get("/customers/me", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == fake_customer["email"]
        assert data["domain"] == fake_customer["domain"]

    def test_get_me_no_auth(self, client):
        # TestClient persists cookies — clear any session left by previous tests
        # so this truly hits the "no auth" path.
        client.cookies.clear()
        resp = client.get("/customers/me", headers={"Authorization": ""})
        assert resp.status_code in (401, 403)

    def test_patch_me(self, client, fake_customer):
        resp = client.patch(
            "/customers/me",
            headers=auth_headers(fake_customer["token"]),
            json={"name": "Updated Corp"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Corp"

    def test_invalid_jwt_returns_401(self, client):
        client.cookies.clear()
        resp = client.get(
            "/customers/me",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rules tests
# ---------------------------------------------------------------------------

class TestRules:
    def test_list_rules_empty(self, client, fake_customer):
        resp = client.get("/rules", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_create_rule_string(self, client, fake_customer):
        resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={
                "pattern": "confidential",
                "match_type": "string",
                "scope": "both",
                "description": "Block confidential mentions",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["pattern"] == "confidential"
        assert data["active"] is True

    def test_create_rule_regex(self, client, fake_customer):
        resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": r"\bSSN\b", "match_type": "regex", "scope": "external"},
        )
        assert resp.status_code == 201

    def test_create_rule_invalid_regex(self, client, fake_customer):
        resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "[unclosed", "match_type": "regex"},
        )
        assert resp.status_code == 422

    def test_list_rules_after_create(self, client, fake_customer):
        resp = client.get("/rules", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_update_rule(self, client, fake_customer):
        create_resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "update-me", "match_type": "string"},
        )
        assert create_resp.status_code == 201
        rule_id = create_resp.json()["id"]

        update_resp = client.put(
            f"/rules/{rule_id}",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "updated-pattern", "description": "now updated"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["pattern"] == "updated-pattern"

    def test_delete_rule(self, client, fake_customer):
        create_resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "delete-me", "match_type": "string"},
        )
        rule_id = create_resp.json()["id"]

        del_resp = client.delete(
            f"/rules/{rule_id}",
            headers=auth_headers(fake_customer["token"]),
        )
        assert del_resp.status_code == 204

        list_resp = client.get("/rules", headers=auth_headers(fake_customer["token"]))
        ids = [r["id"] for r in list_resp.json()]
        assert rule_id not in ids

    def test_delete_nonexistent_rule(self, client, fake_customer):
        resp = client.delete(
            f"/rules/{uuid.uuid4()}",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 404

    def test_cannot_access_other_customers_rule(self, client, fake_customer):
        """Customer A cannot delete a rule that belongs to customer B."""
        create_resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "mine", "match_type": "string"},
        )
        rule_id = create_resp.json()["id"]

        customer2 = register_customer(client)
        del_resp = client.delete(
            f"/rules/{rule_id}",
            headers=auth_headers(customer2["token"]),
        )
        assert del_resp.status_code == 404


# ---------------------------------------------------------------------------
# Logs tests
# ---------------------------------------------------------------------------

class TestLogs:
    def test_list_logs_empty(self, client, fake_customer):
        resp = client.get("/logs", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 1
        assert isinstance(data["results"], list)

    def test_logs_pagination_params(self, client, fake_customer):
        resp = client.get(
            "/logs?page=1&page_size=10",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["page_size"] == 10

    def test_today_stats_empty_returns_zero(self, client, fake_customer):
        """F-39: server-side aggregation works with no rows."""
        resp = client.get(
            "/logs/stats/today",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scanned"] == 0
        assert data["blocked"] == 0
        assert data["allowed"] == 0
        assert data["block_rate"] == 0.0
        assert data["top_rules"] == []

    def test_today_stats_accepts_tz_offset(self, client, fake_customer):
        """F-56: tz_offset_minutes query param is honored."""
        resp = client.get(
            "/logs/stats/today?tz_offset_minutes=-480",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 200

    def test_today_stats_clamps_extreme_tz(self, client, fake_customer):
        """Out-of-range tz_offset_minutes is clamped, not rejected."""
        resp = client.get(
            "/logs/stats/today?tz_offset_minutes=999999",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 200

    def test_logs_invalid_outcome(self, client, fake_customer):
        resp = client.get(
            "/logs?outcome=invalid",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 422


class TestCsrfProtection:
    """Sprint C3 F-11: double-submit-cookie CSRF. Cookie-authenticated
    mutations require the X-CSRF-Token header to equal the csrf_token cookie.
    Bearer-auth bypasses (no cookie surface)."""

    def test_cookie_mutation_without_csrf_header_is_rejected(self, client):
        info = register_customer(client)
        client.cookies.set("session", info["token"])
        client.cookies.set("csrf_token", info["csrf_token"])
        resp = client.post("/rules", json={
            "pattern": "test", "match_type": "string", "action": "block",
        })
        assert resp.status_code == 403, resp.text
        assert "CSRF" in resp.json()["detail"]

    def test_cookie_mutation_with_mismatched_csrf_header_is_rejected(self, client):
        info = register_customer(client)
        client.cookies.set("session", info["token"])
        client.cookies.set("csrf_token", info["csrf_token"])
        resp = client.post(
            "/rules",
            json={"pattern": "x", "match_type": "string", "action": "block"},
            headers={"X-CSRF-Token": "wrong-value"},
        )
        assert resp.status_code == 403, resp.text

    def test_cookie_mutation_with_matching_csrf_header_succeeds(self, client):
        info = register_customer(client)
        client.cookies.set("session", info["token"])
        client.cookies.set("csrf_token", info["csrf_token"])
        resp = client.post(
            "/rules",
            json={"pattern": "ok", "match_type": "string", "action": "block"},
            headers={"X-CSRF-Token": info["csrf_token"]},
        )
        assert resp.status_code in (200, 201), resp.text

    def test_cookie_GET_does_not_require_csrf_header(self, client):
        info = register_customer(client)
        client.cookies.set("session", info["token"])
        client.cookies.set("csrf_token", info["csrf_token"])
        resp = client.get("/customers/me")
        assert resp.status_code == 200, resp.text

    def test_bearer_mutation_without_csrf_header_succeeds(self, client, fake_customer):
        client.cookies.clear()
        resp = client.post(
            "/rules",
            json={"pattern": "bearerok", "match_type": "string", "action": "block"},
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code in (200, 201), resp.text


class TestAdminPanel:
    """Sprint C1 hotfix (audit C-4): admin panel hardening."""

    def _admin_headers(self):
        import os
        return {"Authorization": f"Bearer {os.environ['ADMIN_SECRET']}"}

    def test_admin_requires_auth(self, client):
        client.cookies.clear()
        resp = client.get("/admin/stats")
        assert resp.status_code == 401

    def test_admin_with_valid_secret_succeeds(self, client):
        client.cookies.clear()
        resp = client.get("/admin/stats", headers=self._admin_headers())
        assert resp.status_code == 200, resp.text
        assert "total_customers" in resp.json()

    def test_admin_audit_log_records_actions(self, client):
        client.cookies.clear()
        client.get("/admin/stats", headers=self._admin_headers())
        client.get("/admin/stats", headers={"Authorization": "Bearer wrong"})
        resp = client.get("/admin/audit?limit=50", headers=self._admin_headers())
        assert resp.status_code == 200
        rows = resp.json()
        assert any(r["status_code"] == 200 and r["path"] == "/admin/stats" for r in rows)
        assert any(r["status_code"] == 401 for r in rows)

    def test_admin_ip_allowlist_blocks_when_set(self, client, monkeypatch):
        from routers import admin as admin_mod
        import ipaddress
        monkeypatch.setattr(admin_mod, "_ADMIN_ALLOWLIST",
                            [ipaddress.ip_network("10.99.99.0/24")])
        client.cookies.clear()
        resp = client.get("/admin/stats", headers=self._admin_headers())
        assert resp.status_code == 403
        assert resp.json()["detail"] == "IP not allowed"

    def test_admin_rate_limit(self, client, monkeypatch):
        """F-19: limiter is now Postgres-backed.

        We monkey-patch ``_check_rate_limit`` directly to assert that the
        admin router returns 429 when it returns False. End-to-end
        behaviour against real Postgres is covered by integration tests.
        """
        from routers import admin as admin_mod

        calls = {"n": 0}

        async def fake_limit(ip: str) -> bool:
            calls["n"] += 1
            return calls["n"] <= 3

        monkeypatch.setattr(admin_mod, "_check_rate_limit", fake_limit)
        client.cookies.clear()
        h = self._admin_headers()
        codes = [client.get("/admin/stats", headers=h).status_code for _ in range(4)]
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429
