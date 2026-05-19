"""
Sprint 3 integration tests — auth, customers, rules, logs.

Runs against the LIVE server at http://localhost:8000 (inside the container).
No event-loop gymnastics: plain httpx, no TestClient, no asyncpg cross-loop issues.

Requires:
  - Server running with ALLOW_TEST_TOKENS=1
  - JWT_SECRET set (any value)
"""
import json
import os
import uuid

import httpx
import pytest

BASE = "http://localhost:8000"
client = httpx.Client(base_url=BASE, timeout=10)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fake_google_token(sub: str, email: str, name: str = "Test Corp") -> str:
    """Encode fake claims as 'test:<json>' — accepted when ALLOW_TEST_TOKENS=1."""
    claims = {"sub": sub, "email": email, "name": name, "aud": ""}
    return "test:" + json.dumps(claims)


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def register_customer(domain: str = None, sub: str = None) -> dict:
    domain = domain or f"test-{uuid.uuid4().hex[:8]}.example.com"
    sub = sub or f"gsub-{uuid.uuid4().hex}"
    email = f"admin@{domain}"
    resp = client.post(
        "/auth/google",
        json={
            "id_token": fake_google_token(sub, email),
            "domain": domain,
            "company_name": "Test Corp",
        },
    )
    assert resp.status_code == 200, f"register_customer failed: {resp.status_code} {resp.text}"
    data = resp.json()
    return {
        "token": data["access_token"],
        "customer_id": data["customer_id"],
        "email": email,
        "domain": domain,
        "sub": sub,
        "is_new": data["is_new"],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fake_customer():
    return register_customer()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuthGoogle:
    def test_new_customer(self, fake_customer):
        assert fake_customer["is_new"] is True
        assert fake_customer["token"]
        assert fake_customer["customer_id"]

    def test_existing_customer_same_sub_returns_token(self, fake_customer):
        """Re-login with same google_sub → is_new=False."""
        resp = client.post(
            "/auth/google",
            json={
                "id_token": fake_google_token(fake_customer["sub"], fake_customer["email"]),
                "domain": fake_customer["domain"],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_new"] is False

    def test_duplicate_domain_different_sub_returns_409(self, fake_customer):
        other_sub = f"gsub-other-{uuid.uuid4().hex}"
        other_email = f"other@{fake_customer['domain']}"
        resp = client.post(
            "/auth/google",
            json={
                "id_token": fake_google_token(other_sub, other_email),
                "domain": fake_customer["domain"],
            },
        )
        assert resp.status_code == 409

    def test_invalid_token_returns_401_or_500(self):
        resp = client.post("/auth/google", json={"id_token": "not-a-real-token"})
        assert resp.status_code in (401, 500)


# ---------------------------------------------------------------------------
# Customer tests
# ---------------------------------------------------------------------------

class TestCustomers:
    def test_get_me(self, fake_customer):
        resp = client.get("/customers/me", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == fake_customer["email"]
        assert data["domain"] == fake_customer["domain"]

    def test_get_me_no_auth(self):
        resp = client.get("/customers/me")
        assert resp.status_code == 403

    def test_patch_me(self, fake_customer):
        resp = client.patch(
            "/customers/me",
            headers=auth_headers(fake_customer["token"]),
            json={"name": "Updated Corp"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Corp"

    def test_invalid_jwt_returns_401(self):
        resp = client.get(
            "/customers/me",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rules tests
# ---------------------------------------------------------------------------

class TestRules:
    def test_list_rules_empty(self, fake_customer):
        resp = client.get("/rules", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        # May have rules if module fixture is shared; just confirm it's a list
        assert isinstance(resp.json(), list)

    def test_create_rule_string(self, fake_customer):
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

    def test_create_rule_regex(self, fake_customer):
        resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": r"\bSSN\b", "match_type": "regex", "scope": "external"},
        )
        assert resp.status_code == 201

    def test_create_rule_invalid_regex(self, fake_customer):
        resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "[unclosed", "match_type": "regex"},
        )
        assert resp.status_code == 422

    def test_list_rules_after_create(self, fake_customer):
        resp = client.get("/rules", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_update_rule(self, fake_customer):
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

    def test_delete_rule(self, fake_customer):
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

    def test_delete_nonexistent_rule(self, fake_customer):
        resp = client.delete(
            f"/rules/{uuid.uuid4()}",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 404

    def test_cannot_access_other_customers_rule(self, fake_customer):
        """Customer A cannot delete a rule that belongs to customer B."""
        create_resp = client.post(
            "/rules",
            headers=auth_headers(fake_customer["token"]),
            json={"pattern": "mine", "match_type": "string"},
        )
        rule_id = create_resp.json()["id"]

        customer2 = register_customer()
        del_resp = client.delete(
            f"/rules/{rule_id}",
            headers=auth_headers(customer2["token"]),
        )
        assert del_resp.status_code == 404


# ---------------------------------------------------------------------------
# Logs tests
# ---------------------------------------------------------------------------

class TestLogs:
    def test_list_logs_empty(self, fake_customer):
        resp = client.get("/logs", headers=auth_headers(fake_customer["token"]))
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 1
        assert isinstance(data["results"], list)

    def test_logs_pagination_params(self, fake_customer):
        resp = client.get(
            "/logs?page=1&page_size=10",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["page_size"] == 10

    def test_logs_invalid_outcome(self, fake_customer):
        resp = client.get(
            "/logs?outcome=invalid",
            headers=auth_headers(fake_customer["token"]),
        )
        assert resp.status_code == 422
