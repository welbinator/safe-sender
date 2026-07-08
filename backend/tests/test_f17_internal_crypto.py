"""F-17: field-level encryption for backend↔smtp internal channel."""
import os
import sys
import pytest


# Depending on `client` (or `_seed_env`) guarantees DATABASE_URL,
# INTERNAL_SHARED_SECRET, etc. are set before we import internal_crypto.
@pytest.fixture()
def crypto(client):
    sys.modules.pop("internal_crypto", None)
    import internal_crypto
    return internal_crypto


def test_roundtrip_encrypt_decrypt(crypto):
    token = crypto.encrypt_field("deadbeef" * 8)
    assert isinstance(token, str)
    assert "deadbeef" not in token  # confidentiality smoke
    assert crypto.decrypt_field(token).decode("ascii") == "deadbeef" * 8


def test_token_is_nondeterministic(crypto):
    """Fernet includes a random IV; same plaintext -> different ciphertext."""
    t1 = crypto.encrypt_field("abc123")
    t2 = crypto.encrypt_field("abc123")
    assert t1 != t2


def test_invalid_token_raises(crypto):
    with pytest.raises(crypto.InvalidToken):
        crypto.decrypt_field("gAAAAA" + "X" * 100)


def test_previous_secret_can_decrypt(crypto, monkeypatch):
    """Rotation: ciphertext minted under previous secret still decrypts."""
    # Mint under "old current" (= A)
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "A" * 48)
    monkeypatch.delenv("INTERNAL_SHARED_SECRET_PREVIOUS", raising=False)
    sys.modules.pop("internal_crypto", None)
    sys.modules.pop("internal_auth", None)
    import internal_crypto as ic_old
    token = ic_old.encrypt_field("rotate-me")

    # Re-key: new current = B, previous = A
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "B" * 48)
    monkeypatch.setenv("INTERNAL_SHARED_SECRET_PREVIOUS", "A" * 48)
    sys.modules.pop("internal_crypto", None)
    sys.modules.pop("internal_auth", None)
    import internal_crypto as ic_new
    assert ic_new.decrypt_field(token) == b"rotate-me"
    # New encrypts work too
    round2 = ic_new.encrypt_field("fresh")
    assert ic_new.decrypt_field(round2) == b"fresh"

    # Cleanup: re-import under default test env so other tests see consistent state
    sys.modules.pop("internal_crypto", None)
    sys.modules.pop("internal_auth", None)


def test_rules_endpoint_returns_encrypted_salt(client, monkeypatch):
    """Integration: /internal/rules/{domain} returns subject_hash_salt_enc
    that decrypts to the same hex as the plaintext field."""
    from unittest.mock import AsyncMock, MagicMock
    import main as backend_main
    sys.modules.pop("internal_crypto", None)
    import internal_crypto

    fake_customer = {
        "id": "cust-123",
        "domain_verified": True,
        "is_verified": True,
        "ai_scan_enabled": False,
        "subject_hash_salt": b"\x11" * 32,
    }
    fake_conn = MagicMock()
    fake_conn.fetchrow = AsyncMock(return_value=fake_customer)
    fake_conn.fetch = AsyncMock(return_value=[])

    class FakePoolCtx:
        async def __aenter__(self_inner):
            return fake_conn

        async def __aexit__(self_inner, *a):
            return None

    fake_pool = MagicMock()
    fake_pool.acquire = MagicMock(return_value=FakePoolCtx())
    monkeypatch.setattr(backend_main, "get_pool", lambda: fake_pool)

    secret = os.environ["INTERNAL_SHARED_SECRET"]
    r = client.get(
        "/internal/rules/example.com",
        headers={"X-Internal-Secret": secret},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "subject_hash_salt_enc" in body
    assert "subject_hash_salt" in body  # transition: still present
    decrypted_hex = internal_crypto.decrypt_field(
        body["subject_hash_salt_enc"]
    ).decode("ascii")
    assert decrypted_hex == body["subject_hash_salt"]
    assert bytes.fromhex(decrypted_hex) == b"\x11" * 32
