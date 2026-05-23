"""
safesender_crypto — shared field-level encryption for backend↔smtp internal calls.

Single source of truth for F-17. Both backend and smtp containers import this
package so the HKDF parameters, salt, and Fernet-key derivation can never
silently drift apart (S-L4).

Threat model
------------
Anyone with host access can tcpdump the Docker bridge and capture
`subject_hash_salt` (returned from /internal/rules/{domain}) in plaintext.
The salt is the HMAC key used to hash email subjects — leak it and the
privacy guarantee on stored `subject_hash` rows is gone.

Design
------
- Encrypt with Fernet (AES-128-CBC + HMAC-SHA256) using an HKDF-SHA256
  derived key from INTERNAL_SHARED_SECRET. Both sides already share this
  secret; no new key material, no mTLS plumbing.
- Rotation: when INTERNAL_SHARED_SECRET rotates, MultiFernet accepts the
  previous secret for decryption during the rotation window. Mirrors the
  auth-token rotation in internal_auth.

S-L5 note: this is intentionally Fernet, not raw AES-256-GCM. Fernet uses a
fresh 16-byte CSPRNG IV per encrypt (no nonce-reuse concern) and bundles an
authenticated HMAC-SHA256 tag. The 128-bit data key is derived from a
≥256-bit shared secret via HKDF; the 128 vs 256 distinction is irrelevant
for the salts and short fields encrypted here (collision/preimage are not
the threat model — confidentiality + integrity on the wire are). If we
ever need to encrypt long-lived at-rest tuples, revisit with AES-256-GCM-SIV.

Parameter versioning
--------------------
HKDF info / salt are versioned by string literal. Bumping any of them is a
breaking wire change — both sides must roll together. Treat changes here
the same way you'd treat a schema migration: PR, review, deploy both
containers in the same window.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Versioned KDF parameters — DO NOT change without a coordinated deploy of
# backend AND smtp containers in the same release window.
# ---------------------------------------------------------------------------
PARAMS_VERSION = "v1"
_HKDF_INFO = b"safe-sender-internal-field-encryption-v1"
_HKDF_SALT = b"safe-sender-static-salt-f17"
_KEY_LENGTH = 32  # bytes — Fernet wants exactly 32 raw bytes, urlsafe-b64 encoded


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte Fernet key from a shared secret via HKDF-SHA256."""
    import base64

    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def build_multifernet(
    current_secret: str,
    previous_secret: str | None = None,
) -> MultiFernet:
    """Build a MultiFernet keychain.

    Encrypt always uses `current_secret`; decrypt tries current then previous.
    Raises ValueError if `current_secret` is too short to be safe.
    """
    if not current_secret or len(current_secret) < 32:
        raise ValueError(
            "current_secret must be at least 32 chars; refusing to derive a weak key"
        )
    keys = [Fernet(_derive_fernet_key(current_secret))]
    if previous_secret and len(previous_secret) >= 32:
        keys.append(Fernet(_derive_fernet_key(previous_secret)))
    return MultiFernet(keys)


# ---------------------------------------------------------------------------
# Module-level singleton bound to the process environment, so call sites can
# just `from safesender_crypto import encrypt_field, decrypt_field`.
# ---------------------------------------------------------------------------
_SECRET = os.environ.get("INTERNAL_SHARED_SECRET", "")
_SECRET_PREVIOUS = os.environ.get("INTERNAL_SHARED_SECRET_PREVIOUS", "") or None

if not _SECRET or len(_SECRET) < 32:
    raise RuntimeError(
        "INTERNAL_SHARED_SECRET must be set (>=32 chars) for safesender_crypto"
    )

_multi = build_multifernet(_SECRET, _SECRET_PREVIOUS)


def encrypt_field(plaintext: str) -> str:
    """Encrypt a small sensitive field. Returns urlsafe-b64 ASCII string."""
    if plaintext is None:
        raise ValueError("plaintext must not be None")
    return _multi.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_field(token: str) -> bytes:
    """Decrypt a token produced by encrypt_field. Raises InvalidToken on failure.

    Returns bytes (not str) so callers retain control over decoding — some
    payloads are hex-encoded ASCII, others may be UTF-8 text. Use
    ``.decode("ascii")`` or ``.decode("utf-8")`` at the call site.
    """
    if token is None:
        raise ValueError("token must not be None")
    return _multi.decrypt(token.encode("ascii"))


__all__ = [
    "PARAMS_VERSION",
    "build_multifernet",
    "encrypt_field",
    "decrypt_field",
    "InvalidToken",
]
