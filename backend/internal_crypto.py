"""
F-17: Field-level encryption for sensitive values on backend↔smtp internal calls.

Threat: anyone with host access can tcpdump the Docker bridge and capture
`subject_hash_salt` (returned from /internal/rules/{domain}) in plaintext.
The salt is the HMAC key used to hash email subjects — leak it and the
privacy guarantee on stored `subject_hash` rows is gone.

Fix: encrypt the salt with Fernet using an HKDF-derived key from
INTERNAL_SHARED_SECRET. Both sides already share this secret; no new key
material, no mTLS plumbing, no per-connection handshake.

Rotation: when INTERNAL_SHARED_SECRET rotates, the derived Fernet key
rotates with it. During the rotation window, decryption tries the previous
secret's key as a fallback (mirrors the auth rotation in internal_auth.py).
"""
from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from internal_auth import INTERNAL_SHARED_SECRET, INTERNAL_SHARED_SECRET_PREVIOUS

_HKDF_INFO = b"safe-sender:internal-field-encryption:v1"
_HKDF_SALT = b"safe-sender-static-salt-f17"  # static — keying is via the secret


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte Fernet key from a shared secret via HKDF-SHA256."""
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


# Build a MultiFernet so decrypt accepts current OR previous, encrypt always
# uses current. Mirrors internal_auth rotation semantics.
_current = Fernet(_derive_fernet_key(INTERNAL_SHARED_SECRET))
_fernets = [_current]
if INTERNAL_SHARED_SECRET_PREVIOUS:
    _fernets.append(Fernet(_derive_fernet_key(INTERNAL_SHARED_SECRET_PREVIOUS)))
_multi = MultiFernet(_fernets)


def encrypt_field(plaintext: bytes | str) -> str:
    """Encrypt a small sensitive field. Returns urlsafe-b64 ASCII string."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return _multi.encrypt(plaintext).decode("ascii")


def decrypt_field(token: str) -> bytes:
    """Decrypt a token produced by encrypt_field. Raises InvalidToken on failure."""
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return _multi.decrypt(token.encode("ascii"))


__all__ = ["encrypt_field", "decrypt_field", "InvalidToken"]
