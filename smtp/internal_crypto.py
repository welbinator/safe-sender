"""
F-17 (smtp side): mirror of backend/internal_crypto.py.

Two-container project, so we duplicate ~50 lines rather than ship a shared
package. Keep this file byte-for-byte in lock-step with backend's version
for the encryption parameters (info, salt, HKDF length).
"""
from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HKDF_INFO = b"safe-sender:internal-field-encryption:v1"
_HKDF_SALT = b"safe-sender-static-salt-f17"


def _derive_fernet_key(secret: str) -> bytes:
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


_SECRET = os.environ.get("INTERNAL_SHARED_SECRET", "")
_SECRET_PREVIOUS = os.environ.get("INTERNAL_SHARED_SECRET_PREVIOUS", "")

if not _SECRET or len(_SECRET) < 32:
    raise RuntimeError(
        "INTERNAL_SHARED_SECRET must be set (>=32 chars) for internal_crypto"
    )

_fernets = [Fernet(_derive_fernet_key(_SECRET))]
if _SECRET_PREVIOUS and len(_SECRET_PREVIOUS) >= 32:
    _fernets.append(Fernet(_derive_fernet_key(_SECRET_PREVIOUS)))
_multi = MultiFernet(_fernets)


def encrypt_field(plaintext: bytes | str) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return _multi.encrypt(plaintext).decode("ascii")


def decrypt_field(token: str) -> bytes:
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return _multi.decrypt(token.encode("ascii"))


__all__ = ["encrypt_field", "decrypt_field", "InvalidToken"]
