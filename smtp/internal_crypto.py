"""Backward-compatible shim. See backend/internal_crypto.py for context.

F-17 moved into the shared `safesender_crypto` package (S-L4).
"""

from safesender_crypto import (  # noqa: F401
    PARAMS_VERSION,
    InvalidToken,
    build_multifernet,
    decrypt_field,
    encrypt_field,
)
