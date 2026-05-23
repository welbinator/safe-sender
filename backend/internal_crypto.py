"""Backward-compatible shim.

F-17 moved into the shared `safesender_crypto` package (S-L4: single source
of truth so backend and smtp can't drift). Keeping this module so existing
imports (`from internal_crypto import encrypt_field`) keep working and to
preserve the test entrypoint at backend/tests/test_f17_internal_crypto.py.
"""

from safesender_crypto import (  # noqa: F401
    PARAMS_VERSION,
    InvalidToken,
    build_multifernet,
    decrypt_field,
    encrypt_field,
)
