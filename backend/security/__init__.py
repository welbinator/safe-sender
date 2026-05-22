"""Security primitives: JWT, Google OIDC, CSRF.

Sprint C1 t8: extracted from monolithic auth_utils.py. Keeping a single import
surface so call sites stay terse:

    from security import create_jwt, decode_jwt, verify_google_id_token
"""
from .jwt_tokens import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_EXPIRE_DAYS,
    JWT_ISSUER,
    create_jwt,
    decode_jwt,
)
from .google_oidc import (
    GOOGLE_CLIENT_ID,
    GOOGLE_VALID_ISSUERS,
    WORKSPACE_ONLY,
    verify_google_id_token,
)

__all__ = [
    "JWT_ALGORITHM",
    "JWT_AUDIENCE",
    "JWT_EXPIRE_DAYS",
    "JWT_ISSUER",
    "create_jwt",
    "decode_jwt",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_VALID_ISSUERS",
    "WORKSPACE_ONLY",
    "verify_google_id_token",
]
