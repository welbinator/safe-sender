"""Deprecated shim — import from `security` instead.

Sprint C1 t8 moved JWT + Google OIDC into `security/`. This module re-exports
the same names so old import sites (and the audit test that asserts
`import auth_utils` still works) continue to function.

Remove after one release cycle.
"""
from security import (  # noqa: F401
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_EXPIRE_DAYS,
    JWT_ISSUER,
    GOOGLE_CLIENT_ID,
    GOOGLE_VALID_ISSUERS,
    WORKSPACE_ONLY,
    create_jwt,
    decode_jwt,
    verify_google_id_token,
)
