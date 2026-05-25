"""Application service layer.

Services own *business logic* and orchestrate one or more repositories.
Routers become thin: parse the request body, call a service method, shape
the response.

Conventions
-----------
* Services NEVER touch asyncpg or raw SQL directly — they go through
  repositories.
* Services raise domain-specific exceptions (defined in `services.errors`)
  that routers convert to HTTPException at the edge.
* Services accept already-constructed repos via __init__ — same lifetime
  as the request (one connection per request via FastAPI dependency).
* Services may pull in adjacent infrastructure (DNS resolver, SMTP client,
  bcrypt, secrets) — that's the whole point of having them.

Import policy (F-31)
--------------------
This package intentionally re-exports ONLY the cross-cutting error
hierarchy. Service classes and per-service data carriers
(`AuthService`, `LoginResult`, `ProcessResult`, etc.) MUST be imported
from their concrete module:

    from services.auth import AuthService, LoginResult         # ✓
    from services.webhooks import MailgunWebhookService         # ✓
    from services import AuthService                           # ✗ (gone)

This kills the "import everything from one place" pattern that hides
inter-service coupling and turns the package surface into a junk drawer.
"""
from .errors import (
    ConflictError,
    DomainAlreadyVerified,
    DomainVerificationNotInitialized,
    InvalidRegexPattern,
    NotFoundError,
    ServiceError,
    TooManyRules,
)

__all__ = [
    # exceptions (cross-cutting — routers catch these without caring
    # which service raised them)
    "ServiceError",
    "NotFoundError",
    "ConflictError",
    "InvalidRegexPattern",
    "DomainAlreadyVerified",
    "DomainVerificationNotInitialized",
    "TooManyRules",
]
