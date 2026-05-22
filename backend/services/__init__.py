"""Application service layer.

Services own *business logic* and orchestrate one or more repositories.
Routers become thin: parse the request body, call a service method, shape the
response.

Conventions
-----------
* Services NEVER touch asyncpg or raw SQL directly — they go through
  repositories.
* Services raise domain-specific exceptions (defined in `services.errors`) that
  routers convert to HTTPException at the edge.
* Services accept already-constructed repos via __init__ — same lifetime as
  the request (one connection per request via FastAPI dependency).
* Services may pull in adjacent infrastructure (DNS resolver, SMTP client,
  bcrypt, secrets) — that's the whole point of having them.
"""
from .errors import (
    DomainAlreadyVerified,
    DomainVerificationNotInitialized,
    InvalidRegexPattern,
    NotFoundError,
    ServiceError,
)
from .customers import CustomerService
from .rules import RuleService

__all__ = [
    "CustomerService",
    "RuleService",
    "ServiceError",
    "NotFoundError",
    "InvalidRegexPattern",
    "DomainAlreadyVerified",
    "DomainVerificationNotInitialized",
]
