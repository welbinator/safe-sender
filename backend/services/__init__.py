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
    ConflictError,
    DomainAlreadyVerified,
    DomainVerificationNotInitialized,
    InvalidRegexPattern,
    NotFoundError,
    ServiceError,
)
from .admin import AdminService
from .auth import AuthService, LoginResult
from .customers import CustomerService
from .logs import LogPage, LogService
from .rules import RuleService
from .webhooks import ProcessResult, SesWebhookService

__all__ = [
    "AdminService",
    "AuthService",
    "CustomerService",
    "LogService",
    "RuleService",
    "SesWebhookService",
    # data carriers
    "LoginResult",
    "LogPage",
    "ProcessResult",
    # exceptions
    "ServiceError",
    "NotFoundError",
    "ConflictError",
    "InvalidRegexPattern",
    "DomainAlreadyVerified",
    "DomainVerificationNotInitialized",
]
