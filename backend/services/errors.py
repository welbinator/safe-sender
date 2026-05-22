"""Domain exceptions raised by the service layer.

Routers catch these at their edge and translate to HTTPException. Keeping the
HTTP vocabulary out of services means we can reuse them from background tasks,
CLI scripts, or webhook handlers without forcing FastAPI semantics on the
caller.
"""
from __future__ import annotations


class ServiceError(Exception):
    """Base class for all expected service-layer failures.

    Carries an HTTP status code as a hint — the router uses it as the default
    when translating to HTTPException, but is free to override.
    """

    status_code: int = 400
    default_message: str = "Service error"

    def __init__(self, message: str | None = None):
        super().__init__(message or self.default_message)


class NotFoundError(ServiceError):
    status_code = 404
    default_message = "Resource not found"


class ConflictError(ServiceError):
    status_code = 409
    default_message = "Conflict"


class InvalidRegexPattern(ServiceError):
    status_code = 422
    default_message = "Invalid regex pattern"


class DomainAlreadyVerified(ServiceError):
    """Not really an error — surfaces as a 200 in the existing API contract.

    Kept as an exception so the router branching logic is uniform: catch and
    return the appropriate success-shape response.
    """

    status_code = 200
    default_message = "Domain already verified"


class DomainVerificationNotInitialized(ServiceError):
    status_code = 400
    default_message = "Run verify-domain/init first"
