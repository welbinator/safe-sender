"""Data access layer.

Repositories encapsulate raw SQL behind intent-revealing methods. Routers
and services should never write SQL directly — call a repository.

Conventions
-----------
* Every repo is constructed with an asyncpg connection or pool. Read-only
  callers pass a pool; multi-step writers pass a connection inside an
  explicit transaction.
* Methods return plain dicts (asyncpg `Record` -> `dict(row)`). No ORM.
* Methods are named after the *intent* (`get_active_by_id`,
  `mark_inactive`) rather than the SQL verb.
* No business logic lives here. Validation, authorization, side effects
  belong in the service layer.
"""
from .customers import CustomerRepository
from .rules import RuleRepository
from .scan_logs import ScanLogRepository
from .suppressions import SuppressionRepository
from .admin_audit import AdminAuditRepository

__all__ = [
    "CustomerRepository",
    "RuleRepository",
    "ScanLogRepository",
    "SuppressionRepository",
    "AdminAuditRepository",
]
