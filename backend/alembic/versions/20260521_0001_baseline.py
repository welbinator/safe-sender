"""baseline: snapshot of all pre-Alembic SQL

Revision ID: 20260521_0001
Revises:
Create Date: 2026-05-21

This baseline runs the original db/schema.sql and every legacy
migrations/*.sql file in sorted order. Every legacy DDL statement uses
IF NOT EXISTS / IF EXISTS, so this is safe to apply on:
  - fresh databases (creates everything),
  - existing databases (no-op; `alembic stamp head` is preferred but this
    is defense-in-depth in case stamping is forgotten).

After this revision, *all* schema changes go through Alembic. Do NOT add
new files to backend/migrations/ — create them via `alembic revision`.
"""
from pathlib import Path

from alembic import op
import sqlalchemy as sa  # noqa: F401  (kept for migration-template consistency)

revision = "20260521_0001"
down_revision = None
branch_labels = None
depends_on = None


_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_LEGACY_FILES = [
    # NOTE: legacy_bootstrap.sql is the hand-written IF-NOT-EXISTS DDL that
    # predates Alembic. db/schema.sql is a pg_dump artifact (CI drift check
    # only) and MUST NOT be replayed here — it would clash on alembic_version.
    _BACKEND_ROOT / "db" / "legacy_bootstrap.sql",
    *sorted((_BACKEND_ROOT / "migrations").glob("*.sql")),
]


def upgrade() -> None:
    conn = op.get_bind()
    pgcrypto_available = bool(
        conn.exec_driver_sql(
            "SELECT 1 FROM pg_available_extensions WHERE name = 'pgcrypto'"
        ).fetchone()
    )
    if pgcrypto_available:
        conn.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    for path in _LEGACY_FILES:
        sql = path.read_text(encoding="utf-8").strip()
        if not sql:
            continue
        # Strip transactional wrappers (Alembic owns the txn) and any
        # CREATE EXTENSION pgcrypto lines — handled above and skipped
        # when pgcrypto isn't installable (test envs use a shim).
        cleaned_lines = []
        for line in sql.splitlines():
            stripped = line.strip()
            upper = stripped.upper()
            if upper in {"BEGIN;", "COMMIT;", "BEGIN", "COMMIT"}:
                continue
            if upper.startswith("CREATE EXTENSION") and "PGCRYPTO" in upper:
                continue
            cleaned_lines.append(line)
        conn.exec_driver_sql("\n".join(cleaned_lines))


def downgrade() -> None:
    # The baseline is intentionally non-reversible — bringing the DB to
    # an empty state would destroy customer data. To wipe a dev DB, drop
    # and recreate it instead.
    raise NotImplementedError("Baseline migration is not reversible")
