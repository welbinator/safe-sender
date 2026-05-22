"""admin_rate_limit table for cross-process admin rate limiting (F-19)

Revision ID: 20260522_0002
Revises: 20260522_0001
Create Date: 2026-05-22

The previous in-process `dict[ip] -> deque[timestamps]` limiter on
`routers/admin.py` was reset on every container restart and useless under
multi-replica scale-out. We replace it with a Postgres-backed sliding
window using an atomic UPSERT — one row per (ip, window_start_minute).
"""
from alembic import op

revision = "20260522_0002"
down_revision = "20260522_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_rate_limit (
            ip            TEXT        NOT NULL,
            window_start  TIMESTAMPTZ NOT NULL,
            request_count INTEGER     NOT NULL DEFAULT 0,
            PRIMARY KEY (ip, window_start)
        )
        """
    )
    # Index for the housekeeping DELETE that purges expired windows.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_rate_limit_window
        ON admin_rate_limit (window_start)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_admin_rate_limit_window")
    op.execute("DROP TABLE IF EXISTS admin_rate_limit")
