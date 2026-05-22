"""drop plaintext subject column from scan_logs (F-08)

Revision ID: 20260522_0001
Revises: 20260521_0001
Create Date: 2026-05-22

migrations/007_subject_temp.sql added a plaintext `subject` column for
early-debugging visibility, marked TEMPORARY. Our privacy promise is that
message subjects are stored only as HMAC `subject_hash`, so the plaintext
column is a standing breach of that promise. The HMAC column remains.

This is non-destructive on tables that were never populated (column simply
goes away). For DBs where production traffic landed plaintext into the
column, that data is irrecoverably dropped — which is the intent.
"""
from alembic import op

revision = "20260522_0001"
down_revision = "20260521_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_logs DROP COLUMN IF EXISTS subject")


def downgrade() -> None:
    # Re-add as nullable. Original data is gone — this only restores the
    # column shape for rollback compatibility, not the values.
    op.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS subject TEXT")
