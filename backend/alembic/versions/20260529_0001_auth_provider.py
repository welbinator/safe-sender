"""Add auth_provider column to customers

Revision ID: 20260529_0001
Revises: 20260528_0001
Create Date: 2026-05-29
"""
from alembic import op

revision = "20260529_0001"
down_revision = "20260528_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE customers
        ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'google'
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE customers DROP COLUMN IF EXISTS auth_provider")
