"""Add microsoft_sub column to customers

Revision ID: 20260529_0002
Revises: 20260529_0001
Create Date: 2026-05-29
"""
from alembic import op

revision = "20260529_0002"
down_revision = "20260529_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE customers
        ADD COLUMN IF NOT EXISTS microsoft_sub TEXT UNIQUE
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE customers DROP COLUMN IF EXISTS microsoft_sub")
