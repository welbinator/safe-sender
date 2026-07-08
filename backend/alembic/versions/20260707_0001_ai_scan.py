"""Add AI scan tables and columns for AI add-on (Sprint 2)."""
from alembic import op

revision = "20260707_0001"
down_revision = "20260529_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS ai_policies (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            policy_text TEXT NOT NULL CHECK (char_length(policy_text) BETWEEN 10 AND 500),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ai_policies_customer_id ON ai_policies(customer_id)")
    op.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS ai_scan_enabled BOOLEAN NOT NULL DEFAULT FALSE")
    op.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_decision TEXT")
    op.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_confidence INT")
    op.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_reason TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_logs DROP COLUMN IF EXISTS ai_reason")
    op.execute("ALTER TABLE scan_logs DROP COLUMN IF EXISTS ai_confidence")
    op.execute("ALTER TABLE scan_logs DROP COLUMN IF EXISTS ai_decision")
    op.execute("ALTER TABLE customers DROP COLUMN IF EXISTS ai_scan_enabled")
    op.execute("DROP TABLE IF EXISTS ai_policies")
