"""customer_domains table for multi-domain support

Revision ID: 20260528_0001
Revises: 20260522_0002
Create Date: 2026-05-28

Adds customer_domains table so each customer can verify multiple sending
domains. Migrates existing single-domain data from the customers table.
The old domain/domain_verified/domain_verification_token columns on
customers are left in place for backward compat -- to be dropped later.
"""
from alembic import op

revision = "20260528_0001"
down_revision = "20260522_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS customer_domains (
            id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            customer_id        UUID        NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            domain             TEXT        NOT NULL,
            verified           BOOLEAN     NOT NULL DEFAULT FALSE,
            verification_token TEXT,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT customer_domains_domain_uq UNIQUE (domain)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_domains_customer_id ON customer_domains (customer_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_domains_domain ON customer_domains (domain)"
    )

    op.execute(
        """
        INSERT INTO customer_domains (customer_id, domain, verified, verification_token, created_at)
        SELECT
            id,
            domain,
            COALESCE(domain_verified, FALSE),
            domain_verification_token,
            NOW()
        FROM customers
        WHERE domain IS NOT NULL AND domain != ''
        ON CONFLICT (domain) DO NOTHING
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_customer_domains_domain")
    op.execute("DROP INDEX IF EXISTS idx_customer_domains_customer_id")
    op.execute("DROP TABLE IF EXISTS customer_domains")
