-- Sprint 5: domain ownership verification
ALTER TABLE customers
    ADD COLUMN IF NOT EXISTS domain_verification_token TEXT,
    ADD COLUMN IF NOT EXISTS domain_verified BOOLEAN NOT NULL DEFAULT FALSE;
