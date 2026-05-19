-- Sprint 6: suppressed_addresses table for SES bounce/complaint webhooks
-- Run: psql $DATABASE_URL -f migrations/004_suppressed_addresses.sql

CREATE TABLE IF NOT EXISTS suppressed_addresses (
    id          BIGSERIAL PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    reason      TEXT NOT NULL CHECK (reason IN ('bounce', 'complaint')),
    detail      TEXT,
    suppressed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suppressed_email ON suppressed_addresses(email);
