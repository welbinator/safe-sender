-- Sprint B Batch 2: privacy & multi-tenant suppression isolation
--
-- C12: Per-customer HMAC salt for subject_hash so rainbow-table / dictionary
--      attacks against the log table can't trivially recover common subject
--      lines across customers. Salt is opaque random bytes; only the SMTP
--      service ever needs to read it.
--
-- C16: suppressed_addresses gains customer_id so one customer's hard bounce
--      can't pollute another customer's sending. Column is nullable so we
--      can deploy without backfilling — legacy NULL rows are treated as
--      global suppressions for backward compatibility until backfill.
--
-- Run:
--   psql $DATABASE_URL -f migrations/008_sprint_b_privacy.sql
--
-- Rollback (manual, irreversible for salts already generated):
--   ALTER TABLE customers DROP COLUMN subject_hash_salt;
--   ALTER TABLE suppressed_addresses DROP COLUMN customer_id;

BEGIN;

-- pgcrypto provides gen_random_bytes; safe to re-run.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- C12: per-customer HMAC key. NOT NULL with default => existing rows get
-- their own fresh salt at migration time. App code must always read this
-- column, never recompute from any deterministic source.
ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS subject_hash_salt BYTEA NOT NULL DEFAULT gen_random_bytes(32);

-- C16: multi-tenant suppression. Nullable for legacy rows (treated as global
-- by the lookup endpoint). New rows MUST have customer_id; the application
-- enforces this — the DB stays permissive to avoid a hard cutover.
ALTER TABLE suppressed_addresses
  ADD COLUMN IF NOT EXISTS customer_id UUID
    REFERENCES customers(id) ON DELETE CASCADE;

-- Drop the global UNIQUE on email — same address can now legitimately be
-- suppressed for different customers. Replace with a per-(customer, email)
-- partial unique. Legacy NULL rows fall under a separate partial unique to
-- preserve "global suppression" semantics for the backfill window.
ALTER TABLE suppressed_addresses
  DROP CONSTRAINT IF EXISTS suppressed_addresses_email_key;

CREATE UNIQUE INDEX IF NOT EXISTS suppressed_addresses_customer_email_uq
  ON suppressed_addresses (customer_id, email)
  WHERE customer_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS suppressed_addresses_legacy_email_uq
  ON suppressed_addresses (email)
  WHERE customer_id IS NULL;

-- Composite index for the hot path (suppression lookup at SMTP send time).
CREATE INDEX IF NOT EXISTS idx_suppressed_customer_email
  ON suppressed_addresses (customer_id, email);

COMMIT;
