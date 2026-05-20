-- TEMPORARY: store plaintext subject for testing purposes.
-- Remove before go-live and revert to subject_hash only.
ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS subject TEXT;
