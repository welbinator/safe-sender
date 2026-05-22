-- F-08: Drop the temporary plaintext `subject` column from scan_logs.
--
-- 007_subject_temp.sql added this for early-debugging visibility, marked
-- "remove before go-live". The privacy guarantee (smtp/main.py:14) says the
-- subject is stored only as a SHA-256 hash, so the plaintext column is a
-- standing breach of that promise. The HMAC `subject_hash` column remains
-- the only retained representation.
--
-- Rollback (manual, not encouraged — defeats the privacy guarantee):
--   ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS subject TEXT;

ALTER TABLE scan_logs DROP COLUMN IF EXISTS subject;
