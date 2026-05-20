-- Sprint 7: per-customer SMTP credentials
ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS smtp_username TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS smtp_password_hash TEXT;
