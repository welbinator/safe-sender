-- Sprint B: auth_provider + microsoft_sub columns
ALTER TABLE customers ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'google';
ALTER TABLE customers ADD COLUMN IF NOT EXISTS microsoft_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS customers_microsoft_sub_uniq ON customers(microsoft_sub) WHERE microsoft_sub IS NOT NULL;
