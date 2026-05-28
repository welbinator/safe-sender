BEGIN;

-- Ensure pgcrypto is available for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Create customer_domains table
CREATE TABLE IF NOT EXISTS customer_domains (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id           UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    domain                TEXT NOT NULL,
    verified              BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token    TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT customer_domains_domain_uq UNIQUE (domain)
);

CREATE INDEX IF NOT EXISTS idx_customer_domains_customer_id ON customer_domains (customer_id);
CREATE INDEX IF NOT EXISTS idx_customer_domains_domain ON customer_domains (domain);

-- 2. Migrate existing customer data into customer_domains
-- For each customer that has a domain, insert a row into customer_domains
-- carrying over their verified status and verification token.
INSERT INTO customer_domains (customer_id, domain, verified, verification_token, created_at)
SELECT
    id,
    domain,
    COALESCE(domain_verified, FALSE),
    domain_verification_token,
    NOW()
FROM customers
WHERE domain IS NOT NULL AND domain != ''
ON CONFLICT (domain) DO NOTHING;

-- NOTE: The old domain / domain_verified / domain_verification_token columns on
-- the customers table are intentionally left in place for backward compatibility.
-- They will be dropped in a future migration once all application code has been
-- updated to use the customer_domains table exclusively.

COMMIT;
