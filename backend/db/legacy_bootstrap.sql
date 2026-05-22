CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL UNIQUE,
    name TEXT,
    email TEXT NOT NULL,
    google_sub TEXT UNIQUE,          -- Google OAuth subject identifier
    plan TEXT NOT NULL DEFAULT 'basic',  -- 'basic' | 'pro'
    dashboard_config JSONB,           -- per-customer widget/layout overrides (NULL = use default)
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    match_type TEXT NOT NULL CHECK (match_type IN ('string', 'regex')),
    scope TEXT NOT NULL DEFAULT 'external' CHECK (scope IN ('external', 'internal', 'both')),
    applies_to_email TEXT,            -- NULL = org-wide; email address = specific user
    is_exception BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE = this user bypasses the rule
    active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_customer_id ON rules(customer_id);
CREATE INDEX IF NOT EXISTS idx_rules_active ON rules(customer_id, active);

CREATE TABLE IF NOT EXISTS scan_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject_hash TEXT,               -- SHA-256 of subject, never plaintext
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'blocked')),
    matched_rule_id UUID REFERENCES rules(id) ON DELETE SET NULL,
    smtp_message_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_customer_id ON scan_logs(customer_id);
CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(customer_id, created_at DESC);
