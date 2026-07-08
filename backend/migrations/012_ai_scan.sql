-- Sprint 2 AI add-on
ALTER TABLE customers ADD COLUMN IF NOT EXISTS ai_scan_enabled BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS ai_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    policy_text TEXT NOT NULL CHECK (char_length(policy_text) BETWEEN 10 AND 500),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_policies_customer_idx ON ai_policies(customer_id);
ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_decision TEXT;
ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_confidence FLOAT;
ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS ai_reason TEXT;
