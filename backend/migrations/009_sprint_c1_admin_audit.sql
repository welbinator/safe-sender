-- Sprint C1 hotfix (audit C-4): admin panel audit trail.
-- Every authenticated admin action writes one row here.

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip           TEXT NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    status_code  INTEGER NOT NULL,
    detail       JSONB
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_created_at
    ON admin_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_ip
    ON admin_audit_log (ip, created_at DESC);
