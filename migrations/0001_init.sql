-- Ethos PostgreSQL Schema Initialization

CREATE TABLE IF NOT EXISTS sandboxes (
    id VARCHAR(64) PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    policy_profile VARCHAR(64) NOT NULL DEFAULT 'default_strict',
    root_path TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id VARCHAR(64) PRIMARY KEY,
    sandbox_id VARCHAR(64) NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
    description TEXT NOT NULL DEFAULT '',
    file_hashes JSONB NOT NULL DEFAULT '{}'::jsonb,
    taint_ledger_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    sandbox_id VARCHAR(64) NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    caller VARCHAR(64) NOT NULL DEFAULT 'agent',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_sandbox ON audit_events(sandbox_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
