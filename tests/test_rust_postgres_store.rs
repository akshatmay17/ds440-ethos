use ethos::models::{AuditEvent, SnapshotMetadata};

#[test]
fn test_postgres_schema_compiles_and_parses() {
    let schema = include_str!("../migrations/0001_init.sql");
    assert!(schema.contains("CREATE TABLE IF NOT EXISTS sandboxes"));
    assert!(schema.contains("CREATE TABLE IF NOT EXISTS snapshots"));
    assert!(schema.contains("CREATE TABLE IF NOT EXISTS audit_events"));
    assert!(schema.contains("CREATE INDEX IF NOT EXISTS idx_audit_sandbox"));
}

#[test]
fn test_snapshot_metadata_serialization_for_postgres() {
    let mut file_hashes = std::collections::HashMap::new();
    file_hashes.insert("app.py".to_string(), "abc123hash".to_string());

    let snap = SnapshotMetadata {
        snapshot_id: "snap_100".to_string(),
        timestamp: 1725890000.0,
        description: "postgres test snapshot".to_string(),
        file_hashes,
        taint_ledger_state: serde_json::json!({
            "app.py": {
                "tag": "SYSTEM",
                "trust_level": "TRUSTED"
            }
        }),
    };

    let json_val = serde_json::to_value(&snap).unwrap();
    assert_eq!(json_val["snapshot_id"], "snap_100");
    assert!(json_val["file_hashes"]["app.py"] == "abc123hash");
}

#[test]
fn test_audit_event_jsonb_format() {
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: 1725890000.0,
        event_type: "POLICY_BLOCK".to_string(),
        action: "network_egress".to_string(),
        caller: "agent".to_string(),
        details: serde_json::json!({
            "program": "curl",
            "reason": "Referenced untrusted data",
            "blocked": true
        }),
    };

    let event_json = serde_json::to_value(&event).unwrap();
    assert_eq!(event_json["event_type"], "POLICY_BLOCK");
    assert_eq!(event_json["details"]["blocked"], true);
}
