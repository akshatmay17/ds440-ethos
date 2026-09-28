use ethos::models::{ProvenanceRecord, ProvenanceTag, TrustLevel};
use ethos::taint::TaintEngine;

#[test]
fn test_record_and_retrieve_provenance() {
    let mut engine = TaintEngine::new();
    let record = ProvenanceRecord {
        source_id: "config.json".to_string(),
        tag: ProvenanceTag::System,
        trust_level: TrustLevel::Trusted,
        chain_of_custody: vec![],
        timestamp: 0.0,
        metadata: serde_json::json!({}),
    };
    engine.record_provenance("config.json", record.clone());

    let retrieved = engine.get_provenance("config.json");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().trust_level, TrustLevel::Trusted);
    assert!(!engine.is_tainted("config.json"));
}

#[test]
fn test_taint_propagation_inherits_worst_severity() {
    let mut engine = TaintEngine::new();
    let clean = ProvenanceRecord {
        source_id: "clean.txt".to_string(),
        tag: ProvenanceTag::User,
        trust_level: TrustLevel::Internal,
        chain_of_custody: vec![],
        timestamp: 0.0,
        metadata: serde_json::json!({}),
    };
    let tainted = ProvenanceRecord {
        source_id: "malicious.txt".to_string(),
        tag: ProvenanceTag::UntrustedWeb,
        trust_level: TrustLevel::Untrusted,
        chain_of_custody: vec!["https://evil.site".to_string()],
        timestamp: 0.0,
        metadata: serde_json::json!({}),
    };
    engine.record_provenance("clean.txt", clean);
    engine.record_provenance("malicious.txt", tainted);

    let derived = engine.propagate(
        &["clean.txt".to_string(), "malicious.txt".to_string()],
        "derived.txt",
        None,
    );

    assert_eq!(derived.trust_level, TrustLevel::Untrusted);
    assert!(derived.chain_of_custody.contains(&"malicious.txt".to_string()));
    assert!(engine.is_tainted("derived.txt"));
}

#[test]
fn test_policy_blocks_privileged_action_on_tainted_resource() {
    let mut engine = TaintEngine::new();
    let tainted = ProvenanceRecord {
        source_id: "payload.sh".to_string(),
        tag: ProvenanceTag::UntrustedWeb,
        trust_level: TrustLevel::Untrusted,
        chain_of_custody: vec![],
        timestamp: 0.0,
        metadata: serde_json::json!({}),
    };
    engine.record_provenance("payload.sh", tainted);

    // Privileged action (network_egress) on tainted resource -> blocked
    let decision = engine.evaluate_policy("network_egress", &["payload.sh".to_string()]);
    assert!(!decision.allowed);
    assert_eq!(decision.rule_id, Some("RULE-001".to_string()));

    // Safe unprivileged action -> allowed
    let benign = engine.evaluate_policy("read_safe", &["payload.sh".to_string()]);
    assert!(benign.allowed);
}

#[test]
fn test_snapshot_export_and_restore() {
    let mut engine = TaintEngine::new();
    let record = ProvenanceRecord {
        source_id: "data.bin".to_string(),
        tag: ProvenanceTag::ExternalFile,
        trust_level: TrustLevel::Untrusted,
        chain_of_custody: vec![],
        timestamp: 0.0,
        metadata: serde_json::json!({}),
    };
    engine.record_provenance("data.bin", record);

    let state = engine.export_state();

    let mut new_engine = TaintEngine::new();
    assert!(!new_engine.is_tainted("data.bin"));

    new_engine.restore_state(state);
    assert!(new_engine.is_tainted("data.bin"));
}
