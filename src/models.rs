//! Core data schemas and domain types for Ethos.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust severity levels. Ordered such that Hostile > Untrusted > Internal > Trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TrustLevel {
    Trusted = 0,
    Internal = 1,
    Untrusted = 2,
    Hostile = 3,
}

impl TrustLevel {
    pub fn is_tainted(&self) -> bool {
        *self >= TrustLevel::Untrusted
    }
}

/// Provenance classifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvenanceTag {
    System,
    User,
    Internal,
    UntrustedWeb,
    ExternalFile,
    Derived,
}

/// Tracks origin, classification, and custody chain for any file or memory resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub source_id: String,
    pub tag: ProvenanceTag,
    pub trust_level: TrustLevel,
    #[serde(default)]
    pub chain_of_custody: Vec<String>,
    #[serde(default)]
    pub timestamp: f64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub call_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default = "default_caller")]
    pub caller: String,
}

fn default_caller() -> String {
    "agent".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub rule_id: Option<String>,
    pub action: String,
    pub reason: String,
    #[serde(default)]
    pub taint_records: Vec<ProvenanceRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub status: String, // "SUCCESS", "BLOCKED_BY_POLICY", "ERROR"
    pub output: serde_json::Value,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub provenance: Option<ProvenanceRecord>,
    #[serde(default)]
    pub policy_decision: Option<PolicyDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub snapshot_id: String,
    pub timestamp: f64,
    pub description: String,
    #[serde(default)]
    pub file_hashes: HashMap<String, String>,
    #[serde(default)]
    pub taint_ledger_state: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub step_id: usize,
    #[serde(default)]
    pub modified_files: Vec<String>,
    #[serde(default)]
    pub created_files: Vec<String>,
    #[serde(default)]
    pub deleted_files: Vec<String>,
    pub active_taint_count: usize,
    #[serde(default)]
    pub tainted_resources: Vec<String>,
    #[serde(default)]
    pub provenance_context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: f64,
    pub event_type: String,
    pub action: String,
    pub caller: String,
    pub details: serde_json::Value,
}
