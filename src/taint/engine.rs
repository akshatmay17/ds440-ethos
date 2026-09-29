use crate::models::{PolicyDecision, ProvenanceRecord, ProvenanceTag, TrustLevel};
use crate::taint::policy::{PolicyProfile, TaintPolicyConfig};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TaintEngine {
    ledger: HashMap<String, ProvenanceRecord>,
    pub config: TaintPolicyConfig,
}

impl Default for TaintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintEngine {
    pub fn new() -> Self {
        Self {
            ledger: HashMap::new(),
            config: TaintPolicyConfig::default(),
        }
    }

    pub fn new_with_config(config: TaintPolicyConfig) -> Self {
        Self {
            ledger: HashMap::new(),
            config,
        }
    }

    pub fn record_provenance(&mut self, resource_id: &str, record: ProvenanceRecord) {
        self.ledger.insert(resource_id.to_string(), record);
    }

    pub fn get_provenance(&self, resource_id: &str) -> Option<&ProvenanceRecord> {
        self.ledger.get(resource_id)
    }

    pub fn is_tainted(&self, resource_id: &str) -> bool {
        self.get_provenance(resource_id)
            .map(|r| r.trust_level.is_tainted())
            .unwrap_or(false)
    }

    pub fn propagate(
        &mut self,
        source_ids: &[String],
        target_id: &str,
        tag: Option<ProvenanceTag>,
    ) -> ProvenanceRecord {
        let mut highest_level = TrustLevel::Internal;
        let mut combined_custody = Vec::new();
        let mut found_sources = false;

        for sid in source_ids {
            if let Some(rec) = self.ledger.get(sid) {
                found_sources = true;
                if rec.trust_level > highest_level {
                    highest_level = rec.trust_level;
                }
                for c in &rec.chain_of_custody {
                    if !combined_custody.contains(c) {
                        combined_custody.push(c.clone());
                    }
                }
                if !combined_custody.contains(&rec.source_id) {
                    combined_custody.push(rec.source_id.clone());
                }
            } else if !combined_custody.contains(sid) {
                combined_custody.push(sid.clone());
            }
        }

        let effective_tag = tag.unwrap_or({
            if found_sources {
                ProvenanceTag::Derived
            } else {
                ProvenanceTag::Internal
            }
        });

        let new_record = ProvenanceRecord {
            source_id: target_id.to_string(),
            tag: effective_tag,
            trust_level: highest_level,
            chain_of_custody: combined_custody,
            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            metadata: serde_json::json!({ "derived_from": source_ids }),
        };

        self.ledger
            .insert(target_id.to_string(), new_record.clone());
        new_record
    }

    pub fn evaluate_policy(&self, action: &str, resource_ids: &[String]) -> PolicyDecision {
        let mut tainted_records = Vec::new();
        for rid in resource_ids {
            if let Some(rec) = self.get_provenance(rid) {
                if rec.trust_level.is_tainted() {
                    tainted_records.push(rec.clone());
                }
            }
        }

        let is_privileged = self.config.privileged_actions.contains(action);

        // Strict mode: file writes derived from untrusted input are blocked
        if self.config.profile == PolicyProfile::Strict
            && action == "write"
            && !tainted_records.is_empty()
        {
            return PolicyDecision {
                allowed: false,
                rule_id: Some("TAINT-STRICT-WRITE".to_string()),
                action: action.to_string(),
                reason:
                    "Strict zero-trust mode: file writes derived from untrusted inputs are blocked"
                        .to_string(),
                taint_records: tainted_records,
            };
        }

        // AuditOnly mode: record violation in telemetry without blocking (for Paper 2 observation)
        if self.config.profile == PolicyProfile::AuditOnly
            && is_privileged
            && !tainted_records.is_empty()
        {
            return PolicyDecision {
                allowed: true,
                rule_id: Some("AUDIT-LOGGED".to_string()),
                action: action.to_string(),
                reason: "Audit-only research mode: policy violation recorded in telemetry without blocking".to_string(),
                taint_records: tainted_records,
            };
        }

        if is_privileged && !tainted_records.is_empty() {
            let tainted_names: Vec<String> = tainted_records
                .iter()
                .map(|r| r.source_id.clone())
                .collect();
            PolicyDecision {
                allowed: false,
                rule_id: Some("RULE-001".to_string()),
                action: action.to_string(),
                reason: format!(
                    "Action '{}' is privileged and blocked because referenced inputs contain untrusted data: {:?}",
                    action, tainted_names
                ),
                taint_records: tainted_records,
            }
        } else {
            PolicyDecision {
                allowed: true,
                rule_id: None,
                action: action.to_string(),
                reason: "Allowed by boundary policy".to_string(),
                taint_records: tainted_records,
            }
        }
    }

    pub fn evaluate_path_policy(
        &self,
        action: &str,
        path: &str,
        resource_ids: &[String],
    ) -> PolicyDecision {
        if self.config.is_path_sensitive(path) {
            return PolicyDecision {
                allowed: false,
                rule_id: Some("TAINT-PATH-SECRET".to_string()),
                action: action.to_string(),
                reason: format!(
                    "Sensitive path protection: access or mutation of secret path '{}' is blocked",
                    path
                ),
                taint_records: vec![],
            };
        }
        self.evaluate_policy(action, resource_ids)
    }

    pub fn evaluate_network_egress(&self, url: &str, resource_ids: &[String]) -> PolicyDecision {
        let mut tainted_records = Vec::new();
        for rid in resource_ids {
            if let Some(rec) = self.get_provenance(rid) {
                if rec.trust_level.is_tainted() {
                    tainted_records.push(rec.clone());
                }
            }
        }

        if !tainted_records.is_empty() {
            if self.config.is_network_allowed(url) {
                return PolicyDecision {
                    allowed: true,
                    rule_id: Some("TAINT-NETWORK-ALLOWLIST-APPROVED".to_string()),
                    action: "network_egress".to_string(),
                    reason: format!(
                        "Approved network destination '{}' permitted by allowlist",
                        url
                    ),
                    taint_records: tainted_records,
                };
            } else {
                return PolicyDecision {
                    allowed: false,
                    rule_id: Some("TAINT-NETWORK-ALLOWLIST".to_string()),
                    action: "network_egress".to_string(),
                    reason: format!("Egress destination '{}' is not in approved allowlist while carrying tainted data", url),
                    taint_records: tainted_records,
                };
            }
        }

        PolicyDecision {
            allowed: true,
            rule_id: None,
            action: "network_egress".to_string(),
            reason: "Untainted network egress permitted".to_string(),
            taint_records: vec![],
        }
    }

    pub fn declassify(&mut self, resource_id: &str, token: &str) -> bool {
        if self.config.valid_tokens.contains(token) {
            if let Some(rec) = self.ledger.get_mut(resource_id) {
                rec.trust_level = TrustLevel::Trusted;
                rec.tag = ProvenanceTag::User;
                rec.chain_of_custody
                    .push(format!("DECLASSIFIED_BY_{}", token));
                return true;
            }
        }
        false
    }

    pub fn list_tainted_resources(&self) -> Vec<String> {
        let mut list: Vec<String> = self
            .ledger
            .iter()
            .filter(|(_, rec)| rec.trust_level.is_tainted())
            .map(|(k, _)| k.clone())
            .collect();
        list.sort();
        list
    }

    pub fn export_state(&self) -> serde_json::Value {
        serde_json::to_value(&self.ledger).unwrap_or(serde_json::json!({}))
    }

    pub fn restore_state(&mut self, state: serde_json::Value) {
        if let Ok(ledger) = serde_json::from_value::<HashMap<String, ProvenanceRecord>>(state) {
            self.ledger = ledger;
        }
    }
}
