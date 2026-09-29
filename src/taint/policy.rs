use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyProfile {
    Standard,
    Strict,
    AuditOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPolicyConfig {
    pub profile: PolicyProfile,
    pub privileged_actions: HashSet<String>,
    pub sensitive_paths: Vec<String>,
    pub network_allowlist: Vec<String>,
    pub valid_tokens: HashSet<String>,
}

impl Default for TaintPolicyConfig {
    fn default() -> Self {
        let mut privileged_actions = HashSet::new();
        for action in &[
            "network_egress",
            "exec_privileged",
            "file_delete",
            "send_email",
            "exfiltrate",
            "curl",
            "wget",
            "rm",
        ] {
            privileged_actions.insert(action.to_string());
        }

        let mut valid_tokens = HashSet::new();
        valid_tokens.insert("SEC-OVERRIDE-TOKEN-VALIDATED".to_string());

        Self {
            profile: PolicyProfile::Standard,
            privileged_actions,
            sensitive_paths: vec![
                ".env".to_string(),
                "id_rsa".to_string(),
                "id_ed25519".to_string(),
                ".ssh/".to_string(),
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "secrets.json".to_string(),
            ],
            network_allowlist: Vec::new(),
            valid_tokens,
        }
    }
}

impl TaintPolicyConfig {
    pub fn is_path_sensitive(&self, path: &str) -> bool {
        let normalized = path.replace('\\', "/");
        for sensitive in &self.sensitive_paths {
            if normalized == *sensitive
                || normalized.ends_with(sensitive)
                || normalized.contains(sensitive)
            {
                return true;
            }
        }
        false
    }

    pub fn is_network_allowed(&self, url: &str) -> bool {
        if self.network_allowlist.is_empty() {
            return false;
        }

        for domain in &self.network_allowlist {
            if url.contains(domain) {
                return true;
            }
        }
        false
    }
}
