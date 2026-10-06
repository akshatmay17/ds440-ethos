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
                // Ethos-owned credential/config stores: the setup wizard and
                // models.dev cache live under the user home directory and are
                // readable by host-level exec — treat them as secrets.
                ".ethos/config.json".to_string(),
                ".taintbox/config.json".to_string(),
                "models_dev_cache.json".to_string(),
            ],
            network_allowlist: Vec::new(),
            valid_tokens,
        }
    }
}

impl TaintPolicyConfig {
    pub fn is_path_sensitive(&self, path: &str) -> bool {
        // Case-folded: NTFS/APFS resolve ".ENV" to ".env", so a raw-argument
        // case twist must not slip the secret-path read guard.
        let normalized = path.replace('\\', "/").to_lowercase();
        for sensitive in &self.sensitive_paths {
            let s = sensitive.to_lowercase();
            if normalized == s || normalized.ends_with(&s) || normalized.contains(&s) {
                return true;
            }
        }
        false
    }

    /// Extract the host portion of a URL (no url crate in dependency tree —
    /// hand-rolled, covers scheme://[userinfo@]host[:port]/...).
    fn url_host(url: &str) -> String {
        let rest = url
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(url);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        host.split(':').next().unwrap_or(host).to_lowercase()
    }

    pub fn is_network_allowed(&self, url: &str) -> bool {
        if self.network_allowlist.is_empty() {
            return false;
        }

        // Host-based match, NOT substring: an allowlisted "api.github.com"
        // must not approve "api.github.com.evil.com" or
        // "https://evil.com/?u=api.github.com" (RT-17). Exact host or a
        // dot-delimited subdomain of an allowlisted host passes.
        let host = Self::url_host(url);
        if host.is_empty() {
            return false;
        }
        for domain in &self.network_allowlist {
            let d = domain.to_lowercase();
            if host == d || host.ends_with(&format!(".{}", d)) {
                return true;
            }
        }
        false
    }
}
