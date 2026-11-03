pub struct OuroborosWall {
    protected_patterns: Vec<&'static str>,
}

impl Default for OuroborosWall {
    fn default() -> Self {
        Self::new()
    }
}

impl OuroborosWall {
    /// Conservative exec-side check: instructions remain readable through
    /// structured read tools; opaque interpreter commands referencing these
    /// surfaces are rejected because their read/write intent is ambiguous.
    pub fn references_instruction_surface(text: &str) -> bool {
        let normalized = text.replace('\\', "/").to_lowercase();
        normalized.split(|c: char| !(c.is_alphanumeric() || "._/-".contains(c)))
            .any(|token| {
                let basename = token.rsplit('/').next().unwrap_or(token);
                matches!(basename, "agents.md" | "claude.md" | "gemini.md" | "skill.md" | "memory.md")
                    || token.split('/').any(|p| matches!(p, ".claude" | ".agents" | ".cursor"))
            })
    }

    pub fn new() -> Self {
        Self {
            // Patterns are stored lowercase; comparison is case-folded because
            // filesystems (NTFS, default macOS) are case-insensitive while
            // attackers control the raw tool argument casing.
            protected_patterns: vec![
                "tests/",
                "src/taint/",
                "src/walls/",
                "migrations/",
                ".git/",
                "cargo.toml",
                ".github/workflows/",
                "policy.default.yaml",
                "config/runtime.yaml",
                "config/exec.container.json",
                ".ethos_provenance.json",
                // Sandbox identity markers are trusted by restore_snapshot's
                // destructive-rewind guard; forging them through the tool
                // layer would arm wipes on non-sandbox directories.
                ".ethos_sandbox",
                ".taintbox_sandbox",
            ],
        }
    }

    pub fn check_write(&self, target_path: &str, _content: &str) -> anyhow::Result<()> {
        let normalized = target_path.replace('\\', "/").to_lowercase();
        // Instruction and persistent-memory files can promote attacker text
        // into trusted instructions on a later turn/session. Only the operator
        // may change these through a trusted path outside agent tools.
        if Self::references_instruction_surface(&normalized) {
            return Err(anyhow::anyhow!(
                "Ouroboros Wall Block: Agent modification of instruction/memory surface '{}' is prohibited",
                target_path
            ));
        }
        for pattern in &self.protected_patterns {
            if normalized.contains(pattern) || normalized.starts_with(pattern) {
                return Err(anyhow::anyhow!(
                    "Ouroboros Wall Block: Modification of security-critical infrastructure '{}' is prohibited",
                    target_path
                ));
            }
        }
        Ok(())
    }
}
