pub struct OuroborosWall {
    protected_patterns: Vec<&'static str>,
}

impl Default for OuroborosWall {
    fn default() -> Self {
        Self::new()
    }
}

impl OuroborosWall {
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
