//! Secret Redaction Wall.
//!
//! Path-based guards try to stop the agent from *opening* secret files, but
//! there are endless ways to open a file (`cat`, `head`, globs, interpreters).
//! This wall works on *values* instead: it learns the secret values that exist
//! in the workspace and environment, then scrubs them out of every tool result
//! before the model sees it. It also refuses outbound tool calls whose
//! arguments carry a known secret value.

use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

pub const REDACTION_MARKER: &str = "[REDACTED]";

const MAX_DEPTH: usize = 4;
const MAX_ENTRIES: usize = 5_000;
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MIN_SECRET_LEN: usize = 8;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".ethos_snapshots",
    ".taintbox_snapshots",
];
const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist"];
const SECRET_NAME_TOKENS: &[&str] = &[
    "key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "credentials",
];

#[derive(Debug, Clone, Default)]
pub struct SecretRedactor {
    /// Known secret values, longest first so overlapping values redact cleanly.
    values: Vec<String>,
    patterns: Vec<Regex>,
}

impl SecretRedactor {
    /// A redactor that only knows the built-in credential formats.
    pub fn new() -> Self {
        let patterns = [
            r"sk-[A-Za-z0-9_\-]{20,}",
            r"gh[pousr]_[A-Za-z0-9]{30,}",
            r"AKIA[0-9A-Z]{16}",
            r"xox[baprs]-[A-Za-z0-9\-]{10,}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
        Self {
            values: Vec::new(),
            patterns,
        }
    }

    /// Build a redactor from explicit values (used by tests and callers that
    /// already hold the secrets).
    pub fn with_values<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut r = Self::new();
        let set: BTreeSet<String> = values
            .into_iter()
            .map(Into::into)
            .filter(|v| looks_secret(v))
            .collect();
        r.set_values(set);
        r
    }

    /// Learn secrets from the sandbox workspace, the process environment and
    /// the Ethos credential stores in the user's home directory.
    pub fn collect<F>(root: Option<&Path>, is_sensitive: F) -> Self
    where
        F: Fn(&str) -> bool,
    {
        let mut set = BTreeSet::new();
        if let Some(root) = root {
            let mut budget = MAX_ENTRIES;
            walk(root, root, 0, &mut budget, &is_sensitive, &mut set);
        }
        collect_env(&mut set);
        collect_home_stores(&mut set);
        let mut r = Self::new();
        r.set_values(set);
        r
    }

    fn set_values(&mut self, set: BTreeSet<String>) {
        let mut values: Vec<String> = set.into_iter().collect();
        values.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        self.values = values;
    }

    pub fn known_value_count(&self) -> usize {
        self.values.len()
    }

    /// Replace every known secret in `text`. Returns the clean text and the
    /// number of replacements made.
    pub fn redact(&self, text: &str) -> (String, usize) {
        let mut out = text.to_string();
        let mut count = 0;
        for v in &self.values {
            let hits = out.matches(v.as_str()).count();
            if hits > 0 {
                count += hits;
                out = out.replace(v.as_str(), REDACTION_MARKER);
            }
        }
        for p in &self.patterns {
            let hits = p.find_iter(&out).count();
            if hits > 0 {
                count += hits;
                out = p.replace_all(&out, REDACTION_MARKER).into_owned();
            }
        }
        (out, count)
    }

    /// Redact every string inside a JSON value, in place.
    pub fn redact_value(&self, value: &mut serde_json::Value) -> usize {
        match value {
            serde_json::Value::String(s) => {
                let (clean, n) = self.redact(s);
                if n > 0 {
                    *s = clean;
                }
                n
            }
            serde_json::Value::Array(items) => items.iter_mut().map(|v| self.redact_value(v)).sum(),
            serde_json::Value::Object(map) => {
                map.values_mut().map(|v| self.redact_value(v)).sum()
            }
            _ => 0,
        }
    }

    /// True if `text` carries a known secret value or credential pattern.
    pub fn contains_secret(&self, text: &str) -> bool {
        self.values.iter().any(|v| text.contains(v.as_str()))
            || self.patterns.iter().any(|p| p.is_match(text))
    }

    /// True if any string inside a JSON value carries a known secret.
    pub fn value_contains_secret(&self, value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(s) => self.contains_secret(s),
            serde_json::Value::Array(items) => items.iter().any(|v| self.value_contains_secret(v)),
            serde_json::Value::Object(map) => map.values().any(|v| self.value_contains_secret(v)),
            _ => false,
        }
    }
}

/// Heuristic that keeps ordinary config values (`true`, `8000`, `production`)
/// from being treated as secrets and scrubbed out of unrelated output.
fn looks_secret(v: &str) -> bool {
    let v = v.trim();
    if v.len() < MIN_SECRET_LEN {
        return false;
    }
    if v.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    if v.len() < 20 && v.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    true
}

fn name_is_secretish(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| SECRET_NAME_TOKENS.contains(&tok))
}

fn is_template(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    TEMPLATE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

fn walk<F>(
    root: &Path,
    dir: &Path,
    depth: usize,
    budget: &mut usize,
    is_sensitive: &F,
    out: &mut BTreeSet<String>,
) where
    F: Fn(&str) -> bool,
{
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if file_type.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(root, &path, depth + 1, budget, is_sensitive, out);
            }
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if !is_sensitive(&rel) || is_template(&rel) {
            continue;
        }
        if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            extract_values(&rel, &content, out);
        }
    }
}

/// Pull candidate secret values out of one sensitive file.
fn extract_values(rel: &str, content: &str, out: &mut BTreeSet<String>) {
    let lower = rel.to_lowercase();

    if lower.ends_with(".json") {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
            // In a dedicated secrets file every string counts; elsewhere only
            // fields whose name looks like a credential.
            let all = lower.ends_with("secrets.json");
            collect_json(&json, all, false, out);
            return;
        }
    }

    let mut saw_assignment = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, value)) = line.split_once('=') {
            if !key.trim().is_empty() && !key.contains(' ') {
                saw_assignment = true;
                let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
                if looks_secret(value) {
                    out.insert(value.to_string());
                }
            }
        }
    }

    // Key material (id_rsa, id_ed25519, ...): no KEY=VALUE lines, so every
    // substantial line is part of the secret.
    if !saw_assignment {
        for line in content.lines() {
            let line = line.trim();
            if line.len() >= 20 && !line.starts_with("-----") {
                out.insert(line.to_string());
            }
        }
    }
}

fn collect_json(
    value: &serde_json::Value,
    all: bool,
    parent_secretish: bool,
    out: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::String(s) => {
            if (all || parent_secretish) && looks_secret(s) {
                out.insert(s.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_json(v, all, parent_secretish, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_json(v, all, name_is_secretish(k), out);
            }
        }
        _ => {}
    }
}

/// Child processes inherit the Ethos environment, so `env` / `printenv` would
/// otherwise print provider keys straight back to the model.
fn collect_env(out: &mut BTreeSet<String>) {
    for (name, value) in std::env::vars() {
        if name_is_secretish(&name) && looks_secret(&value) {
            out.insert(value);
        }
    }
}

fn collect_home_stores(out: &mut BTreeSet<String>) {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    if home.is_empty() {
        return;
    }
    for rel in [".ethos/config.json", ".taintbox/config.json"] {
        let path = Path::new(&home).join(rel);
        if let Ok(content) = std::fs::read_to_string(&path) {
            extract_values(rel, &content, out);
        }
    }
}
