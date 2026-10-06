use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: Severity,
    pub pattern_name: String,
    pub match_excerpt: String,
}

struct PatternDef {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: Regex,
}

pub struct PromptInjectScanner {
    patterns: Vec<PatternDef>,
}

impl Default for PromptInjectScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptInjectScanner {
    pub fn new() -> Self {
        let pattern_specs: Vec<(&str, &str, Severity, &str)> = vec![
            (
                "ignore_previous",
                "instruction_override",
                Severity::High,
                r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(the above|previous|prior|earlier)\s+(instructions?|prompts?|rules?|directives?)\b",
            ),
            (
                "ignore_above_broad",
                "instruction_override",
                Severity::High,
                r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(the above|previous|prior|earlier)\b",
            ),
            (
                "new_task",
                "instruction_override",
                Severity::Medium,
                r"(?i)\b(your\s+new\s+task\s+is|you\s+must\s+now|disregard\s+everything)\b",
            ),
            (
                "role_confusion",
                "role_confusion",
                Severity::High,
                r"(?i)\b(you\s+are\s+now|pretend\s+to\s+be|from\s+now\s+on\s+respond\s+as)\s+[A-Za-z0-9_-]+\b",
            ),
            (
                "dan_jailbreak",
                "capability_jailbreak",
                Severity::High,
                r"(?i)\b(DAN\s+mode|jailbreak|developer\s+mode|unrestricted\s+AI|no\s+restrictions)\b",
            ),
            (
                "exfil_credentials",
                "exfiltration",
                Severity::High,
                r"(?i)\b(exfiltrate|id_rsa|\.env|dump\s+credentials|system\s+prompt|send\s+to\s+evil)\b",
            ),
            (
                "tool_misuse",
                "tool_misuse",
                Severity::High,
                r"(?i)\b(curl\s+-X|curl\s+.*http|wget\s+.*http|rm\s+-rf\s+/)\b",
            ),
        ];

        let mut compiled = Vec::new();
        for (name, category, severity, pat) in pattern_specs {
            if let Ok(re) = Regex::new(pat) {
                compiled.push(PatternDef {
                    name,
                    category,
                    severity,
                    regex: re,
                });
            }
        }

        Self { patterns: compiled }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for p in &self.patterns {
            if let Some(mat) = p.regex.find(text) {
                findings.push(Finding {
                    category: p.category.to_string(),
                    severity: p.severity,
                    pattern_name: p.name.to_string(),
                    match_excerpt: mat.as_str().to_string(),
                });
            }
        }

        findings
    }

    /// LLM-safe findings digest: pattern names and categories only. Never
    /// embed `match_excerpt` into agent-facing context — the raw excerpt is
    /// attacker text and re-delivering it verbatim is itself an injection
    /// channel (RT-13).
    pub fn summarize_findings(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(|f| format!("{}[{}]", f.pattern_name, f.category))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
