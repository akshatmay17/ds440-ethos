use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::models::{
    AuditEvent, Observation, ProvenanceRecord, ProvenanceTag, SnapshotMetadata, ToolResult,
    TrustLevel,
};
use crate::runtime::{LocalIsolatedRuntime, SandboxRuntime};
use crate::taint::TaintEngine;

pub const NETWORK_PROGRAMS: &[&str] = &["curl", "wget", "nc", "ncat", "ssh", "scp", "ftp"];
pub const DELETE_PROGRAMS: &[&str] = &["rm", "del", "unlink", "shred"];

pub struct ACIHarness {
    pub runtime: Box<dyn SandboxRuntime>,
    pub taint_engine: TaintEngine,
    pub snapshots: HashMap<String, SnapshotMetadata>,
    step_counter: usize,
    audit_events: Vec<AuditEvent>,
}

impl ACIHarness {
    pub fn new_with_temp_dir() -> anyhow::Result<Self> {
        #[allow(deprecated)]
        let temp_dir = tempfile::tempdir()?.into_path();
        let runtime = LocalIsolatedRuntime::new(&temp_dir)?;

        // Marker file for restore_snapshot safety
        std::fs::write(temp_dir.join(".ethos_sandbox"), "ethos sandbox")?;
        let _ = std::fs::write(temp_dir.join(".taintbox_sandbox"), "ethos sandbox");

        Ok(Self {
            runtime: Box::new(runtime),
            taint_engine: TaintEngine::new(),
            snapshots: HashMap::new(),
            step_counter: 0,
            audit_events: Vec::new(),
        })
    }

    pub fn new_with_dir<P: AsRef<Path>>(dir: P) -> anyhow::Result<Self> {
        let runtime = LocalIsolatedRuntime::new(dir)?;
        Ok(Self {
            runtime: Box::new(runtime),
            taint_engine: TaintEngine::new(),
            snapshots: HashMap::new(),
            step_counter: 0,
            audit_events: Vec::new(),
        })
    }

    pub fn root_dir(&self) -> Option<std::path::PathBuf> {
        self.runtime.root_dir()
    }

    fn log_event(&mut self, event_type: &str, action: &str, details: serde_json::Value) {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            event_type: event_type.to_string(),
            action: action.to_string(),
            caller: "agent".to_string(),
            details,
        };
        self.audit_events.push(event);
    }

    pub fn read(&mut self, path: &str) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        let decision = self.taint_engine.evaluate_path_policy("read", path, &[]);
        if !decision.allowed {
            self.log_event(
                "POLICY_BLOCK",
                "read",
                serde_json::json!({ "path": path, "reason": decision.reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "read".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", decision.reason)),
                provenance: None,
                policy_decision: Some(decision),
            };
        }

        match self.runtime.read_file(path) {
            Ok(content) => {
                let rec = self
                    .taint_engine
                    .get_provenance(path)
                    .cloned()
                    .unwrap_or_else(|| {
                        let new_rec = ProvenanceRecord {
                            source_id: path.to_string(),
                            tag: ProvenanceTag::System,
                            trust_level: TrustLevel::Internal,
                            chain_of_custody: vec![],
                            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                            metadata: serde_json::json!({}),
                        };
                        self.taint_engine.record_provenance(path, new_rec.clone());
                        new_rec
                    });

                self.log_event(
                    "TOOL_READ",
                    "read",
                    serde_json::json!({ "path": path, "size": content.len() }),
                );

                ToolResult {
                    call_id,
                    tool_name: "read".to_string(),
                    status: "SUCCESS".to_string(),
                    output: serde_json::Value::String(content),
                    error: None,
                    provenance: Some(rec),
                    policy_decision: None,
                }
            }
            Err(e) => ToolResult {
                call_id,
                tool_name: "read".to_string(),
                status: "ERROR".to_string(),
                output: serde_json::Value::Null,
                error: Some(e.to_string()),
                provenance: None,
                policy_decision: None,
            },
        }
    }

    pub fn write(
        &mut self,
        path: &str,
        content: &str,
        source_ids: Option<Vec<String>>,
    ) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        let ouroboros = crate::walls::ouroboros::OuroborosWall::new();
        if let Err(e) = ouroboros.check_write(path, content) {
            let reason = e.to_string();
            self.log_event(
                "POLICY_BLOCK",
                "write",
                serde_json::json!({ "path": path, "reason": reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "write".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", reason)),
                provenance: None,
                policy_decision: Some(crate::models::PolicyDecision {
                    allowed: false,
                    rule_id: Some("OUROBOROS-WALL".to_string()),
                    action: "write".to_string(),
                    reason,
                    taint_records: vec![],
                }),
            };
        }

        let sources = source_ids.as_deref().unwrap_or(&[]);
        let decision = self
            .taint_engine
            .evaluate_path_policy("write", path, sources);
        if !decision.allowed {
            self.log_event(
                "POLICY_BLOCK",
                "write",
                serde_json::json!({ "path": path, "reason": decision.reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "write".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", decision.reason)),
                provenance: None,
                policy_decision: Some(decision),
            };
        }
        match self.runtime.write_file(path, content) {
            Ok(_) => {
                let rec = if let Some(sources) = &source_ids {
                    self.taint_engine.propagate(sources, path, None)
                } else {
                    let new_rec = ProvenanceRecord {
                        source_id: path.to_string(),
                        tag: ProvenanceTag::User,
                        trust_level: TrustLevel::Internal,
                        chain_of_custody: vec![],
                        timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                        metadata: serde_json::json!({}),
                    };
                    self.taint_engine.record_provenance(path, new_rec.clone());
                    new_rec
                };

                self.log_event(
                    "TOOL_WRITE",
                    "write",
                    serde_json::json!({ "path": path, "size": content.len(), "sources": source_ids }),
                );

                ToolResult {
                    call_id,
                    tool_name: "write".to_string(),
                    status: "SUCCESS".to_string(),
                    output: serde_json::json!(format!(
                        "Successfully wrote {} bytes to {}",
                        content.len(),
                        path
                    )),
                    error: None,
                    provenance: Some(rec),
                    policy_decision: None,
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                let is_escape = err_msg.contains("Path escape")
                    || err_msg.contains("Absolute paths not allowed");
                if is_escape {
                    self.log_event(
                        "POLICY_BLOCK",
                        "write",
                        serde_json::json!({ "path": path, "reason": err_msg }),
                    );
                }
                ToolResult {
                    call_id,
                    tool_name: "write".to_string(),
                    status: if is_escape {
                        "BLOCKED_BY_POLICY".to_string()
                    } else {
                        "ERROR".to_string()
                    },
                    output: serde_json::Value::Null,
                    error: Some(err_msg.clone()),
                    provenance: None,
                    policy_decision: if is_escape {
                        Some(crate::models::PolicyDecision {
                            allowed: false,
                            rule_id: Some("SANDBOX-ESCAPE-GUARD".to_string()),
                            action: "write".to_string(),
                            reason: err_msg,
                            taint_records: vec![],
                        })
                    } else {
                        None
                    },
                }
            }
        }
    }

    pub fn edit_block(
        &mut self,
        path: &str,
        target_content: &str,
        replacement_content: &str,
        source_ids: Option<Vec<String>>,
    ) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        let ouroboros = crate::walls::ouroboros::OuroborosWall::new();
        if let Err(e) = ouroboros.check_write(path, replacement_content) {
            let reason = e.to_string();
            self.log_event(
                "POLICY_BLOCK",
                "edit_block",
                serde_json::json!({ "path": path, "reason": reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "edit_block".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", reason)),
                provenance: None,
                policy_decision: Some(crate::models::PolicyDecision {
                    allowed: false,
                    rule_id: Some("OUROBOROS-WALL".to_string()),
                    action: "edit_block".to_string(),
                    reason,
                    taint_records: vec![],
                }),
            };
        }

        let sources = source_ids.as_deref().unwrap_or(&[]);
        let decision = self
            .taint_engine
            .evaluate_path_policy("write", path, sources);
        if !decision.allowed {
            self.log_event(
                "POLICY_BLOCK",
                "edit_block",
                serde_json::json!({ "path": path, "reason": decision.reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "edit_block".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", decision.reason)),
                provenance: None,
                policy_decision: Some(decision),
            };
        }

        let current = match self.runtime.read_file(path) {
            Ok(c) => c,
            Err(e) => {
                return ToolResult {
                    call_id,
                    tool_name: "edit_block".to_string(),
                    status: "ERROR".to_string(),
                    output: serde_json::Value::Null,
                    error: Some(e.to_string()),
                    provenance: None,
                    policy_decision: None,
                };
            }
        };

        if !current.contains(target_content) {
            return ToolResult {
                call_id,
                tool_name: "edit_block".to_string(),
                status: "ERROR".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Target content not found in file: {}", path)),
                provenance: None,
                policy_decision: None,
            };
        }

        let modified = current.replacen(target_content, replacement_content, 1);
        match self.runtime.write_file(path, &modified) {
            Ok(_) => {
                let rec = if let Some(sources) = &source_ids {
                    self.taint_engine.propagate(sources, path, None)
                } else {
                    let prev_rec = self.taint_engine.get_provenance(path).cloned();
                    prev_rec.unwrap_or_else(|| {
                        let new_rec = ProvenanceRecord {
                            source_id: path.to_string(),
                            tag: ProvenanceTag::User,
                            trust_level: TrustLevel::Internal,
                            chain_of_custody: vec![],
                            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                            metadata: serde_json::json!({}),
                        };
                        self.taint_engine.record_provenance(path, new_rec.clone());
                        new_rec
                    })
                };

                self.log_event(
                    "TOOL_EDIT_BLOCK",
                    "edit_block",
                    serde_json::json!({ "path": path }),
                );

                ToolResult {
                    call_id,
                    tool_name: "edit_block".to_string(),
                    status: "SUCCESS".to_string(),
                    output: serde_json::json!(format!("Successfully replaced block in {}", path)),
                    error: None,
                    provenance: Some(rec),
                    policy_decision: None,
                }
            }
            Err(e) => ToolResult {
                call_id,
                tool_name: "edit_block".to_string(),
                status: "ERROR".to_string(),
                output: serde_json::Value::Null,
                error: Some(e.to_string()),
                provenance: None,
                policy_decision: None,
            },
        }
    }

    pub fn fold_output(&self, text: &str, head_lines: usize, tail_lines: usize) -> String {
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() <= head_lines + tail_lines {
            return text.to_string();
        }

        let head = &lines[..head_lines];
        let tail = &lines[lines.len() - tail_lines..];
        let truncated_count = lines.len() - head_lines - tail_lines;

        format!(
            "{}\n\n... [{} lines truncated to preserve model context] ...\n\n{}",
            head.join("\n"),
            truncated_count,
            tail.join("\n")
        )
    }

    pub fn view_lines(&mut self, path: &str, start_line: usize, end_line: usize) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        match self.runtime.read_file(path) {
            Ok(content) => {
                let lines: Vec<&str> = content.lines().collect();
                if lines.is_empty() {
                    return ToolResult {
                        call_id,
                        tool_name: "view_lines".to_string(),
                        status: "SUCCESS".to_string(),
                        output: serde_json::Value::String(String::new()),
                        error: None,
                        provenance: self.taint_engine.get_provenance(path).cloned(),
                        policy_decision: None,
                    };
                }

                let start_idx = if start_line == 0 { 0 } else { start_line - 1 };
                let end_idx = std::cmp::min(end_line, lines.len());

                let mut formatted = String::new();
                for (idx, line) in lines.iter().enumerate().take(end_idx).skip(start_idx) {
                    formatted.push_str(&format!("{}: {}\n", idx + 1, line));
                }

                self.log_event(
                    "TOOL_VIEW_LINES",
                    "view_lines",
                    serde_json::json!({ "path": path, "start": start_line, "end": end_line }),
                );

                ToolResult {
                    call_id,
                    tool_name: "view_lines".to_string(),
                    status: "SUCCESS".to_string(),
                    output: serde_json::Value::String(formatted),
                    error: None,
                    provenance: self.taint_engine.get_provenance(path).cloned(),
                    policy_decision: None,
                }
            }
            Err(e) => ToolResult {
                call_id,
                tool_name: "view_lines".to_string(),
                status: "ERROR".to_string(),
                output: serde_json::Value::Null,
                error: Some(e.to_string()),
                provenance: None,
                policy_decision: None,
            },
        }
    }

    pub fn search_files(&mut self, pattern: &str) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        let all_files = self.runtime.list_files();

        let clean_pattern = pattern.trim_start_matches('*').trim_end_matches('*');
        let matched: Vec<String> = all_files
            .into_iter()
            .filter(|f| {
                if pattern == "*" || pattern == "**/*" {
                    true
                } else if pattern.starts_with('*') {
                    f.ends_with(clean_pattern)
                } else {
                    f.contains(clean_pattern)
                }
            })
            .collect();

        self.log_event(
            "TOOL_SEARCH_FILES",
            "search_files",
            serde_json::json!({ "pattern": pattern, "matches": matched.len() }),
        );

        ToolResult {
            call_id,
            tool_name: "search_files".to_string(),
            status: "SUCCESS".to_string(),
            output: serde_json::to_value(&matched).unwrap_or(serde_json::json!([])),
            error: None,
            provenance: None,
            policy_decision: None,
        }
    }

    pub fn grep(&mut self, query: &str) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();
        let all_files = self.runtime.list_files();
        let mut results = String::new();

        for file in all_files {
            if let Ok(content) = self.runtime.read_file(&file) {
                for (idx, line) in content.lines().enumerate() {
                    if line.contains(query) {
                        results.push_str(&format!("{}:{}: {}\n", file, idx + 1, line));
                    }
                }
            }
        }

        self.log_event("TOOL_GREP", "grep", serde_json::json!({ "query": query }));

        ToolResult {
            call_id,
            tool_name: "grep".to_string(),
            status: "SUCCESS".to_string(),
            output: serde_json::Value::String(results),
            error: None,
            provenance: None,
            policy_decision: None,
        }
    }

    pub fn fetch(
        &mut self,
        url: &str,
        save_as: Option<&str>,
        mock_content: Option<&str>,
    ) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();

        // Enforce network egress policy
        let decision = self.taint_engine.evaluate_network_egress(url, &[]);
        if !decision.allowed {
            self.log_event(
                "POLICY_BLOCK",
                "fetch",
                serde_json::json!({ "url": url, "reason": decision.reason }),
            );
            return ToolResult {
                call_id,
                tool_name: "fetch".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(format!("Policy violation: {}", decision.reason)),
                provenance: None,
                policy_decision: Some(decision),
            };
        }

        let target_path = save_as
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("downloads/{}.txt", Uuid::new_v4().simple()));

        let payload = if let Some(mock) = mock_content {
            mock.to_string()
        } else {
            // Attempt real HTTP GET via reqwest
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            let fetch_res: Result<String, String> =
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    tokio::task::block_in_place(|| {
                        rt.block_on(async {
                            match client.get(url).send().await {
                                Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
                                Err(e) => Err(e.to_string()),
                            }
                        })
                    })
                } else if let Ok(rt) = tokio::runtime::Runtime::new() {
                    rt.block_on(async {
                        match client.get(url).send().await {
                            Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
                            Err(e) => Err(e.to_string()),
                        }
                    })
                } else {
                    Err("Runtime unavailable".to_string())
                };

            match fetch_res {
                Ok(text) => text,
                Err(e) => {
                    format!("<!-- [Ethos Web Fetch] Offline simulated content for {} ({}) -->\nUntrusted web payload for evaluation.", url, e)
                }
            }
        };

        if let Err(e) = self.runtime.write_file(&target_path, &payload) {
            return ToolResult {
                call_id,
                tool_name: "fetch".to_string(),
                status: "ERROR".to_string(),
                output: serde_json::Value::Null,
                error: Some(e.to_string()),
                provenance: None,
                policy_decision: None,
            };
        }

        let record = ProvenanceRecord {
            source_id: target_path.clone(),
            tag: ProvenanceTag::UntrustedWeb,
            trust_level: TrustLevel::Untrusted,
            chain_of_custody: vec![url.to_string()],
            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            metadata: serde_json::json!({ "origin_url": url }),
        };
        self.taint_engine
            .record_provenance(&target_path, record.clone());

        self.log_event(
            "TOOL_FETCH",
            "fetch",
            serde_json::json!({ "url": url, "saved_to": target_path }),
        );

        ToolResult {
            call_id,
            tool_name: "fetch".to_string(),
            status: "SUCCESS".to_string(),
            output: serde_json::Value::String(payload),
            error: None,
            provenance: Some(record),
            policy_decision: Some(decision),
        }
    }

    pub fn exec(&mut self, program: &str, args: &[String]) -> ToolResult {
        let call_id = Uuid::new_v4().to_string();

        let mut target_url = "https://unknown-egress".to_string();
        let mut action = if NETWORK_PROGRAMS
            .iter()
            .any(|&p| p.eq_ignore_ascii_case(program))
        {
            "network_egress"
        } else if DELETE_PROGRAMS
            .iter()
            .any(|&p| p.eq_ignore_ascii_case(program))
        {
            "file_delete"
        } else if ["bash", "sh", "dash", "zsh", "cmd", "powershell", "pwsh"]
            .iter()
            .any(|&p| p.eq_ignore_ascii_case(program))
        {
            "exec_privileged"
        } else {
            "exec"
        };

        let is_shell_wrapper = ["bash", "sh", "dash", "zsh", "cmd", "powershell", "pwsh"]
            .iter()
            .any(|&p| p.eq_ignore_ascii_case(program));

        if action == "exec_privileged" {
            for i in 0..args.len() {
                if args[i] == "-c" || args[i] == "-Command" {
                    if let Some(cmd) = args.get(i + 1) {
                        if NETWORK_PROGRAMS.iter().any(|&p| cmd.contains(p)) {
                            action = "network_egress";
                            if let Some(url) = cmd.split_whitespace().find(|a| {
                                a.starts_with("http://")
                                    || a.starts_with("https://")
                                    || a.contains("://")
                            }) {
                                target_url = url.to_string();
                            }
                        } else if DELETE_PROGRAMS.iter().any(|&p| cmd.contains(p)) {
                            action = "file_delete";
                        }
                    }
                }
            }
        }

        // Scan args for referenced files
        let mut referenced_files = Vec::new();
        for arg in args {
            let clean = arg.trim_start_matches('@').trim();
            if self.runtime.file_exists(clean) {
                referenced_files.push(clean.to_string());
            }
        }
        // Shell commands embed filenames in -c content — scan those too
        if is_shell_wrapper {
            for arg in args {
                if arg == "-c" || arg == "-Command" {
                    continue;
                }
                for word in arg.split_whitespace() {
                    let clean = word.trim_start_matches('@').trim();
                    if self.runtime.file_exists(clean)
                        && !referenced_files.contains(&clean.to_string())
                    {
                        referenced_files.push(clean.to_string());
                    }
                }
            }
        }

        if action == "network_egress" || action == "file_delete" {
            for t in self.taint_engine.list_tainted_resources() {
                if !referenced_files.contains(&t) {
                    referenced_files.push(t);
                }
            }
        }

        if action == "network_egress" && target_url == "https://unknown-egress" {
            if let Some(url) = args.iter().find(|a| {
                a.starts_with("http://") || a.starts_with("https://") || a.contains("://")
            }) {
                target_url = url.to_string();
            }
        }

        let decision = if action == "network_egress" {
            let net_decision = self
                .taint_engine
                .evaluate_network_egress(&target_url, &referenced_files);
            if !net_decision.allowed {
                net_decision
            } else {
                // Even if network destination is allowlisted, still enforce general taint policy
                let taint_decision = self.taint_engine.evaluate_policy(action, &referenced_files);
                if !taint_decision.allowed {
                    taint_decision
                } else {
                    net_decision
                }
            }
        } else {
            self.taint_engine.evaluate_policy(action, &referenced_files)
        };

        if !decision.allowed {
            self.log_event(
                "POLICY_BLOCK",
                action,
                serde_json::json!({
                    "program": program,
                    "args": args,
                    "reason": decision.reason
                }),
            );

            return ToolResult {
                call_id,
                tool_name: "exec".to_string(),
                status: "BLOCKED_BY_POLICY".to_string(),
                output: serde_json::Value::Null,
                error: Some(decision.reason.clone()),
                provenance: None,
                policy_decision: Some(decision),
            };
        }

        let (exit_code, stdout, stderr) = self.runtime.execute_command(program, args);

        self.log_event(
            "TOOL_EXEC",
            action,
            serde_json::json!({ "program": program, "args": args, "exit_code": exit_code }),
        );

        ToolResult {
            call_id,
            tool_name: "exec".to_string(),
            status: if exit_code == 0 {
                "SUCCESS".to_string()
            } else {
                "ERROR".to_string()
            },
            output: serde_json::json!({ "exit_code": exit_code, "stdout": stdout, "stderr": stderr }),
            error: if exit_code != 0 { Some(stderr) } else { None },
            provenance: None,
            policy_decision: Some(decision),
        }
    }

    pub fn snapshot(&mut self, description: &str) -> anyhow::Result<SnapshotMetadata> {
        let snap_id = format!("snap_{}", chrono::Utc::now().timestamp_millis());
        let file_hashes = self.runtime.create_snapshot(&snap_id)?;
        let taint_state = self.taint_engine.export_state();

        let meta = SnapshotMetadata {
            snapshot_id: snap_id.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            description: description.to_string(),
            file_hashes,
            taint_ledger_state: taint_state,
        };

        self.snapshots.insert(snap_id.clone(), meta.clone());
        self.log_event(
            "SNAPSHOT_CREATED",
            "snapshot",
            serde_json::json!({ "snapshot_id": snap_id, "description": description }),
        );

        Ok(meta)
    }

    pub fn rewind(&mut self, snapshot_id: &str) -> anyhow::Result<()> {
        let meta = self
            .snapshots
            .get(snapshot_id)
            .ok_or_else(|| anyhow::anyhow!("Snapshot not found: {}", snapshot_id))?
            .clone();

        self.runtime.restore_snapshot(snapshot_id)?;
        self.taint_engine.restore_state(meta.taint_ledger_state);

        self.log_event(
            "SNAPSHOT_REWOUND",
            "rewind",
            serde_json::json!({ "snapshot_id": snapshot_id }),
        );
        Ok(())
    }

    pub fn observe(&mut self) -> Observation {
        self.step_counter += 1;
        let files = self.runtime.list_files();
        let tainted = self.taint_engine.list_tainted_resources();

        let mut prov_context = HashMap::new();
        for t in &tainted {
            if let Some(rec) = self.taint_engine.get_provenance(t) {
                prov_context.insert(
                    t.clone(),
                    serde_json::json!({
                        "tag": rec.tag,
                        "trust_level": rec.trust_level,
                        "chain_of_custody": rec.chain_of_custody,
                    }),
                );
            }
        }

        Observation {
            step_id: self.step_counter,
            modified_files: vec![],
            created_files: files,
            deleted_files: vec![],
            active_taint_count: tainted.len(),
            tainted_resources: tainted,
            provenance_context: prov_context,
        }
    }

    pub fn get_audit_events(&self) -> Vec<AuditEvent> {
        self.audit_events.clone()
    }

    pub fn init_workspace(&mut self) -> anyhow::Result<InitSummary> {
        let scanner = crate::walls::promptinject::PromptInjectScanner::new();
        let mut warnings = Vec::new();
        let mut file_records = Vec::new();

        // 1. Check or generate AGENTS.md
        let agents_md_status = if self.runtime.file_exists("AGENTS.md") {
            let content = self.runtime.read_file("AGENTS.md").unwrap_or_default();
            let findings = scanner.scan(&content);
            if !findings.is_empty() {
                warnings.push(format!(
                    "AGENTS.md contains {} suspicious prompt injection pattern(s)!",
                    findings.len()
                ));
                self.taint_engine.record_provenance("AGENTS.md", ProvenanceRecord {
                    source_id: "AGENTS.md".to_string(),
                    tag: ProvenanceTag::ExternalFile,
                    trust_level: TrustLevel::Untrusted,
                    chain_of_custody: vec!["pre_existing_workspace".to_string()],
                    timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                    metadata: serde_json::json!({ "scanner_tripped": true, "findings": findings }),
                });
                "Pre-existing [WARNING: Untrusted Injection Patterns Detected]".to_string()
            } else {
                "Pre-existing [Verified Clean]".to_string()
            }
        } else {
            let template = "# AGENTS.md - Ethos Autonomous Agent Workspace\n\n\
                ## Core Rules & Guardrails\n\
                1. Always inspect files and verify dependencies before modifications.\n\
                2. Untrusted external files and web fetches are quarantined in the Taint Ledger.\n\
                3. Unauthorized network egress is strictly prohibited by BoundaryPolicyEngine.\n\n\
                ## Permitted Tools\n\
                `read`, `write`, `edit_block`, `view_lines`, `search_files`, `grep`, `fetch`, `exec`, `snapshot`, `rewind`, `observe`\n";
            self.runtime.write_file("AGENTS.md", template)?;
            "Generated clean AGENTS.md template".to_string()
        };

        // 2. Walk directory and index all files
        let all_files = self.runtime.list_files();
        for file in &all_files {
            if file == "AGENTS.md" && agents_md_status.contains("Pre-existing") {
                let is_untrusted = self.taint_engine.is_tainted(file);
                file_records.push((
                    file.clone(),
                    "sha256:pre_existing".to_string(),
                    is_untrusted,
                ));
                continue;
            }

            let content = self.runtime.read_file(file).unwrap_or_default();
            let hash = hex::encode(Sha256::digest(content.as_bytes()));
            let findings = scanner.scan(&content);

            let is_untrusted = if !findings.is_empty() {
                warnings.push(format!(
                    "File '{}' flagged: {} suspicious pattern(s)",
                    file,
                    findings.len()
                ));
                true
            } else {
                false
            };

            let tag = if is_untrusted {
                ProvenanceTag::ExternalFile
            } else {
                ProvenanceTag::Internal
            };
            let trust_level = if is_untrusted {
                TrustLevel::Untrusted
            } else {
                TrustLevel::Internal
            };

            if !self.taint_engine.is_tainted(file) {
                self.taint_engine.record_provenance(file, ProvenanceRecord {
                    source_id: file.clone(),
                    tag,
                    trust_level,
                    chain_of_custody: vec!["workspace_init".to_string()],
                    timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                    metadata: serde_json::json!({ "sha256": hash, "findings_count": findings.len() }),
                });
            }

            file_records.push((file.clone(), hash, is_untrusted));
        }

        // 3. Create baseline snapshot
        let _ = self.snapshot("workspace_init_baseline");

        Ok(InitSummary {
            total_files_indexed: all_files.len(),
            agents_md_status,
            warnings,
            file_records,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InitSummary {
    pub total_files_indexed: usize,
    pub agents_md_status: String,
    pub warnings: Vec<String>,
    pub file_records: Vec<(String, String, bool)>,
}
