//! LLM drivers shared by `ethos run`, `ethos eval` and the TUI.
//!
//! Two wire formats are supported:
//! * [`OpenAiCompatDriver`] — `/chat/completions` with native `tools`
//!   (LM Studio, Ollama, OpenAI, OpenRouter, any OpenAI-compatible server).
//! * [`AnthropicDriver`] — the Anthropic Messages API over raw HTTP.
//!
//! Both drivers send exactly one tool result per tool call. The agent loop
//! records advisory digests (PromptInjectScanner / SemanticGuard) as extra
//! `Tool` messages; [`fold_advisories`] merges those into the adjacent tool
//! result, because both APIs reject a second result for the same call.
//!
//! A transport failure, an HTTP error status, or an empty response is
//! returned as `Err` so the caller can mark the run invalid. Nothing here
//! fabricates a "completed" turn.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::aci::agent_loop::{
    parse_tool_call, AgentMessage, AgentRole, AgentStepAction, LlmDriver, TokenUsage,
};

/// Thread-safe cumulative token counter.
#[derive(Default)]
pub struct UsageCounter {
    input: AtomicU64,
    output: AtomicU64,
    last_input: AtomicU64,
}

impl UsageCounter {
    fn add(&self, input: u64, output: u64) {
        self.input.fetch_add(input, Ordering::Relaxed);
        self.output.fetch_add(output, Ordering::Relaxed);
        self.last_input.store(input, Ordering::Relaxed);
    }
    fn get(&self) -> TokenUsage {
        TokenUsage {
            input: self.input.load(Ordering::Relaxed),
            output: self.output.load(Ordering::Relaxed),
            last_input: self.last_input.load(Ordering::Relaxed),
        }
    }
}

/// Tool names the agent loop uses for advisory (non-result) messages.
const ADVISORY_SOURCES: &[&str] = &["promptinject_scanner", "semantic_guard"];

fn is_advisory(m: &AgentMessage) -> bool {
    m.role == AgentRole::Tool
        && m
            .tool_name
            .as_deref()
            .is_some_and(|n| ADVISORY_SOURCES.contains(&n))
}

/// Returns the history with advisory `Tool` messages folded into the next
/// real tool result (or the previous one, if no result follows), so every
/// assistant tool call is answered by exactly one tool message.
pub fn fold_advisories(history: &[AgentMessage]) -> Vec<AgentMessage> {
    let mut out: Vec<AgentMessage> = Vec::with_capacity(history.len());
    let mut pending: Vec<String> = Vec::new();
    for m in history {
        if is_advisory(m) {
            pending.push(m.content.clone());
            continue;
        }
        if m.role == AgentRole::Tool && !pending.is_empty() {
            let mut merged = m.clone();
            merged.content = format!("{}\n{}", pending.join("\n"), m.content);
            pending.clear();
            out.push(merged);
            continue;
        }
        if !pending.is_empty() {
            // Advisories with no following result: attach to the last tool
            // message if there is one, otherwise drop them.
            if let Some(last) = out.iter_mut().rev().find(|x| x.role == AgentRole::Tool) {
                last.content.push('\n');
                last.content.push_str(&pending.join("\n"));
            }
            pending.clear();
        }
        out.push(m.clone());
    }
    if !pending.is_empty() {
        if let Some(last) = out.iter_mut().rev().find(|x| x.role == AgentRole::Tool) {
            last.content.push('\n');
            last.content.push_str(&pending.join("\n"));
        }
    }
    out
}

/// Runs an async HTTP call from the synchronous `LlmDriver::step`.
/// On a multi-thread runtime this uses `block_in_place`; on a current-thread
/// runtime (or none) it runs the future on a short-lived helper thread, since
/// blocking a current-thread runtime from inside itself would panic.
fn block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| h.block_on(fut))
        }
        _ => std::thread::scope(|s| {
            s.spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime")
                    .block_on(fut)
            })
            .join()
            .expect("driver thread panicked")
        }),
    }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible
// ---------------------------------------------------------------------------

pub struct OpenAiCompatDriver {
    pub client: reqwest::Client,
    /// Base URL ending in `/v1` (the driver appends `/chat/completions`).
    pub api_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub max_tokens: u32,
    pub timeout: Duration,
    usage: UsageCounter,
}

impl OpenAiCompatDriver {
    pub fn new(api_url: &str, model: &str, api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url: api_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key: api_key.filter(|k| !k.trim().is_empty()),
            max_tokens: 4096,
            timeout: Duration::from_secs(600),
            usage: UsageCounter::default(),
        }
    }

    fn build_messages(history: &[AgentMessage]) -> Vec<serde_json::Value> {
        let mut msgs = Vec::new();
        let mut counter = 0;
        let mut last_id = String::new();
        for m in fold_advisories(history) {
            match m.role {
                AgentRole::System => {
                    msgs.push(serde_json::json!({ "role": "system", "content": m.content }))
                }
                AgentRole::User => {
                    msgs.push(serde_json::json!({ "role": "user", "content": m.content }))
                }
                AgentRole::Assistant => {
                    if let Some(tc) = parse_tool_call(&m.content) {
                        counter += 1;
                        last_id = format!("call_{}", counter);
                        msgs.push(serde_json::json!({
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": last_id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": tc.arguments.to_string()
                                }
                            }]
                        }));
                    } else {
                        msgs.push(serde_json::json!({ "role": "assistant", "content": m.content }));
                    }
                }
                AgentRole::Tool => {
                    if last_id.is_empty() {
                        // A tool message with no preceding call: send as user text.
                        msgs.push(serde_json::json!({ "role": "user", "content": m.content }));
                    } else {
                        msgs.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": last_id,
                            "content": m.content
                        }));
                        last_id.clear();
                    }
                }
            }
        }
        msgs
    }
}

impl LlmDriver for OpenAiCompatDriver {
    fn step(&self, history: &[AgentMessage]) -> anyhow::Result<AgentStepAction> {
        let payload = serde_json::json!({
            "model": self.model,
            "messages": Self::build_messages(history),
            "tools": crate::aci::schemas::get_all_tool_definitions(),
            "tool_choice": "auto",
            "temperature": 0.0,
            "max_tokens": self.max_tokens,
        });
        let url = format!("{}/chat/completions", self.api_url);
        let client = self.client.clone();
        let key = self.api_key.clone();
        let timeout = self.timeout;

        let val: serde_json::Value = block_on(async move {
            let mut req = client.post(&url).json(&payload).timeout(timeout);
            if let Some(k) = key {
                req = req.bearer_auth(k);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("{} returned {}: {}", url, status, truncate(&body, 400));
            }
            Ok::<_, anyhow::Error>(serde_json::from_str(&body)?)
        })?;

        if let Some(err) = val.get("error") {
            anyhow::bail!("provider error: {}", truncate(&err.to_string(), 400));
        }
        self.usage.add(
            val["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
            val["usage"]["completion_tokens"].as_u64().unwrap_or(0),
        );
        let msg = &val["choices"][0]["message"];
        if let Some(tc) = msg["tool_calls"].as_array().and_then(|a| a.first()) {
            let name = tc["function"]["name"].as_str().unwrap_or("unknown").to_string();
            let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
            let arguments = serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));
            return Ok(AgentStepAction::CallTool { name, arguments });
        }
        let content = msg["content"].as_str().unwrap_or("");
        let reasoning = msg["reasoning_content"].as_str().unwrap_or("");
        if let Some(tc) = parse_tool_call(content).or_else(|| parse_tool_call(reasoning)) {
            return Ok(AgentStepAction::CallTool {
                name: tc.name,
                arguments: tc.arguments,
            });
        }
        let text = if !content.trim().is_empty() { content } else { reasoning };
        if text.trim().is_empty() {
            anyhow::bail!("empty response from model (no content and no tool call)");
        }
        Ok(AgentStepAction::Finish {
            summary: text.to_string(),
        })
    }

    fn usage(&self) -> TokenUsage {
        self.usage.get()
    }
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

pub struct AnthropicDriver {
    pub client: reqwest::Client,
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
    pub timeout: Duration,
    /// Raw `content` arrays of the assistant turns this driver produced, in
    /// order. Replayed unchanged so thinking blocks survive between turns.
    raw_turns: Mutex<Vec<serde_json::Value>>,
    usage: UsageCounter,
}

impl AnthropicDriver {
    pub const API_URL: &'static str = "https://api.anthropic.com/v1/messages";
    pub const API_VERSION: &'static str = "2026-10-21";

    pub fn new(api_key: &str, model: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            max_tokens: 16000,
            timeout: Duration::from_secs(600),
            raw_turns: Mutex::new(Vec::new()),
            usage: UsageCounter::default(),
        }
    }

    fn tools() -> Vec<serde_json::Value> {
        crate::aci::schemas::get_all_tool_definitions()
            .into_iter()
            .filter_map(|t| {
                let f = t.get("function")?;
                Some(serde_json::json!({
                    "name": f.get("name")?,
                    "description": f.get("description").cloned().unwrap_or_default(),
                    "input_schema": f.get("parameters").cloned()
                        .unwrap_or(serde_json::json!({"type": "object", "properties": {}})),
                }))
            })
            .collect()
    }
}

impl LlmDriver for AnthropicDriver {
    fn step(&self, history: &[AgentMessage]) -> anyhow::Result<AgentStepAction> {
        let mut raw = self.raw_turns.lock().unwrap();
        // A fresh conversation (system + first user message) starts over.
        if history.len() <= 2 {
            raw.clear();
        }

        let mut system = String::new();
        let mut messages: Vec<serde_json::Value> = Vec::new();
        let mut assistant_idx = 0usize;
        let mut pending_tool_id: Option<String> = None;

        for m in fold_advisories(history) {
            match m.role {
                AgentRole::System => {
                    if !system.is_empty() {
                        system.push_str("\n\n");
                    }
                    system.push_str(&m.content);
                }
                AgentRole::User => messages.push(serde_json::json!({
                    "role": "user",
                    "content": [{ "type": "text", "text": m.content }]
                })),
                AgentRole::Assistant => {
                    let replay = raw.get(assistant_idx).cloned();
                    assistant_idx += 1;
                    let content = match replay {
                        Some(c) => c,
                        None => match parse_tool_call(&m.content) {
                            Some(tc) => serde_json::json!([{
                                "type": "tool_use",
                                "id": format!("toolu_ethos_{}", assistant_idx),
                                "name": tc.name,
                                "input": tc.arguments,
                            }]),
                            None => serde_json::json!([{ "type": "text", "text": m.content }]),
                        },
                    };
                    pending_tool_id = content.as_array().and_then(|blocks| {
                        blocks
                            .iter()
                            .find(|b| b["type"] == "tool_use")
                            .and_then(|b| b["id"].as_str().map(|s| s.to_string()))
                    });
                    messages.push(serde_json::json!({ "role": "assistant", "content": content }));
                }
                AgentRole::Tool => match pending_tool_id.take() {
                    Some(id) => messages.push(serde_json::json!({
                        "role": "user",
                        "content": [{ "type": "tool_result", "tool_use_id": id, "content": m.content }]
                    })),
                    None => messages.push(serde_json::json!({
                        "role": "user",
                        "content": [{ "type": "text", "text": m.content }]
                    })),
                },
            }
        }

        // `temperature` is omitted: current Claude models reject non-default
        // sampling parameters. Parallel tool use is disabled because the
        // agent loop executes one tool per step.
        let payload = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            "tools": Self::tools(),
            "tool_choice": { "type": "auto", "disable_parallel_tool_use": true },
        });

        let client = self.client.clone();
        let key = self.api_key.clone();
        let timeout = self.timeout;
        let val: serde_json::Value = block_on(async move {
            let resp = client
                .post(Self::API_URL)
                .header("x-api-key", key)
                .header("anthropic-version", Self::API_VERSION)
                .json(&payload)
                .timeout(timeout)
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("Anthropic API returned {}: {}", status, truncate(&body, 400));
            }
            Ok::<_, anyhow::Error>(serde_json::from_str(&body)?)
        })?;

        let u = &val["usage"];
        self.usage.add(
            u["input_tokens"].as_u64().unwrap_or(0)
                + u["cache_read_input_tokens"].as_u64().unwrap_or(0)
                + u["cache_creation_input_tokens"].as_u64().unwrap_or(0),
            u["output_tokens"].as_u64().unwrap_or(0),
        );
        let blocks = val["content"].as_array().cloned().unwrap_or_default();
        raw.push(serde_json::Value::Array(blocks.clone()));

        if val["stop_reason"] == "refusal" {
            return Ok(AgentStepAction::Finish {
                summary: format!(
                    "[model refusal{}]",
                    val["stop_details"]["category"]
                        .as_str()
                        .map(|c| format!(": {}", c))
                        .unwrap_or_default()
                ),
            });
        }
        if let Some(b) = blocks.iter().find(|b| b["type"] == "tool_use") {
            return Ok(AgentStepAction::CallTool {
                name: b["name"].as_str().unwrap_or("unknown").to_string(),
                arguments: b["input"].clone(),
            });
        }
        let text: Vec<&str> = blocks
            .iter()
            .filter(|b| b["type"] == "text")
            .filter_map(|b| b["text"].as_str())
            .collect();
        let text = text.join("\n");
        if text.trim().is_empty() {
            anyhow::bail!("empty response from model (stop_reason {})", val["stop_reason"]);
        }
        Ok(AgentStepAction::Finish { summary: text })
    }

    fn usage(&self) -> TokenUsage {
        self.usage.get()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Builds a driver from a provider name and connection settings, as stored
/// in the user config. `anthropic` uses the Messages API; every other
/// provider is treated as OpenAI-compatible.
pub fn driver_for(
    provider: &str,
    api_url: &str,
    api_key: Option<String>,
    model: &str,
) -> anyhow::Result<Box<dyn LlmDriver>> {
    if provider == "anthropic" || api_url.contains("api.anthropic.com") {
        let key = api_key
            .filter(|k| !k.trim().is_empty())
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .ok_or_else(|| anyhow::anyhow!("no Anthropic API key (set ANTHROPIC_API_KEY or run /setup)"))?;
        return Ok(Box::new(AnthropicDriver::new(&key, model)));
    }
    Ok(Box::new(OpenAiCompatDriver::new(api_url, model, api_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: AgentRole, content: &str, tool: Option<&str>) -> AgentMessage {
        AgentMessage {
            role,
            content: content.to_string(),
            tool_name: tool.map(|s| s.to_string()),
        }
    }

    #[test]
    fn advisories_fold_into_single_tool_result() {
        let h = vec![
            msg(AgentRole::System, "sys", None),
            msg(AgentRole::User, "task", None),
            msg(AgentRole::Assistant, "<tool_call>{\"name\":\"read\",\"arguments\":{}}</tool_call>", None),
            msg(AgentRole::Tool, "[PromptInjectScanner] 1 pattern", Some("promptinject_scanner")),
            msg(AgentRole::Tool, "{\"status\":\"SUCCESS\"}", Some("read")),
        ];
        let f = fold_advisories(&h);
        let tools: Vec<_> = f.iter().filter(|m| m.role == AgentRole::Tool).collect();
        assert_eq!(tools.len(), 1);
        assert!(tools[0].content.contains("PromptInjectScanner"));
        assert!(tools[0].content.contains("SUCCESS"));
    }

    #[test]
    fn openai_messages_answer_each_call_once() {
        let h = vec![
            msg(AgentRole::System, "sys", None),
            msg(AgentRole::User, "task", None),
            msg(AgentRole::Assistant, "<tool_call>{\"name\":\"read\",\"arguments\":{}}</tool_call>", None),
            msg(AgentRole::Tool, "[SemanticGuard] risk", Some("semantic_guard")),
            msg(AgentRole::Tool, "result", Some("read")),
        ];
        let m = OpenAiCompatDriver::build_messages(&h);
        let tool_msgs = m.iter().filter(|x| x["role"] == "tool").count();
        assert_eq!(tool_msgs, 1);
    }
}
