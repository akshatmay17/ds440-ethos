use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

pub const CACHE_TTL_SECONDS: u64 = 7 * 24 * 3600; // 7 days (weekly TTL)
pub const MODELS_DEV_URL: &str = "https://models.dev/api.json";
pub const SNAPSHOT_BYTES: &str = include_str!("../../data/models_dev_snapshot.json");

pub const POPULAR_PROVIDER_IDS: &[&str] = &[
    "ollama",
    "openai",
    "anthropic",
    "google",
    "deepseek",
    "openrouter",
    "groq",
    "mistral",
    "togetherai",
    "cohere",
    "custom",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCost {
    #[serde(default)]
    pub input: f64,
    #[serde(default)]
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub context_window: usize,
    pub max_output_tokens: usize,
    pub tool_format: String, // "xml", "native_json"
    pub cost_input_per_million: f64,
    pub cost_output_per_million: f64,
    pub cost_cache_read_per_million: f64,
    pub has_tools: bool,
    pub has_reasoning: bool,
    pub has_vision: bool,
    pub is_open_weights: bool,
    #[serde(default)]
    pub description: Option<String>,
}

impl ModelSpec {
    pub fn new(
        id: &str,
        name: &str,
        provider: &str,
        context_window: usize,
        max_output_tokens: usize,
        tool_format: &str,
        cost_in: f64,
        cost_out: f64,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            provider: provider.to_string(),
            context_window,
            max_output_tokens,
            tool_format: tool_format.to_string(),
            cost_input_per_million: cost_in,
            cost_output_per_million: cost_out,
            cost_cache_read_per_million: 0.0,
            has_tools: tool_format == "native_json",
            has_reasoning: id.contains("r1") || id.contains("o1") || id.contains("o3") || id.contains("reasoner"),
            has_vision: id.contains("4o") || id.contains("gemini") || id.contains("sonnet") || id.contains("vision"),
            is_open_weights: provider == "ollama" || id.contains("llama") || id.contains("qwen") || id.contains("deepseek") || id.contains("gemma"),
            description: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
    pub default_api: String,
    pub env_vars: Vec<String>,
    pub doc_url: Option<String>,
    pub model_count: usize,
    pub is_popular: bool,
}

pub struct ModelCatalogData {
    pub providers: Vec<ProviderSummary>,
    pub models_by_provider: HashMap<String, Vec<ModelSpec>>,
    pub all_models: Vec<ModelSpec>,
    pub last_updated_epoch: u64,
}

impl ModelCatalogData {
    pub fn from_json_str(json_str: &str, last_updated: u64) -> Self {
        let mut providers = Vec::new();
        let mut models_by_provider: HashMap<String, Vec<ModelSpec>> = HashMap::new();
        let mut all_models = Vec::new();

        // 1. Always include local Ollama as a first-class local bunker provider
        let ollama_models = vec![
            ModelSpec::new("qwen2.5-coder:7b", "Qwen 2.5 Coder 7B", "ollama", 32_768, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("qwen2.5-coder:14b", "Qwen 2.5 Coder 14B", "ollama", 32_768, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("qwen2.5-coder:32b", "Qwen 2.5 Coder 32B", "ollama", 32_768, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("deepseek-r1:8b", "DeepSeek R1 Distill 8B", "ollama", 65_536, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("deepseek-r1:14b", "DeepSeek R1 Distill 14B", "ollama", 65_536, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("llama3.3:70b", "Llama 3.3 70B Instruct", "ollama", 131_072, 8_192, "xml", 0.0, 0.0),
            ModelSpec::new("codellama:13b", "CodeLlama 13B", "ollama", 16_384, 4_096, "xml", 0.0, 0.0),
        ];
        all_models.extend(ollama_models.clone());
        models_by_provider.insert("ollama".to_string(), ollama_models);

        providers.push(ProviderSummary {
            id: "ollama".to_string(),
            name: "Ollama (Local Bunker)".to_string(),
            default_api: "http://localhost:11434/v1".to_string(),
            env_vars: vec!["OLLAMA_HOST".to_string()],
            doc_url: Some("https://ollama.com".to_string()),
            model_count: 7,
            is_popular: true,
        });

        // 2. Always include Custom VPS / self-hosted as a provider
        let custom_models = vec![
            ModelSpec::new("custom-model", "Custom OpenAI-Compatible Model", "custom", 65_536, 8_192, "native_json", 0.0, 0.0),
        ];
        all_models.extend(custom_models.clone());
        models_by_provider.insert("custom".to_string(), custom_models);
        providers.push(ProviderSummary {
            id: "custom".to_string(),
            name: "Custom (Self-Hosted VLLM/SGLang)".to_string(),
            default_api: "http://localhost:8080/v1".to_string(),
            env_vars: vec!["CUSTOM_API_KEY".to_string()],
            doc_url: None,
            model_count: 1,
            is_popular: true,
        });

        // 3. Parse models.dev raw JSON map
        if let Ok(raw_map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(json_str) {
            for (p_id, p_val) in raw_map {
                let p_name = p_val.get("name").and_then(|v| v.as_str()).unwrap_or(&p_id).to_string();
                let p_api = p_val.get("api").and_then(|v| v.as_str()).map(|s| s.to_string());
                let p_doc = p_val.get("doc").and_then(|v| v.as_str()).map(|s| s.to_string());
                let p_env = p_val.get("env")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();

                let default_api = p_api.unwrap_or_else(|| {
                    match p_id.as_str() {
                        "openai" => "https://api.openai.com/v1".to_string(),
                        "anthropic" => "https://api.anthropic.com/v1".to_string(),
                        "google" => "https://generativelanguage.googleapis.com/v1beta/openai".to_string(),
                        "deepseek" => "https://api.deepseek.com/v1".to_string(),
                        "openrouter" => "https://openrouter.ai/api/v1".to_string(),
                        "groq" => "https://api.groq.com/openai/v1".to_string(),
                        "mistral" => "https://api.mistral.ai/v1".to_string(),
                        "togetherai" => "https://api.together.xyz/v1".to_string(),
                        "cohere" => "https://api.cohere.com/v1".to_string(),
                        _ => format!("https://api.{}.com/v1", p_id),
                    }
                });

                let mut p_models = Vec::new();
                if let Some(raw_models) = p_val.get("models").and_then(|m| m.as_object()) {
                    for (m_key, m_val) in raw_models {
                        let id = m_val.get("id").and_then(|v| v.as_str()).unwrap_or(m_key).to_string();
                        let name = m_val.get("name").and_then(|v| v.as_str()).unwrap_or(&id).to_string();
                        let desc = m_val.get("description").and_then(|v| v.as_str()).map(|s| s.to_string());
                        
                        let context_window = m_val.get("limit")
                            .and_then(|l| l.get("context"))
                            .and_then(|c| c.as_u64())
                            .unwrap_or(32_768) as usize;
                        let max_output_tokens = m_val.get("limit")
                            .and_then(|l| l.get("output"))
                            .and_then(|c| c.as_u64())
                            .unwrap_or(4_096) as usize;
                        
                        let cost_in = m_val.get("cost")
                            .and_then(|c| c.get("input"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let cost_out = m_val.get("cost")
                            .and_then(|c| c.get("output"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let cost_cache = m_val.get("cost")
                            .and_then(|c| c.get("cache_read"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);

                        let tool_call = m_val.get("tool_call").and_then(|v| v.as_bool()).unwrap_or(false);
                        let reasoning = m_val.get("reasoning").and_then(|v| v.as_bool()).unwrap_or(false);
                        let open_weights = m_val.get("open_weights").and_then(|v| v.as_bool()).unwrap_or(false);

                        let has_vision = m_val.get("modalities")
                            .and_then(|m| m.get("input"))
                            .and_then(|inp| inp.as_array())
                            .map(|arr| arr.iter().any(|v| v.as_str() == Some("image")))
                            .unwrap_or(false);

                        let tool_format = if tool_call { "native_json".to_string() } else { "xml".to_string() };

                        let spec = ModelSpec {
                            id,
                            name,
                            provider: p_id.clone(),
                            context_window,
                            max_output_tokens,
                            tool_format,
                            cost_input_per_million: cost_in,
                            cost_output_per_million: cost_out,
                            cost_cache_read_per_million: cost_cache,
                            has_tools: tool_call,
                            has_reasoning: reasoning,
                            has_vision,
                            is_open_weights: open_weights,
                            description: desc,
                        };

                        p_models.push(spec.clone());
                        all_models.push(spec);
                    }
                }

                // Sort models so largest context windows are up front
                p_models.sort_by(|a, b| b.context_window.cmp(&a.context_window));

                let is_pop = POPULAR_PROVIDER_IDS.contains(&p_id.as_str());

                providers.push(ProviderSummary {
                    id: p_id.clone(),
                    name: p_name,
                    default_api,
                    env_vars: p_env,
                    doc_url: p_doc,
                    model_count: p_models.len(),
                    is_popular: is_pop,
                });

                models_by_provider.insert(p_id, p_models);
            }
        }

        // Sort providers: popular first, then alphabetical by name
        providers.sort_by(|a, b| {
            match (a.is_popular, b.is_popular) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });

        Self {
            providers,
            models_by_provider,
            all_models,
            last_updated_epoch: last_updated,
        }
    }
}

static CATALOG_DATA: OnceLock<RwLock<ModelCatalogData>> = OnceLock::new();

/// Dynamic Model Catalog powered by models.dev standards with weekly caching
pub struct ModelCatalog;

impl ModelCatalog {
    pub fn cache_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let ethos_path = PathBuf::from(&home).join(".ethos").join("models_dev_cache.json");
        if ethos_path.exists() {
            return ethos_path;
        }
        let legacy_path = PathBuf::from(&home).join(".taintbox").join("models_dev_cache.json");
        if legacy_path.exists() {
            return legacy_path;
        }
        ethos_path
    }

    fn init_catalog() -> RwLock<ModelCatalogData> {
        let cache_file = Self::cache_path();
        let mut content = None;
        let mut last_updated = 0;

        if cache_file.exists() {
            if let Ok(metadata) = fs::metadata(&cache_file) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(epoch) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                        last_updated = epoch.as_secs();
                    }
                }
            }
            if let Ok(c) = fs::read_to_string(&cache_file) {
                if !c.trim().is_empty() {
                    content = Some(c);
                }
            }
        }

        if content.is_none() {
            if let Ok(c) = fs::read_to_string("data/models_dev_snapshot.json") {
                if !c.trim().is_empty() {
                    content = Some(c);
                }
            }
        }

        let json_str = content.unwrap_or_else(|| SNAPSHOT_BYTES.to_string());
        let data = ModelCatalogData::from_json_str(&json_str, last_updated);
        RwLock::new(data)
    }

    pub fn get_data() -> &'static RwLock<ModelCatalogData> {
        CATALOG_DATA.get_or_init(Self::init_catalog)
    }

    /// List all providers from models.dev (200+ providers), optionally filtered by query
    pub fn list_providers(search: Option<&str>) -> Vec<ProviderSummary> {
        let lock = Self::get_data().read().unwrap();
        match search {
            Some(q) if !q.trim().is_empty() => {
                let q_lower = q.trim().to_lowercase();
                lock.providers
                    .iter()
                    .filter(|p| p.id.to_lowercase().contains(&q_lower) || p.name.to_lowercase().contains(&q_lower))
                    .cloned()
                    .collect()
            }
            _ => lock.providers.clone(),
        }
    }

    /// Returns all models for a given provider from models.dev
    pub fn get_models_for_provider(provider: &str) -> Vec<ModelSpec> {
        let lock = Self::get_data().read().unwrap();
        let prov_lower = provider.to_lowercase();

        if let Some(models) = lock.models_by_provider.get(&prov_lower) {
            return models.clone();
        }

        // Fuzzy match (e.g. "gemini" -> "google", "llama" -> "ollama")
        if prov_lower == "gemini" {
            if let Some(models) = lock.models_by_provider.get("google") {
                return models.clone();
            }
        }

        for (p_id, models) in &lock.models_by_provider {
            if p_id.contains(&prov_lower) || prov_lower.contains(p_id) {
                return models.clone();
            }
        }

        vec![ModelSpec::new(
            "default",
            "Default Model",
            provider,
            32_768,
            4_096,
            "xml",
            0.0,
            0.0,
        )]
    }

    /// Lookup a specific model specification by ID across all 7,600+ models
    pub fn find_model(model_id: &str) -> Option<ModelSpec> {
        let lock = Self::get_data().read().unwrap();
        let id_lower = model_id.to_lowercase();
        // 1. Exact match first
        if let Some(m) = lock.all_models.iter().find(|m| m.id.to_lowercase() == id_lower) {
            return Some(m.clone());
        }
        // 2. Partial match fallback
        lock.all_models
            .iter()
            .find(|m| m.id.to_lowercase().contains(&id_lower) || id_lower.contains(&m.id.to_lowercase()))
            .cloned()
    }

    /// Get canonical API endpoint URL for a provider
    pub fn get_default_endpoint(provider: &str) -> String {
        let lock = Self::get_data().read().unwrap();
        let prov_lower = provider.to_lowercase();
        if let Some(p) = lock.providers.iter().find(|p| p.id == prov_lower) {
            return p.default_api.clone();
        }
        match prov_lower.as_str() {
            "openai" => "https://api.openai.com/v1".to_string(),
            "anthropic" => "https://api.anthropic.com/v1".to_string(),
            "google" | "gemini" => "https://generativelanguage.googleapis.com/v1beta/openai".to_string(),
            "ollama" => "http://localhost:11434/v1".to_string(),
            "deepseek" => "https://api.deepseek.com/v1".to_string(),
            "openrouter" => "https://openrouter.ai/api/v1".to_string(),
            "groq" => "https://api.groq.com/openai/v1".to_string(),
            "mistral" => "https://api.mistral.ai/v1".to_string(),
            "togetherai" => "https://api.together.xyz/v1".to_string(),
            "cohere" => "https://api.cohere.com/v1".to_string(),
            _ => format!("https://api.{}.com/v1", prov_lower),
        }
    }

    /// Get expected environment variable names for provider credentials
    pub fn get_env_vars_for_provider(provider: &str) -> Vec<String> {
        let lock = Self::get_data().read().unwrap();
        let prov_lower = provider.to_lowercase();
        if let Some(p) = lock.providers.iter().find(|p| p.id == prov_lower) {
            return p.env_vars.clone();
        }
        vec![format!("{}_API_KEY", prov_lower.to_uppercase())]
    }

    /// Complete models.dev catalog covering all 7,600+ models
    pub fn get_full_catalog() -> Vec<ModelSpec> {
        let lock = Self::get_data().read().unwrap();
        lock.all_models.clone()
    }

    /// Refresh catalog from https://models.dev/api.json and update cache
    pub async fn refresh_cache() -> anyhow::Result<usize> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        let resp = client
            .get(MODELS_DEV_URL)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ethos/0.1.0")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Failed to fetch models.dev API: HTTP status {}", resp.status());
        }

        let body = resp.text().await?;
        let cache_file = Self::cache_path();
        if let Some(parent) = cache_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&cache_file, &body);

        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_data = ModelCatalogData::from_json_str(&body, now_epoch);
        let provider_count = new_data.providers.len();

        let lock = Self::get_data();
        if let Ok(mut write_guard) = lock.write() {
            *write_guard = new_data;
        }

        Ok(provider_count)
    }

    /// Check if cache is older than 7 days; if so, trigger background update
    pub fn trigger_background_update_if_needed() {
        let cache_file = Self::cache_path();
        let mut needs_refresh = true;

        if cache_file.exists() {
            if let Ok(meta) = fs::metadata(&cache_file) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                        if elapsed.as_secs() < CACHE_TTL_SECONDS {
                            needs_refresh = false;
                        }
                    }
                }
            }
        }

        if needs_refresh {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async {
                    let _ = Self::refresh_cache().await;
                });
            }
        }
    }
}
