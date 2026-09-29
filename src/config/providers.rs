use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiderCloudConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub endpoint: String,
    pub concurrency: usize,
    pub proxy_mode: bool,
    pub status: String,
}

impl Default for SpiderCloudConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("SPIDER_API_KEY").is_ok(),
            api_key: std::env::var("SPIDER_API_KEY").ok(),
            endpoint: std::env::var("SPIDER_ENDPOINT")
                .unwrap_or_else(|_| "https://api.spider.cloud".to_string()),
            concurrency: 5,
            proxy_mode: true,
            status: "ready".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BunkerConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub status: String,
}

impl Default for BunkerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: std::env::var("OLLAMA_HOST")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),
            model: std::env::var("BUNKER_MODEL")
                .unwrap_or_else(|_| "qwen2.5-coder:latest".to_string()),
            status: "connected".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierLlmConfig {
    pub provider: String,
    pub api_key: Option<String>,
    pub model: String,
    pub status: String,
}

impl Default for FrontierLlmConfig {
    fn default() -> Self {
        let has_key = std::env::var("OPENAI_API_KEY").is_ok();
        Self {
            provider: "openai".to_string(),
            api_key: std::env::var("OPENAI_API_KEY").ok(),
            model: "gpt-4o".to_string(),
            status: if has_key { "configured" } else { "pending_key" }.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    pub status: String,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://postgres:postgres@localhost:5432/ethos".to_string()
            }),
            max_connections: 5,
            status: "configured".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderRegistry {
    pub spider: SpiderCloudConfig,
    pub bunker: BunkerConfig,
    pub frontier: FrontierLlmConfig,
    pub postgres: PostgresConfig,
}

#[derive(Debug, Clone)]
pub struct ProviderManager {
    inner: Arc<RwLock<ProviderRegistry>>,
}

impl Default for ProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ProviderRegistry::default())),
        }
    }

    pub fn get_registry(&self) -> ProviderRegistry {
        self.inner.read().unwrap().clone()
    }

    pub fn update_spider(
        &mut self,
        api_key: Option<String>,
        endpoint: Option<String>,
        concurrency: Option<usize>,
    ) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(key) = api_key {
                lock.spider.api_key = Some(key);
                lock.spider.enabled = true;
                lock.spider.status = "configured".to_string();
            }
            if let Some(ep) = endpoint {
                lock.spider.endpoint = ep;
            }
            if let Some(c) = concurrency {
                lock.spider.concurrency = c;
            }
        }
    }

    pub fn update_bunker(&mut self, endpoint: Option<String>, model: Option<String>) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(ep) = endpoint {
                lock.bunker.endpoint = ep;
            }
            if let Some(m) = model {
                lock.bunker.model = m;
            }
        }
    }

    pub fn update_frontier(
        &mut self,
        provider: Option<String>,
        api_key: Option<String>,
        model: Option<String>,
    ) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(p) = provider {
                lock.frontier.provider = p;
            }
            if let Some(key) = api_key {
                lock.frontier.api_key = Some(key);
                lock.frontier.status = "configured".to_string();
            }
            if let Some(m) = model {
                lock.frontier.model = m;
            }
        }
    }
}
