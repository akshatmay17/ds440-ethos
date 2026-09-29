use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub provider: String,
    pub api_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub policy_profile: String,
    pub temperature: f64,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            provider: "ollama".to_string(),
            api_url: "http://localhost:11434/v1".to_string(),
            api_key: None,
            model: "qwen2.5-coder".to_string(),
            policy_profile: "Standard".to_string(),
            temperature: 0.0,
        }
    }
}

impl UserConfig {
    pub fn config_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let ethos_path = PathBuf::from(&home).join(".ethos").join("config.json");
        if ethos_path.exists() {
            return ethos_path;
        }
        let legacy_path = PathBuf::from(&home).join(".taintbox").join("config.json");
        if legacy_path.exists() {
            return legacy_path;
        }
        ethos_path
    }

    /// Checks if any supported LLM provider API key exists in the current environment or .env
    pub fn has_env_api_key() -> bool {
        let _ = dotenvy::dotenv();
        [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "OPENROUTER_API_KEY",
            "GROQ_API_KEY",
            "DEEPSEEK_API_KEY",
            "MISTRAL_API_KEY",
            "COHERE_API_KEY",
            "TOGETHER_API_KEY",
            "ETHOS_API_KEY",
            "TBOX_API_KEY",
        ]
        .iter()
        .any(|v| std::env::var(v).map(|k| !k.trim().is_empty()).unwrap_or(false))
    }

    /// Checks if an explicit user configuration file exists at ~/.ethos/config.json
    pub fn is_explicitly_configured() -> bool {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(&home).join(".ethos").join("config.json").exists()
    }

    pub fn load() -> Option<Self> {
        let _ = dotenvy::dotenv();
        let path = Self::config_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<UserConfig>(&content) {
                    return Some(cfg);
                }
            }
        }

        // Fallback: check environment variables (loaded from process or .env)
        if let Ok(key) = std::env::var("OPENROUTER_API_KEY") {
            return Some(Self {
                provider: "openrouter".to_string(),
                api_url: std::env::var("OPENROUTER_BASE_URL")
                    .unwrap_or_else(|_| "https://openrouter.ai/api/v1".to_string()),
                api_key: Some(key),
                model: std::env::var("OPENROUTER_MODEL")
                    .unwrap_or_else(|_| "anthropic/claude-3.5-sonnet".to_string()),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            return Some(Self {
                provider: "openai".to_string(),
                api_url: std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
                api_key: Some(key),
                model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string()),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            return Some(Self {
                provider: "anthropic".to_string(),
                api_url: "https://api.anthropic.com/v1".to_string(),
                api_key: Some(key),
                model: "claude-3-5-sonnet-20241022".to_string(),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }
        if let Ok(key) =
            std::env::var("GEMINI_API_KEY").or_else(|_| std::env::var("GOOGLE_API_KEY"))
        {
            return Some(Self {
                provider: "google".to_string(),
                api_url: std::env::var("GEMINI_BASE_URL").unwrap_or_else(|_| {
                    "https://generativelanguage.googleapis.com/v1beta/openai".to_string()
                }),
                api_key: Some(key),
                model: std::env::var("GEMINI_MODEL")
                    .unwrap_or_else(|_| "gemini-2.5-flash".to_string()),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }
        if let Ok(key) = std::env::var("GROQ_API_KEY") {
            return Some(Self {
                provider: "groq".to_string(),
                api_url: "https://api.groq.com/openai/v1".to_string(),
                api_key: Some(key),
                model: "llama-3.3-70b-versatile".to_string(),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }
        if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
            return Some(Self {
                provider: "deepseek".to_string(),
                api_url: "https://api.deepseek.com/v1".to_string(),
                api_key: Some(key),
                model: "deepseek-chat".to_string(),
                policy_profile: "Standard".to_string(),
                temperature: 0.0,
            });
        }

        None
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }
}

/// Interactive onboarding and configuration wizard for ethos
pub fn run_setup_wizard() -> anyhow::Result<UserConfig> {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                   ETHOS HARNESS: AGENT SETUP WIZARD                  ║");
    println!("║       Configure LLM provider, API credentials, and boundary policy   ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    println!("Select your LLM Inference Provider:");
    println!("  [1] Ollama / Local Bunker (default: http://localhost:11434/v1)");
    println!("  [2] OpenAI (https://api.openai.com/v1)");
    println!("  [3] OpenRouter (https://openrouter.ai/api/v1)");
    println!("  [4] DeepSeek (https://api.deepseek.com/v1)");
    println!("  [5] Anthropic Claude (https://api.anthropic.com/v1)");
    println!("  [6] Custom Self-Hosted / VPS Endpoint");
    print!("\nEnter choice [1-6] (default: 1): ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let (provider, default_url, needs_key) = match choice {
        "2" => ("openai", "https://api.openai.com/v1", true),
        "3" => ("openrouter", "https://openrouter.ai/api/v1", true),
        "4" => ("deepseek", "https://api.deepseek.com/v1", true),
        "5" => ("anthropic", "https://api.anthropic.com/v1", true),
        "6" => ("custom", "http://localhost:8080/v1", false),
        _ => ("ollama", "http://localhost:11434/v1", false),
    };

    // API URL
    print!("Endpoint URL [{}]: ", default_url);
    io::stdout().flush()?;
    let mut url_input = String::new();
    io::stdin().read_line(&mut url_input)?;
    let url_input = url_input.trim();
    let api_url = if url_input.is_empty() {
        default_url.to_string()
    } else {
        url_input.to_string()
    };

    // API Key
    let api_key = if needs_key {
        print!("API Key: ");
        io::stdout().flush()?;
        let mut key_input = String::new();
        io::stdin().read_line(&mut key_input)?;
        let key_input = key_input.trim();
        if key_input.is_empty() {
            None
        } else {
            Some(key_input.to_string())
        }
    } else {
        print!("API Key (optional for Ollama/local, press Enter to skip): ");
        io::stdout().flush()?;
        let mut key_input = String::new();
        io::stdin().read_line(&mut key_input)?;
        let key_input = key_input.trim();
        if key_input.is_empty() {
            None
        } else {
            Some(key_input.to_string())
        }
    };

    // Dynamic model picker from models.dev catalog
    let available_models =
        crate::config::models_dev::ModelCatalog::get_models_for_provider(provider);
    println!("\nSelect Model from models.dev Catalog for '{}':", provider);
    for (i, m) in available_models.iter().enumerate() {
        println!(
            "  [{}] {} ({}) [ctx: {}k]",
            i + 1,
            m.name,
            m.id,
            m.context_window / 1000
        );
    }
    println!("  [0] Custom / unlisted model name");
    print!("\nChoice [0-{}] (default: 1): ", available_models.len());
    io::stdout().flush()?;

    let mut model_choice = String::new();
    io::stdin().read_line(&mut model_choice)?;
    let model_choice = model_choice.trim();

    let model = if model_choice == "0" {
        print!("Enter custom model identifier: ");
        io::stdout().flush()?;
        let mut custom_model = String::new();
        io::stdin().read_line(&mut custom_model)?;
        let trimmed = custom_model.trim();
        if trimmed.is_empty() {
            available_models[0].id.clone()
        } else {
            trimmed.to_string()
        }
    } else if let Ok(idx) = model_choice.parse::<usize>() {
        if idx >= 1 && idx <= available_models.len() {
            available_models[idx - 1].id.clone()
        } else {
            available_models[0].id.clone()
        }
    } else {
        available_models[0].id.clone()
    };

    // Policy profile
    println!("\nSelect Boundary Policy Enforcement Profile:");
    println!(
        "  [1] Standard (Blocks unauthorized writes & unallowlisted egress on untrusted data)"
    );
    println!("  [2] Strict (Zero unconfined execution; blocks all untrusted write/exec turns)");
    print!("Choice [1-2] (default: 1): ");
    io::stdout().flush()?;
    let mut pol_input = String::new();
    io::stdin().read_line(&mut pol_input)?;
    let policy_profile = if pol_input.trim() == "2" {
        "Strict".to_string()
    } else {
        "Standard".to_string()
    };

    let config = UserConfig {
        provider: provider.to_string(),
        api_url,
        api_key,
        model,
        policy_profile,
        temperature: 0.0,
    };

    config.save()?;
    println!(
        "\n[+] Configuration saved to: {}",
        UserConfig::config_path().display()
    );
    println!(
        "[+] Provider: {} | Model: {}",
        config.provider, config.model
    );
    println!("[+] Policy Profile: {}\n", config.policy_profile);

    Ok(config)
}
