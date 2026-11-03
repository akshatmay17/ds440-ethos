use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A repository .env must not select an unconfined execution backend.
    ethos::runtime::ExecutionSettings::configured()?;
    // Project files may supply application credentials/settings, never process
    // launch paths, Docker client configuration or execution authorization.
    if let Ok(entries)=dotenvy::dotenv_iter() {
        for (key,value) in entries.flatten() {
            if ["OPENAI_API_KEY","ANTHROPIC_API_KEY","OPENROUTER_API_KEY","SPIDER_API_KEY",
                "OLLAMA_HOST","DATABASE_URL","ETHOS_SEMANTIC_NEURAL","ETHOS_SEMANTIC_MODEL_DIR",
                "ETHOS_SEMANTIC_MODEL","HF_TOKEN","ETHOS_DECLASSIFY_TOKEN"].contains(&key.as_str())
                && std::env::var_os(&key).is_none() { std::env::set_var(key,value); }
        }
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    ethos::cli::run_cli().await
}
