use ethos::config::providers::ProviderManager;

#[test]
fn test_provider_manager_defaults_and_updates() {
    let mut manager = ProviderManager::new();
    let reg = manager.get_registry();

    assert_eq!(reg.spider.endpoint, "https://api.spider.cloud");
    assert_eq!(reg.spider.concurrency, 5);
    assert_eq!(reg.bunker.model, "qwen2.5-coder:latest");

    // Update Spider Cloud config
    manager.update_spider(
        Some("test_spider_key_123".to_string()),
        Some("https://custom.spider.cloud".to_string()),
        Some(10),
    );

    let updated = manager.get_registry();
    assert_eq!(updated.spider.api_key.unwrap(), "test_spider_key_123");
    assert_eq!(updated.spider.endpoint, "https://custom.spider.cloud");
    assert_eq!(updated.spider.concurrency, 10);
    assert!(updated.spider.enabled);
    assert_eq!(updated.spider.status, "configured");

    // Update Ollama Bunker config
    manager.update_bunker(
        Some("http://bunker.internal:11434".to_string()),
        Some("deepseek-r1:7b".to_string()),
    );
    let bunker_updated = manager.get_registry();
    assert_eq!(
        bunker_updated.bunker.endpoint,
        "http://bunker.internal:11434"
    );
    assert_eq!(bunker_updated.bunker.model, "deepseek-r1:7b");

    // Update Frontier LLM config
    manager.update_frontier(
        Some("anthropic".to_string()),
        Some("ant_key_xyz".to_string()),
        Some("claude-3-5-sonnet".to_string()),
    );
    let frontier_updated = manager.get_registry();
    assert_eq!(frontier_updated.frontier.provider, "anthropic");
    assert_eq!(frontier_updated.frontier.api_key.unwrap(), "ant_key_xyz");
    assert_eq!(frontier_updated.frontier.model, "claude-3-5-sonnet");
}

#[test]
fn test_models_dev_catalog_lookup() {
    use ethos::config::models_dev::ModelCatalog;

    let ollama_models = ModelCatalog::get_models_for_provider("ollama");
    assert!(!ollama_models.is_empty());
    assert!(ollama_models.iter().any(|m| m.id.contains("qwen2.5-coder")));

    let openai_models = ModelCatalog::get_models_for_provider("openai");
    assert!(!openai_models.is_empty());
    assert!(openai_models.iter().any(|m| m.id == "gpt-4o"));

    let anthropic_models = ModelCatalog::get_models_for_provider("anthropic");
    assert!(!anthropic_models.is_empty());
    assert!(anthropic_models.iter().any(|m| m.id.contains("claude")));

    let google_models = ModelCatalog::get_models_for_provider("google");
    assert!(!google_models.is_empty());
    assert!(google_models.iter().any(|m| m.id.contains("gemini")));

    let found = ModelCatalog::find_model("gpt-4o");
    assert!(found.is_some());
    let spec = found.unwrap();
    assert_eq!(spec.context_window, 128_000);
    assert_eq!(spec.tool_format, "native_json");
}
