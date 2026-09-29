use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use ethos::api::routes::{create_router, AppState};
use ethos::store::SessionManager;

#[tokio::test]
async fn test_health_endpoint() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_create_and_delete_sandbox() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state.clone());

    // 1. Create sandbox
    let create_req = Request::builder()
        .method("POST")
        .uri("/v1/sandboxes")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"description": "integration-test"}"#))
        .unwrap();

    let res = app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sandbox_id = body["sandbox_id"].as_str().unwrap();
    assert!(sandbox_id.starts_with("sbx_"));

    // 2. Delete sandbox
    let del_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/sandboxes/{}", sandbox_id))
        .body(Body::empty())
        .unwrap();

    let del_res = app.oneshot(del_req).await.unwrap();
    assert_eq!(del_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_api_tool_write_and_read() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state.clone());

    // Create session
    let sid = state
        .session_manager
        .create_session("write-test")
        .await
        .unwrap();

    // Write tool
    let write_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sandboxes/{}/tools/write", sid))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"path": "test.txt", "content": "hello rust"}"#,
        ))
        .unwrap();

    let write_res = app.clone().oneshot(write_req).await.unwrap();
    assert_eq!(write_res.status(), StatusCode::OK);

    // Read tool
    let read_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sandboxes/{}/tools/read", sid))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"path": "test.txt"}"#))
        .unwrap();

    let read_res = app.oneshot(read_req).await.unwrap();
    assert_eq!(read_res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(read_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["output"], "hello rust");
    assert_eq!(body["status"], "SUCCESS");
}

#[tokio::test]
async fn test_models_dev_api_endpoints() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state.clone());

    // 1. Test GET /v1/models/providers
    let req = Request::builder()
        .uri("/v1/models/providers")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let providers: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(
        providers.len() >= 200,
        "Should contain 200+ providers from models.dev, got {}",
        providers.len()
    );

    // Verify Google and Ollama exist in provider list
    assert!(providers
        .iter()
        .any(|p| p["id"] == "google" || p["id"] == "ollama"));

    // 2. Test GET /v1/models?provider=google
    let req2 = Request::builder()
        .uri("/v1/models?provider=google")
        .body(Body::empty())
        .unwrap();

    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);
    let bytes2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
        .await
        .unwrap();
    let google_models: Vec<serde_json::Value> = serde_json::from_slice(&bytes2).unwrap();
    assert!(
        !google_models.is_empty(),
        "Google models should not be empty"
    );
    assert!(google_models
        .iter()
        .any(|m| m["id"].as_str().unwrap_or("").contains("gemini")));

    // 3. Test GET /api/providers with search query
    let req3 = Request::builder()
        .uri("/api/providers?search=groq")
        .body(Body::empty())
        .unwrap();

    let res3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(res3.status(), StatusCode::OK);
    let bytes3 = axum::body::to_bytes(res3.into_body(), usize::MAX)
        .await
        .unwrap();
    let groq_providers: Vec<serde_json::Value> = serde_json::from_slice(&bytes3).unwrap();
    assert!(!groq_providers.is_empty(), "Should find Groq provider");
    assert_eq!(groq_providers[0]["id"], "groq");
}
