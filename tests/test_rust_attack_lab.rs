use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use ethos::api::routes::{create_router, AppState};
use ethos::store::SessionManager;

#[tokio::test]
async fn test_lab_scenarios_listing() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/v1/lab/scenarios")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let scenarios: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(!scenarios.is_empty());
    assert_eq!(scenarios[0]["id"], "m365_indirect_email_exfil");
}

#[tokio::test]
async fn test_lab_execute_m365_attack_interception() {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lab/execute")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"scenario_id": "m365_indirect_email_exfil"}"#))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["scenario_id"], "m365_indirect_email_exfil");
    assert_eq!(body["final_outcome"], "ATTACK_BLOCKED_BY_POLICY");
    assert_eq!(body["total_steps"], 3);

    let steps = body["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);

    // Step 1: Ingestion
    assert_eq!(steps[0]["status"], "SUCCESS");
    assert!(steps[0]["is_tainted"].as_bool().unwrap());

    // Step 2: Model Read
    assert_eq!(steps[1]["status"], "SUCCESS");

    // Step 3: Adversarial Exfil blocked
    assert_eq!(steps[2]["status"], "BLOCKED_BY_POLICY");
    assert!(steps[2]["policy_decision"].as_str().unwrap().contains("BLOCKED"));
}
