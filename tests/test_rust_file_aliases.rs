use ethos::aci::ACIHarness;

#[tokio::test]
async fn daemon_file_routes_reject_hardlink_reads_and_writes() {
    use axum::{body::Body, http::Request};
    use ethos::{
        api::routes::{create_router, AppState},
        store::SessionManager,
    };
    use tower::ServiceExt;
    let manager = SessionManager::new();
    let id = manager.create_session("alias-regression").await.unwrap();
    let session = manager.get_session(&id).await.unwrap();
    let root = session.lock().await.root_dir().unwrap();
    std::fs::write(root.join(".env"), "PRIVATE_FLAG=fixture-http-record-59271").unwrap();
    std::fs::hard_link(root.join(".env"), root.join("ordinary.txt")).unwrap();
    let app = create_router(AppState::new(manager.clone()));
    for (tool, body) in [
        ("read", serde_json::json!({"path":"ordinary.txt"})),
        (
            "write",
            serde_json::json!({"path":"ordinary.txt","content":"tampered"}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/sandboxes/{id}/tools/{tool}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["status"], "BLOCKED_BY_POLICY", "{tool}");
        assert_eq!(result["policy_decision"]["rule_id"], "FILESYSTEM-BOUNDARY");
        assert!(!result.to_string().contains("fixture-http-record-59271"));
    }
    assert_eq!(
        std::fs::read_to_string(root.join(".env")).unwrap(),
        "PRIVATE_FLAG=fixture-http-record-59271"
    );
    manager.terminate_session(&id).await;
}

#[test]
fn hardlink_alias_cannot_read_or_overwrite_a_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_dir(dir.path()).unwrap();
    // No API-key-shaped value: file access must be denied independently of
    // whether a redaction heuristic recognizes the contents as credentials.
    let secret = "PRIVATE_FLAG=fixture-confidential-record-438271";
    std::fs::write(dir.path().join(".env"), secret).unwrap();
    std::fs::hard_link(
        dir.path().join(".env"),
        dir.path().join("ordinary-notes.txt"),
    )
    .unwrap();
    let result = h.read("ordinary-notes.txt");
    assert_ne!(
        result.status, "SUCCESS",
        "Hardlink alias exposed protected file: {}",
        result.output
    );
    assert!(!result
        .output
        .to_string()
        .contains("fixture-confidential-record-438271"));
    assert_ne!(
        h.write("ordinary-notes.txt", "tampered", None).status,
        "SUCCESS"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env")).unwrap(),
        secret
    );
}

#[test]
fn hardlink_alias_cannot_modify_secret_contents() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join(".env"), "fixture-original-record").unwrap();
    std::fs::hard_link(dir.path().join(".env"), dir.path().join("ordinary.txt")).unwrap();
    let result = h.write("ordinary.txt", "tampered", None);
    assert_ne!(result.status, "SUCCESS");
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env")).unwrap(),
        "fixture-original-record"
    );
}

#[test]
fn alternate_tools_cannot_use_hardlink_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_dir(dir.path()).unwrap();
    let original = "PRIVATE_FLAG=fixture-alias-tool-canary-519";
    std::fs::write(dir.path().join(".env"), original).unwrap();
    std::fs::hard_link(dir.path().join(".env"), dir.path().join("ordinary.txt")).unwrap();
    assert_ne!(h.view_lines("ordinary.txt", 1, 3).status, "SUCCESS");
    assert!(!h
        .grep("PRIVATE_FLAG")
        .output
        .to_string()
        .contains("fixture-alias-tool-canary-519"));
    assert_ne!(
        h.edit_block("ordinary.txt", "PRIVATE_FLAG", "tampered", None)
            .status,
        "SUCCESS"
    );
    assert_ne!(
        h.fetch(
            "https://fixture.invalid/document",
            Some("ordinary.txt"),
            Some("tampered")
        )
        .status,
        "SUCCESS"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env")).unwrap(),
        original
    );
    assert!(h.snapshot("must not silently omit hardlinks").is_err());
}

#[cfg(windows)]
#[test]
fn windows_stream_and_device_names_are_rejected_before_opening() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_dir(dir.path()).unwrap();
    for path in [
        "ordinary.txt:private",
        "NUL",
        "CON",
        "PRN.txt",
        "AUX",
        "COM1",
        "LPT1",
    ] {
        assert_ne!(h.read(path).status, "SUCCESS", "{path}");
        assert_ne!(h.write(path, "tampered", None).status, "SUCCESS", "{path}");
    }
}

#[cfg(unix)]
#[test]
fn in_workspace_symbolic_links_cannot_alias_protected_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join(".env"), "fixture-original").unwrap();
    std::os::unix::fs::symlink(".env", dir.path().join("ordinary.txt")).unwrap();
    assert_ne!(h.read("ordinary.txt").status, "SUCCESS");
    assert_ne!(h.write("ordinary.txt", "tampered", None).status, "SUCCESS");
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env")).unwrap(),
        "fixture-original"
    );
}
