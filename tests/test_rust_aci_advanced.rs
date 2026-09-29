use ethos::aci::ACIHarness;

#[test]
fn test_edit_block_success() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();

    harness.write("calculator.py", "def add(a, b):\n    return a - b\n", None);

    let edit_res = harness.edit_block("calculator.py", "return a - b", "return a + b", None);

    assert_eq!(edit_res.status, "SUCCESS");
    let content = harness.read("calculator.py").output;
    assert_eq!(
        content,
        serde_json::Value::String("def add(a, b):\n    return a + b\n".to_string())
    );
}

#[test]
fn test_edit_block_not_found_returns_error() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();

    harness.write("app.py", "print('hello')", None);

    let edit_res = harness.edit_block("app.py", "nonexistent string block", "replacement", None);

    assert_eq!(edit_res.status, "ERROR");
    assert!(edit_res.error.unwrap().contains("Target content not found"));
}

#[test]
fn test_output_windowing_folds_large_output() {
    let harness = ACIHarness::new_with_temp_dir().unwrap();

    // Generate large text (500 lines)
    let large_text: String = (1..=500).map(|i| format!("Line {}\n", i)).collect();
    let folded = harness.fold_output(&large_text, 20, 20);

    assert!(folded.contains("Line 1"));
    assert!(folded.contains("Line 500"));
    assert!(folded.contains("lines truncated"));
    assert!(folded.len() < large_text.len());
}
