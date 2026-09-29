use ethos::aci::ACIHarness;

#[test]
fn test_view_lines_formats_with_line_numbers() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();

    let sample_code = "line one\nline two\nline three\nline four\nline five\n";
    harness.write("sample.py", sample_code, None);

    // View lines 2 to 4
    let res = harness.view_lines("sample.py", 2, 4);
    assert_eq!(res.status, "SUCCESS");

    let output = res.output.as_str().unwrap();
    assert!(output.contains("2: line two"));
    assert!(output.contains("3: line three"));
    assert!(output.contains("4: line four"));
    assert!(!output.contains("1: line one"));
    assert!(!output.contains("5: line five"));
}

#[test]
fn test_view_lines_out_of_range_handling() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();
    harness.write("short.txt", "alpha\nbeta\n", None);

    let res = harness.view_lines("short.txt", 1, 100);
    assert_eq!(res.status, "SUCCESS");
    let output = res.output.as_str().unwrap();
    assert!(output.contains("1: alpha"));
    assert!(output.contains("2: beta"));
}

#[test]
fn test_search_files_matches_pattern() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();
    harness.write("src/main.rs", "fn main() {}", None);
    harness.write("src/utils.rs", "fn util() {}", None);
    harness.write("docs/readme.md", "# Docs", None);

    let res = harness.search_files("*.rs");
    assert_eq!(res.status, "SUCCESS");

    let matched: Vec<String> = serde_json::from_value(res.output).unwrap();
    assert_eq!(matched.len(), 2);
    assert!(matched.contains(&"src/main.rs".to_string()));
    assert!(matched.contains(&"src/utils.rs".to_string()));
    assert!(!matched.contains(&"docs/readme.md".to_string()));
}

#[test]
fn test_grep_finds_matching_lines() {
    let mut harness = ACIHarness::new_with_temp_dir().unwrap();
    harness.write(
        "auth.py",
        "def login():\n    token = 'SECRET_TOKEN_123'\n    return token\n",
        None,
    );
    harness.write("public.py", "def info():\n    return 'ok'\n", None);

    let res = harness.grep("SECRET_TOKEN");
    assert_eq!(res.status, "SUCCESS");

    let output = res.output.as_str().unwrap();
    assert!(output.contains("auth.py:2:"));
    assert!(output.contains("SECRET_TOKEN_123"));
    assert!(!output.contains("public.py"));
}
