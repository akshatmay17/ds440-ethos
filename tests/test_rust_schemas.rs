use ethos::aci::schemas::get_all_tool_definitions;

#[test]
fn test_export_openai_tool_definitions() {
    let tools = get_all_tool_definitions();
    assert!(tools.len() >= 8);

    let tool_names: Vec<&str> = tools.iter().map(|t| t["function"]["name"].as_str().unwrap()).collect();

    assert!(tool_names.contains(&"read"));
    assert!(tool_names.contains(&"write"));
    assert!(tool_names.contains(&"edit_block"));
    assert!(tool_names.contains(&"view_lines"));
    assert!(tool_names.contains(&"search_files"));
    assert!(tool_names.contains(&"grep"));
    assert!(tool_names.contains(&"exec"));
    assert!(tool_names.contains(&"snapshot"));
    assert!(tool_names.contains(&"rewind"));

    // Verify schema structure on one tool
    let view_tool = tools.iter().find(|t| t["function"]["name"] == "view_lines").unwrap();
    assert_eq!(view_tool["type"], "function");
    assert!(view_tool["function"]["parameters"]["properties"]["path"].is_object());
    assert!(view_tool["function"]["parameters"]["properties"]["start_line"].is_object());
    assert!(view_tool["function"]["parameters"]["properties"]["end_line"].is_object());
}
