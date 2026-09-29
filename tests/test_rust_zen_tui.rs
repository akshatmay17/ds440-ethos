use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ethos::tui::{FeedItem, ZenApp};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[test]
fn test_zen_app_initialization_and_template_feed() {
    let app = ZenApp::default();
    assert_eq!(app.agent_mode, "Build");
    assert_eq!(app.task_title, "Ready");
    assert_eq!(app.tokens, 0);
    assert_eq!(app.context_pct, 0);
    assert_eq!(app.spent_usd, 0.0);
    assert!(!app.feed.is_empty());
}

#[test]
fn test_zen_app_mode_cycling_via_tab() {
    let mut app = ZenApp::default();
    assert_eq!(app.agent_mode, "Build");

    let tab_event = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
    app.handle_key(tab_event);
    assert_eq!(app.agent_mode, "Plan");

    app.handle_key(tab_event);
    assert_eq!(app.agent_mode, "Review");

    app.handle_key(tab_event);
    assert_eq!(app.agent_mode, "Audit");

    app.handle_key(tab_event);
    assert_eq!(app.agent_mode, "Build");
}

#[test]
fn test_zen_app_command_palette_ctrl_p() {
    let mut app = ZenApp::default();
    assert!(!app.palette_open);

    // Open palette with Ctrl+P
    let ctrl_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL);
    app.handle_key(ctrl_p);
    assert!(app.palette_open);

    // Type query: "attack"
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.palette_query, "at");

    let matches = app.get_matching_commands();
    assert!(!matches.is_empty());
    assert!(matches.iter().any(|c| c.name.contains("attack")));

    // Close palette with Esc
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.palette_open);
}

#[test]
fn test_zen_app_prompt_submission_and_metrics() {
    let harness = ethos::aci::ACIHarness::new_with_temp_dir().ok();
    let mut app = ZenApp::new(harness, ethos::config::user_config::UserConfig::default());
    let initial_tokens = app.tokens;

    app.submit_prompt("Build new API authentication endpoint");
    assert_eq!(app.task_title, "Build new API authentication endpoint");
    assert!(app.tokens >= initial_tokens);

    let has_user_prompt = app
        .feed
        .iter()
        .any(|item| matches!(item, FeedItem::UserPrompt { .. }));
    assert!(has_user_prompt);
}

#[test]
fn test_zen_app_attack_staging_and_taint_interception() {
    let harness = ethos::aci::ACIHarness::new_with_temp_dir().ok();
    let mut app = ZenApp::new(harness, ethos::config::user_config::UserConfig::default());
    app.stage_attack_scenario("m365_sox_invoice_reconcile");

    let has_staged = app.feed.iter().any(|item| {
        if let FeedItem::FileAction { path, .. } = item {
            path.contains("m365_sox_invoice_reconcile")
        } else {
            false
        }
    });
    assert!(has_staged);

    app.submit_prompt("Please parse invoice_reconciliation_2026_Q3.txt");
    let has_alert = app
        .feed
        .iter()
        .any(|item| matches!(item, FeedItem::TaintAlert { .. }));
    assert!(has_alert);
}

#[test]
fn test_zen_app_rendering_all_components_without_panic() {
    let backend = TestBackend::new(140, 45);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut app = ZenApp::default();

    // 1. Render default OpenCode layout
    terminal.draw(|f| app.draw(f)).unwrap();

    // 2. Open Command Palette and render modal overlay
    app.palette_open = true;
    app.palette_query = "sox".to_string();
    terminal.draw(|f| app.draw(f)).unwrap();

    // 3. Render with active typing buffer
    app.palette_open = false;
    app.input_buffer = "git commit -m 'feat: update schema'".to_string();
    app.cursor_position = 10;
    terminal.draw(|f| app.draw(f)).unwrap();
}

#[test]
fn test_zen_app_setup_modal_flow() {
    let backend = TestBackend::new(140, 45);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut app = ZenApp::default();
    assert!(!app.setup_open);

    // Trigger /setup command
    app.execute_command_str("/setup");
    assert!(app.setup_open);
    assert_eq!(app.setup_step, 0);

    // Verify rendering setup step 0 (Provider selection)
    terminal.draw(|f| app.draw(f)).unwrap();

    // Advance to Step 1 (Endpoint URL)
    let enter_event = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    app.handle_key(enter_event);
    assert_eq!(app.setup_step, 1);
    terminal.draw(|f| app.draw(f)).unwrap();

    // Advance to Step 2 (API Key)
    app.handle_key(enter_event);
    assert_eq!(app.setup_step, 2);
    terminal.draw(|f| app.draw(f)).unwrap();

    // Advance to Step 3 (Model)
    app.handle_key(enter_event);
    assert_eq!(app.setup_step, 3);
    terminal.draw(|f| app.draw(f)).unwrap();

    // Advance to Step 4 (Policy)
    app.handle_key(enter_event);
    assert_eq!(app.setup_step, 4);
    terminal.draw(|f| app.draw(f)).unwrap();

    // Complete setup
    app.handle_key(enter_event);
    assert!(!app.setup_open);

    // Check confirmation message was appended to feed
    let has_saved_msg = app.feed.iter().any(|item| {
        if let FeedItem::AgentMessage { text } = item {
            text.contains("Configuration saved")
        } else {
            false
        }
    });
    assert!(has_saved_msg);
}

#[test]
fn test_zen_app_keyboard_shortcuts_and_help() {
    use crossterm::event::KeyEventKind;

    let mut app = ZenApp::default();

    // Test typing with KeyEventKind::Press and KeyEventKind::Repeat
    let mut press_h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
    press_h.kind = KeyEventKind::Press;
    app.handle_key(press_h);

    let mut repeat_e = KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE);
    repeat_e.kind = KeyEventKind::Repeat;
    app.handle_key(repeat_e);

    let mut repeat_l = KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE);
    repeat_l.kind = KeyEventKind::Repeat;
    app.handle_key(repeat_l);

    let mut repeat_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE);
    repeat_p.kind = KeyEventKind::Repeat;
    app.handle_key(repeat_p);

    assert_eq!(app.input_buffer, "help");

    // Test Ctrl+U (clear line)
    let ctrl_u = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
    app.handle_key(ctrl_u);
    assert_eq!(app.input_buffer, "");

    // Test typing and word deletion with Ctrl+W
    for c in "foo bar".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    assert_eq!(app.input_buffer, "foo bar");

    let ctrl_w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL);
    app.handle_key(ctrl_w);
    assert_eq!(app.input_buffer, "foo ");

    // Test /help command execution
    app.handle_key(ctrl_u);
    app.execute_command_str("/help");
    let has_help = app.feed.iter().any(|item| {
        if let FeedItem::AgentMessage { text } = item {
            text.contains("Command Reference")
        } else {
            false
        }
    });
    assert!(has_help);
}
