use crossterm::event::KeyCode;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use ethos::config::providers::ProviderManager;
use ethos::metrics::MetricsCollector;
use ethos::tui::TuiApp;

#[test]
fn test_tui_app_tab_navigation_and_keys() {
    let mut app = TuiApp::default();
    assert_eq!(app.selected_tab, 0);

    // Tab switching via next_tab and prev_tab
    app.next_tab();
    assert_eq!(app.selected_tab, 1);
    app.next_tab();
    assert_eq!(app.selected_tab, 2);
    app.prev_tab();
    assert_eq!(app.selected_tab, 1);

    // Direct numeric keys
    app.handle_key(KeyCode::Char('3'));
    assert_eq!(app.selected_tab, 2);
    app.handle_key(KeyCode::Char('5'));
    assert_eq!(app.selected_tab, 4);
    app.handle_key(KeyCode::Char('1'));
    assert_eq!(app.selected_tab, 0);

    // Space toggles pause
    assert!(!app.paused);
    app.handle_key(KeyCode::Char(' '));
    assert!(app.paused);
    app.handle_key(KeyCode::Char(' '));
    assert!(!app.paused);

    // Quit key
    assert!(!app.should_quit);
    app.handle_key(KeyCode::Char('q'));
    assert!(app.should_quit);
}

#[test]
fn test_tui_app_rendering_all_views_without_panic() {
    let backend = TestBackend::new(140, 45);
    let mut terminal = Terminal::new(backend).unwrap();

    let metrics = MetricsCollector::new();
    metrics.set_active_sandboxes(2);
    metrics.increment_steps(8);
    metrics.record_wall_trip("promptinject");

    let providers = ProviderManager::new();
    let mut app = TuiApp::new(metrics, providers);

    // Render Tab 0: Dashboard
    app.selected_tab = 0;
    terminal.draw(|f| app.draw(f)).unwrap();

    // Render Tab 1: Taint Ledger
    app.selected_tab = 1;
    terminal.draw(|f| app.draw(f)).unwrap();

    // Render Tab 2: Containment Walls
    app.selected_tab = 2;
    terminal.draw(|f| app.draw(f)).unwrap();

    // Render Tab 3: Providers & APIs
    app.selected_tab = 3;
    terminal.draw(|f| app.draw(f)).unwrap();

    // Render Tab 4: Benchmarks
    app.selected_tab = 4;
    terminal.draw(|f| app.draw(f)).unwrap();
}
