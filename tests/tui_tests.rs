use git_secret_hunter::scanner::rules::RuleCategory;
use git_secret_hunter::scanner::{FindingGroup, Occurrence, Severity};
use git_secret_hunter::tui::app::App;
use git_secret_hunter::tui::state::ResolvedState;
use git_secret_hunter::tui::ui::render;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn group(index: usize, severity: Severity) -> FindingGroup {
    FindingGroup {
        fingerprint: format!("fp{:012}", index),
        rule_id: "high-entropy-token".to_string(),
        rule_name: format!("Finding number {:03}", index),
        category: RuleCategory::GenericEntropy,
        severity,
        confidence: "NORMAL".to_string(),
        family: "base64".to_string(),
        secret_preview: format!("pref...{:04}", index),
        entropy: Some(4.9),
        verification: None,
        occurrences: vec![Occurrence {
            commit_id: format!("commit{:018}", index),
            commit_author: "Tester".to_string(),
            commit_date: "2026-01-01 10:00:00 +0000".to_string(),
            file_path: format!("app/file_{:03}.py", index),
            line_number: index + 1,
        }],
        commit_count: 1,
        file_count: 1,
        first_seen: "2026-01-01 10:00:00 +0000".to_string(),
        last_seen: "2026-01-01 10:00:00 +0000".to_string(),
    }
}

fn state_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("gsh-tui-state-{}-{}.json", name, std::process::id()))
}

fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    let mut text = String::new();

    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if let Some(cell) = buffer.cell((x, y)) {
                text.push_str(cell.symbol());
            }
        }
        text.push('\n');
    }

    text
}

#[test]
fn test_tui_renders_and_keeps_state() {
    let path = state_path("render");
    let _ = std::fs::remove_file(&path);

    let groups = vec![
        group(0, Severity::Critical),
        group(1, Severity::Info),
        group(2, Severity::Low),
    ];

    let mut app = App::with_resolved(groups, ResolvedState::at_path(path.clone()));
    let mut terminal = Terminal::new(TestBackend::new(110, 32)).expect("test terminal");

    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("render must not fail");

    let text = buffer_text(&terminal);
    assert!(text.contains("GIT SECRET HUNTER"), "header must be rendered");
    assert!(text.contains("Finding number 000"), "first finding must be listed");
    assert!(text.contains("CRIT"), "severity badge must be rendered");
    assert!(text.contains("INFO"), "info badge must be rendered");

    app.toggle_resolved();
    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("render after toggle must not fail");

    let text = buffer_text(&terminal);
    assert!(text.contains("RESOLVED"), "resolved status must be shown");

    let saved = std::fs::read_to_string(&path).expect("state file must be written");
    assert!(saved.contains("fp000000000000"), "state file must contain fingerprint");

    let reloaded = ResolvedState::at_path(path.clone());
    assert!(reloaded.is_resolved("fp000000000000"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_tui_list_scrolls_through_long_findings() {
    let path = state_path("scroll");
    let _ = std::fs::remove_file(&path);

    let groups: Vec<FindingGroup> = (0..60)
        .map(|index| group(index, Severity::Medium))
        .collect();

    let mut app = App::with_resolved(groups, ResolvedState::at_path(path.clone()));
    let mut terminal = Terminal::new(TestBackend::new(110, 24)).expect("test terminal");

    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("initial render must not fail");

    assert_eq!(app.list_state.offset(), 0, "list starts at the top");

    for _ in 0..50 {
        app.next();
    }

    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("render after scrolling must not fail");

    assert!(
        app.list_state.offset() > 0,
        "list must scroll instead of clipping, offset: {}",
        app.list_state.offset()
    );

    let text = buffer_text(&terminal);
    assert!(
        text.contains("Finding number 050"),
        "selected finding must stay visible after scrolling"
    );

    for _ in 0..200 {
        app.next();
    }

    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("render at the end of the list must not fail");

    assert_eq!(app.selected_index, 59, "selection must stop at the last item");

    app.first();
    assert_eq!(app.selected_index, 0, "Home must jump to the first finding");

    app.page_down();
    assert_eq!(app.selected_index, 10, "PageDown must jump forward by a page");

    app.page_up();
    assert_eq!(app.selected_index, 0, "PageUp must jump back a page");

    app.last();
    assert_eq!(app.selected_index, 59, "End must jump to the last finding");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_tui_handles_empty_findings() {
    let mut app = App::with_resolved(Vec::new(), ResolvedState::default());
    let mut terminal = Terminal::new(TestBackend::new(80, 20)).expect("test terminal");

    terminal
        .draw(|frame| render(&mut app, frame))
        .expect("render with no findings must not fail");

    app.next();
    app.previous();
    app.toggle_resolved();

    assert_eq!(app.selected_index, 0);
    assert!(app.current_item().is_none());
}
