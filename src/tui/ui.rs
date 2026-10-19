use super::app::App;
use crate::scanner::rules::Severity;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

const MAX_DETAIL_OCCURRENCES: usize = 8;

fn severity_style(severity: Severity) -> (Style, Style) {
    match severity {
        Severity::Critical => (
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Red),
        ),
        Severity::High => (
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Yellow),
        ),
        Severity::Medium => (
            Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Blue),
        ),
        Severity::Low => (
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::DarkGray),
        ),
        Severity::Info => (
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Cyan),
        ),
    }
}

fn severity_badge_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "[CRIT]",
        Severity::High => "[HIGH]",
        Severity::Medium => "[MED ]",
        Severity::Low => "[LOW ]",
        Severity::Info => "[INFO]",
    }
}

pub fn render(app: &mut App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let (critical, high, medium, low, info) = app.counts_by_severity();

    let header_text = vec![Line::from(vec![
        Span::styled(
            " GIT SECRET HUNTER ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Unique: "),
        Span::styled(
            app.items.len().to_string(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Critical: "),
        Span::styled(
            critical.to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | High: "),
        Span::styled(high.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | Medium: "),
        Span::styled(medium.to_string(), Style::default().fg(Color::Blue)),
        Span::raw(" | Low: "),
        Span::styled(low.to_string(), Style::default().fg(Color::DarkGray)),
        Span::raw(" | Info: "),
        Span::styled(info.to_string(), Style::default().fg(Color::Cyan)),
        Span::raw(" | Resolved: "),
        Span::styled(
            app.resolved_count().to_string(),
            Style::default().fg(Color::Green),
        ),
    ])];

    let header_widget = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Security Audit Overview")
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header_widget, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    let list_items: Vec<ListItem> = app
        .items
        .iter()
        .map(|item| {
            let (badge_style, _) = severity_style(item.group.severity);
            let status_mark = if item.is_resolved { "[RESOLVED] " } else { "" };
            let status_color = if item.is_resolved { Color::Green } else { Color::Reset };

            let line = Line::from(vec![
                Span::styled(severity_badge_text(item.group.severity), badge_style),
                Span::raw(" "),
                Span::styled(status_mark, Style::default().fg(status_color)),
                Span::styled(&item.group.rule_name, Style::default().fg(Color::White)),
                Span::raw(" ("),
                Span::styled(
                    item.group
                        .occurrences
                        .first()
                        .map(|occurrence| occurrence.file_path.as_str())
                        .unwrap_or("unknown"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(")"),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list_widget = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Detected Secrets (unique)")
                .border_style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 45, 60))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    if app.selected_index >= app.items.len() && !app.items.is_empty() {
        app.selected_index = app.items.len() - 1;
    }
    app.list_state.select(if app.items.is_empty() {
        None
    } else {
        Some(app.selected_index)
    });

    frame.render_stateful_widget(list_widget, main_chunks[0], &mut app.list_state);

    let detail_text = if let Some(item) = app.current_item() {
        let group = &item.group;
        let resolved_status = if item.is_resolved {
            Span::styled(
                "RESOLVED (MARKED)",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "ACTIVE RISK",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        };

        let (_, severity_color) = severity_style(group.severity);

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Rule Name:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &group.rule_name,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Category:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(group.category.label(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Severity:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    group.severity.label(),
                    severity_color.add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Confidence:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&group.confidence, Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Audit State: ", Style::default().fg(Color::DarkGray)),
                resolved_status,
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Secret:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &group.secret_preview,
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Fingerprint: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&group.fingerprint, Style::default().fg(Color::LightBlue)),
                Span::styled(
                    format!(" ({})", group.family),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("Entropy:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    group
                        .entropy
                        .map(|entropy| format!("{:.2} bits", entropy))
                        .unwrap_or_else(|| "N/A".to_string()),
                    Style::default().fg(Color::LightBlue),
                ),
            ]),
            Line::from(vec![
                Span::styled("Verification:", Style::default().fg(Color::DarkGray)),
                {
                    let (label, color) = match group.verification.as_ref() {
                        Some(verification) => (
                            format!(
                                " {} ({}; {})",
                                verification.status.label(),
                                verification.provider,
                                verification.detail
                            ),
                            match verification.status {
                                crate::verify::VerificationStatus::Verified => Color::Green,
                                crate::verify::VerificationStatus::Invalid => Color::DarkGray,
                                crate::verify::VerificationStatus::Unknown => Color::Yellow,
                                crate::verify::VerificationStatus::Error => Color::Red,
                            },
                        ),
                        None => (" not performed".to_string(), Color::DarkGray),
                    };

                    Span::styled(label, Style::default().fg(color))
                },
            ]),
            Line::from(vec![
                Span::styled("History:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!(
                        "{} commit(s), {} file(s)",
                        group.commit_count, group.file_count
                    ),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("First seen:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&group.first_seen, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("Last seen:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(&group.last_seen, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Occurrences:",
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            )),
        ];

        for occurrence in group.occurrences.iter().take(MAX_DETAIL_OCCURRENCES) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    occurrence
                        .commit_id
                        .get(..10)
                        .unwrap_or(occurrence.commit_id.as_str())
                        .to_string(),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw(" "),
                Span::styled(
                    format!(
                        "{}:{}",
                        occurrence.file_path, occurrence.line_number
                    ),
                    Style::default().fg(Color::White),
                ),
                Span::raw(" "),
                Span::styled(
                    occurrence.commit_date.clone(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        if group.occurrences.len() > MAX_DETAIL_OCCURRENCES {
            lines.push(Line::from(Span::styled(
                format!(
                    "  ... and {} more occurrence(s)",
                    group.occurrences.len() - MAX_DETAIL_OCCURRENCES
                ),
                Style::default().fg(Color::DarkGray),
            )));
        }

        lines
    } else {
        vec![Line::from("No findings selected")]
    };

    let detail_widget = Paragraph::new(detail_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Finding Inspector")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail_widget, main_chunks[1]);

    let footer_text = Line::from(vec![
        Span::styled(" [↑/k] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Up  "),
        Span::styled(" [↓/j] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Down  "),
        Span::styled(" [Space] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("Toggle Resolved (saved)  "),
        Span::styled(" [q/Ctrl+C] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("Exit TUI"),
    ]);

    let footer_widget = Paragraph::new(footer_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer_widget, chunks[2]);
}
