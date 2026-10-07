use super::app::App;
use crate::scanner::rules::Severity;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(app: &App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let (crit, high, med, low) = app.counts_by_severity();
    let header_text = vec![Line::from(vec![
        Span::styled(
            " GIT SECRET HUNTER ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Total: "),
        Span::styled(
            app.items.len().to_string(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | Critical: "),
        Span::styled(crit.to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw(" | High: "),
        Span::styled(high.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | Medium: "),
        Span::styled(med.to_string(), Style::default().fg(Color::Blue)),
        Span::raw(" | Low: "),
        Span::styled(low.to_string(), Style::default().fg(Color::DarkGray)),
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
        .enumerate()
        .map(|(idx, item)| {
            let is_selected = idx == app.selected_index;
            let (badge_text, badge_color) = match item.finding.severity {
                Severity::Critical => ("[CRIT]", Color::Red),
                Severity::High => ("[HIGH]", Color::Yellow),
                Severity::Medium => ("[MED ]", Color::Blue),
                Severity::Low => ("[LOW ]", Color::DarkGray),
            };

            let status_mark = if item.is_resolved { "[RESOLVED] " } else { "" };
            let status_color = if item.is_resolved { Color::Green } else { Color::Reset };

            let mut style = Style::default();
            if is_selected {
                style = style
                    .bg(Color::Rgb(40, 45, 60))
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD);
            }

            let line = Line::from(vec![
                Span::styled(badge_text, Style::default().fg(badge_color).add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::styled(status_mark, Style::default().fg(status_color)),
                Span::styled(&item.finding.rule_name, Style::default().fg(Color::White)),
                Span::raw(" ("),
                Span::styled(&item.finding.file_path, Style::default().fg(Color::DarkGray)),
                Span::raw(")"),
            ]);

            ListItem::new(line).style(style)
        })
        .collect();

    let list_widget = List::new(list_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Detected Secrets")
            .border_style(Style::default().fg(Color::White)),
    );
    frame.render_widget(list_widget, main_chunks[0]);

    let detail_text = if let Some(item) = app.current_item() {
        let f = &item.finding;
        let resolved_status = if item.is_resolved {
            Span::styled("RESOLVED (MARKED)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("ACTIVE RISK", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        };

        vec![
            Line::from(vec![
                Span::styled("Rule Name:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.rule_name, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Category:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(f.category.label(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Severity:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(f.severity.label(), Style::default().fg(match f.severity {
                    Severity::Critical => Color::Red,
                    Severity::High => Color::Yellow,
                    Severity::Medium => Color::Blue,
                    Severity::Low => Color::DarkGray,
                }).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Confidence:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.confidence, Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Audit State: ", Style::default().fg(Color::DarkGray)),
                resolved_status,
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Location:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}:{}", f.file_path, f.line_number), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Commit ID:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.commit_id, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::styled("Author:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.commit_author, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Commit Date: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.commit_date, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Secret:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(&f.secret_preview, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Entropy:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    f.entropy.map(|e| format!("{:.2} bits", e)).unwrap_or_else(|| "N/A".to_string()),
                    Style::default().fg(Color::LightBlue),
                ),
            ]),
        ]
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
        Span::raw("Toggle Resolved  "),
        Span::styled(" [q / Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("Exit TUI"),
    ]);

    let footer_widget = Paragraph::new(footer_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer_widget, chunks[2]);
}
