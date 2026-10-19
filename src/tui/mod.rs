pub mod app;
pub mod state;
pub mod ui;

use app::App;
use crate::scanner::FindingGroup;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, stdout, Stdout};
use std::time::Duration;

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(out);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

pub fn launch_tui(groups: Vec<FindingGroup>) -> io::Result<()> {
    let mut guard = TerminalGuard::new()?;
    let mut app = App::new(groups);

    loop {
        guard.terminal.draw(|frame| ui::render(&mut app, frame))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.next();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.previous();
                        }
                        KeyCode::PageDown => {
                            app.page_down();
                        }
                        KeyCode::PageUp => {
                            app.page_up();
                        }
                        KeyCode::Home => {
                            app.first();
                        }
                        KeyCode::End => {
                            app.last();
                        }
                        KeyCode::Char(' ') | KeyCode::Char('m') => {
                            app.toggle_resolved();
                        }
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    app.resolved.save();

    Ok(())
}
