use crate::models::{FindingSummary, RunDetail, StatusResponse};
use crate::render::{render_finding_lines, render_status_block};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use std::io::{stdout, IsTerminal};
use std::time::Duration;

pub struct DashboardState {
    pub title: String,
    pub pipeline: String,
    pub run_id: String,
    pub phase: String,
    pub status: StatusResponse,
    pub run_detail: Option<RunDetail>,
    pub events: Vec<String>,
    pub findings: Vec<FindingSummary>,
}

pub fn should_use_tui() -> bool {
    stdout().is_terminal()
}

pub fn boot_sequence(target: &str, pipeline: &str) -> Result<()> {
    let mut stdout = stdout();
    execute!(
        stdout,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )?;
    let target_line = format!("     [ TARGET ]: {} via {} pipeline", target, pipeline);
    let lines = vec![
        "—————————————————————————————[ CHIMERA v1.0 ]—————————————————————————————",
        "     [ SYSTEM BOOT ]: Loading Chimera kernel... [ OK ]",
        "     [ INIT ]: Spawning evidence graph engine... [ OK ]",
        "     [ ARMORY ]: Deploying validators: BOLA·BFLA·JWT·GraphQL·DOM·LLM [ ONLINE ]",
        "     [ PROPHET ]: Connecting to Shannon LLM interface... [ RESPONSIVE ]",
        "     [ BROWSER ]: Initializing Playwright phantoms... [ GHOSTS READY ]",
        target_line.as_str(),
        "—————————————————————————————————————————————————————————————————————",
    ];
    for line in lines {
        println!("\x1b[32m{}\x1b[0m", line);
        std::thread::sleep(Duration::from_millis(55));
    }
    Ok(())
}

pub fn run_dashboard<F>(mut fetch: F) -> Result<()>
where
    F: FnMut() -> Result<Option<DashboardState>>,
{
    if !should_use_tui() {
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = loop {
        if let Some(state) = fetch()? {
            terminal.draw(|frame| {
                let layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(5),
                        Constraint::Min(10),
                        Constraint::Length(3),
                    ])
                    .split(frame.area());

                let top = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
                    .split(layout[1]);

                let bottom = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(top[1]);

                let header = Paragraph::new(vec![
                    Line::from(vec![
                        Span::styled(
                            "CHIMERA@",
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("matrix ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("[ {} ]", state.phase.to_ascii_uppercase()),
                            Style::default().fg(Color::Yellow),
                        ),
                    ]),
                    Line::from(format!(
                        "run={} | pipeline={} | target={}",
                        state.run_id, state.pipeline, state.title
                    )),
                    Line::from("q = disconnect | live feed from /v1"),
                ])
                .block(
                    Block::default()
                        .title("Boot Console")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green)),
                );
                frame.render_widget(header, layout[0]);

                let status_lines = render_status_block(&state.status, state.run_detail.as_ref());
                let status = Paragraph::new(status_lines.join("\n")).block(
                    Block::default()
                        .title("Run State")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green)),
                );
                frame.render_widget(status, top[0]);

                let event_items: Vec<ListItem> = state
                    .events
                    .iter()
                    .rev()
                    .take(18)
                    .map(|item| ListItem::new(item.clone()))
                    .collect();
                let events = List::new(event_items).block(
                    Block::default()
                        .title("Telemetry Feed")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                );
                frame.render_widget(events, bottom[0]);

                let finding_lines =
                    render_finding_lines(&state.findings, bottom[1].width as usize - 6);
                let findings = Paragraph::new(finding_lines.join("\n")).block(
                    Block::default()
                        .title("Confirmed Surface")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Red)),
                );
                frame.render_widget(findings, bottom[1]);

                let footer = Paragraph::new(
                    "Scope-first control surface. Findings and chain artifacts stay replayable.",
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green)),
                );
                frame.render_widget(footer, layout[2]);
            })?;
        }

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                    break Ok(());
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
