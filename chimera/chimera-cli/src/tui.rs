use crate::models::{FindingSummary, RunDetail, RunSummary, StatusResponse};
use crate::render::{render_finding_lines, render_status_block, stat_u64};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{stdout, IsTerminal};
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone)]
pub struct ConsoleSessionState {
    pub selected_run_id: Option<String>,
    pub last_target: Option<String>,
    pub last_pipeline: String,
    pub last_program: Option<String>,
    pub staged_scope_text: Option<String>,
    pub input: String,
    pub command_mode: bool,
    pub logs: Vec<String>,
}

impl ConsoleSessionState {
    pub fn new(
        selected_run_id: Option<String>,
        last_target: Option<String>,
        last_pipeline: String,
        last_program: Option<String>,
    ) -> Self {
        Self {
            selected_run_id,
            last_target,
            last_pipeline,
            last_program,
            staged_scope_text: None,
            input: String::new(),
            command_mode: false,
            logs: Vec::new(),
        }
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        self.logs.push(line.into());
        if self.logs.len() > 120 {
            let drain = self.logs.len().saturating_sub(120);
            self.logs.drain(0..drain);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsoleSnapshot {
    pub status: StatusResponse,
    pub runs: Vec<RunSummary>,
    pub selected_run_id: Option<String>,
    pub selected_run: Option<RunDetail>,
    pub events: Vec<String>,
    pub findings: Vec<FindingSummary>,
    pub api_error: Option<String>,
}

pub enum ConsoleDirective<T> {
    Continue,
    Exit(ConsoleExit<T>),
}

pub enum ConsoleExit<T> {
    Quit,
    Action(T),
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
        "--------------------------------------------------[ CHIMERA v1.0 ]--------------------------------------------------",
        "     [ SYSTEM BOOT ]: Loading Chimera kernel... [ OK ]",
        "     [ INIT ]: Spawning evidence graph engine... [ OK ]",
        "     [ ARMORY ]: Deploying validators: BOLA·BFLA·JWT·GraphQL·DOM·LLM [ ONLINE ]",
        "     [ PROPHET ]: Connecting to Shannon LLM interface... [ RESPONSIVE ]",
        "     [ BROWSER ]: Initializing Playwright phantoms... [ GHOSTS READY ]",
        target_line.as_str(),
        "--------------------------------------------------------------------------------------------------------------------",
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

                let finding_lines = render_finding_lines(
                    &state.findings,
                    (bottom[1].width as usize).saturating_sub(6),
                );
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

pub fn run_console<F, E, T>(
    session: &mut ConsoleSessionState,
    mut fetch: F,
    mut execute: E,
) -> Result<ConsoleExit<T>>
where
    F: FnMut(&mut ConsoleSessionState) -> Result<ConsoleSnapshot>,
    E: FnMut(&str, &ConsoleSnapshot, &mut ConsoleSessionState) -> Result<ConsoleDirective<T>>,
{
    if !should_use_tui() {
        return Ok(ConsoleExit::Quit);
    }

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut snapshot = fetch(session)?;
    let refresh_interval = Duration::from_millis(750);
    let mut last_refresh = Instant::now();

    let result = loop {
        terminal.draw(|frame| draw_console(frame, &snapshot, session))?;

        if last_refresh.elapsed() >= refresh_interval {
            match fetch(session) {
                Ok(updated) => snapshot = updated,
                Err(err) => session.push_log(format!("refresh failed: {err:#}")),
            }
            last_refresh = Instant::now();
        }

        if !event::poll(Duration::from_millis(100))? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }

        if session.command_mode {
            match key.code {
                KeyCode::Esc => {
                    session.command_mode = false;
                    session.input.clear();
                }
                KeyCode::Enter => {
                    let command = session.input.trim().to_string();
                    session.command_mode = false;
                    session.input.clear();
                    if command.is_empty() {
                        continue;
                    }
                    match execute(&command, &snapshot, session)? {
                        ConsoleDirective::Continue => {
                            snapshot = fetch(session)?;
                            last_refresh = Instant::now();
                        }
                        ConsoleDirective::Exit(exit) => break Ok(exit),
                    }
                }
                KeyCode::Backspace => {
                    session.input.pop();
                }
                KeyCode::Char(ch) => session.input.push(ch),
                KeyCode::Tab => session.input.push(' '),
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break Ok(ConsoleExit::Quit),
            KeyCode::Char(':') | KeyCode::Char('/') => {
                session.command_mode = true;
            }
            KeyCode::Char('s') => {
                session.command_mode = true;
                session.input = "run".to_string();
            }
            KeyCode::Char('r') => {
                snapshot = fetch(session)?;
                last_refresh = Instant::now();
                session.push_log("console refreshed");
            }
            KeyCode::Char('j') | KeyCode::Down => {
                cycle_selection(session, &snapshot.runs, 1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                cycle_selection(session, &snapshot.runs, -1);
            }
            KeyCode::Enter => {
                if let Some(run_id) = session.selected_run_id.clone() {
                    session.push_log(format!("focused run {}", abbreviate(&run_id, 18)));
                    snapshot = fetch(session)?;
                    last_refresh = Instant::now();
                }
            }
            _ => {}
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn draw_console(frame: &mut Frame, snapshot: &ConsoleSnapshot, session: &ConsoleSessionState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(31),
            Constraint::Percentage(34),
            Constraint::Percentage(35),
        ])
        .split(layout[1]);

    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(8)])
        .split(body[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(body[2]);

    let scope_mode = if session.staged_scope_text.is_some() {
        "manifest staged"
    } else {
        "target scoped"
    };
    let selected_label = snapshot
        .selected_run_id
        .as_ref()
        .map(|run_id| abbreviate(run_id, 20))
        .unwrap_or_else(|| "none".to_string());
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "CHIMERA ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("console", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!(
                    " [{}]",
                    if snapshot.api_error.is_some() {
                        "DEGRADED"
                    } else {
                        "ONLINE"
                    }
                ),
                Style::default().fg(if snapshot.api_error.is_some() {
                    Color::Red
                } else {
                    Color::Yellow
                }),
            ),
        ]),
        Line::from(format!(
            "target={} | pipeline={} | scope={} | run={}",
            session.last_target.as_deref().unwrap_or("unset"),
            session.last_pipeline,
            scope_mode,
            selected_label
        )),
        Line::from(format!(
            "mode={} | active={} | : command | s run | j/k select | q quit",
            snapshot.status.mode,
            snapshot
                .status
                .active_run
                .as_ref()
                .and_then(|run| run.run_id.as_deref())
                .map(|run_id| abbreviate(run_id, 18))
                .unwrap_or_else(|| "none".to_string())
        )),
    ])
    .block(
        Block::default()
            .title("Operator Console")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(header, layout[0]);

    let run_items: Vec<ListItem> = if snapshot.runs.is_empty() {
        vec![ListItem::new("No runs recorded")]
    } else {
        snapshot
            .runs
            .iter()
            .take(14)
            .map(|run| {
                let findings = stat_u64(&run.stats, "findings_total");
                let chains = stat_u64(&run.stats, "exploit_chains");
                ListItem::new(format!(
                    "{}  {:<10} f={} c={}",
                    abbreviate(&run.run_id, 14),
                    run.status,
                    findings,
                    chains
                ))
            })
            .collect()
    };
    let mut run_state = ListState::default();
    run_state.select(selected_run_index(snapshot));
    let run_list = List::new(run_items)
        .block(
            Block::default()
                .title("Recent Runs")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    frame.render_stateful_widget(run_list, body[0], &mut run_state);

    let mut status_lines = render_status_block(&snapshot.status, snapshot.selected_run.as_ref());
    if let Some(err) = snapshot.api_error.as_ref() {
        status_lines.push(String::new());
        status_lines.push(format!("API: {}", err));
    }
    let status_panel = Paragraph::new(status_lines.join("\n"))
        .block(
            Block::default()
                .title("Status")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(status_panel, center[0]);

    let run_detail_lines = selected_run_lines(snapshot);
    let selected_panel = Paragraph::new(run_detail_lines.join("\n"))
        .block(
            Block::default()
                .title("Run Context")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(selected_panel, center[1]);

    let event_items: Vec<ListItem> = if snapshot.events.is_empty() {
        vec![ListItem::new("No telemetry yet")]
    } else {
        snapshot
            .events
            .iter()
            .rev()
            .take(12)
            .map(|line| {
                ListItem::new(abbreviate(
                    line,
                    (right[0].width as usize).saturating_sub(6),
                ))
            })
            .collect()
    };
    let event_panel = List::new(event_items).block(
        Block::default()
            .title("Telemetry")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    frame.render_widget(event_panel, right[0]);

    let finding_lines = render_finding_lines(
        &snapshot.findings,
        (right[1].width as usize).saturating_sub(6),
    );
    let findings_panel = Paragraph::new(finding_lines.join("\n"))
        .block(
            Block::default()
                .title("Confirmed Findings")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(findings_panel, right[1]);

    let mut log_lines: Vec<String> = session.logs.iter().rev().take(5).cloned().collect();
    log_lines.reverse();
    if log_lines.is_empty() {
        log_lines.push("Type :help for console commands.".to_string());
    }
    let log_panel = Paragraph::new(log_lines.join("\n"))
        .block(
            Block::default()
                .title("Command Log")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(log_panel, layout[2]);

    let prompt_text = if session.command_mode {
        format!("chimera> {}", session.input)
    } else {
        "navigation mode | press : to enter a command".to_string()
    };
    let prompt = Paragraph::new(prompt_text).block(
        Block::default()
            .title(if session.command_mode {
                "Prompt"
            } else {
                "Ready"
            })
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(prompt, layout[3]);
}

fn selected_run_lines(snapshot: &ConsoleSnapshot) -> Vec<String> {
    let Some(run) = snapshot.selected_run.as_ref() else {
        return vec![
            "No run selected".to_string(),
            "Use j/k or `use <run_id>` to focus a run.".to_string(),
        ];
    };

    let findings = stat_u64(&run.stats, "findings_total");
    let chains = stat_u64(&run.stats, "exploit_chains");
    vec![
        format!(
            "Run ID: {}",
            run.run_id
                .as_deref()
                .map(|run_id| abbreviate(run_id, 24))
                .unwrap_or_else(|| "unknown".to_string())
        ),
        format!("Status: {}", run.status.as_deref().unwrap_or("unknown")),
        format!("Findings: {} | Chains: {}", findings, chains),
        format!("Started: {}", run.started_at.as_deref().unwrap_or("n/a")),
        format!("Ended: {}", run.ended_at.as_deref().unwrap_or("n/a")),
        format!(
            "Artifacts: {}",
            run.artifacts_dir.as_deref().unwrap_or("n/a")
        ),
    ]
}

fn selected_run_index(snapshot: &ConsoleSnapshot) -> Option<usize> {
    let Some(selected) = snapshot.selected_run_id.as_ref() else {
        return None;
    };
    snapshot
        .runs
        .iter()
        .take(14)
        .position(|run| &run.run_id == selected)
}

fn cycle_selection(session: &mut ConsoleSessionState, runs: &[RunSummary], delta: isize) {
    if runs.is_empty() {
        return;
    }

    let current = session
        .selected_run_id
        .as_ref()
        .and_then(|run_id| runs.iter().position(|run| &run.run_id == run_id))
        .unwrap_or(0);

    let next = if delta.is_negative() {
        current
            .checked_sub(delta.unsigned_abs())
            .unwrap_or(runs.len() - 1)
    } else {
        (current + delta as usize) % runs.len()
    };

    session.selected_run_id = Some(runs[next].run_id.clone());
}

fn abbreviate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    let keep = width.saturating_sub(3);
    format!("{}...", &value[..keep])
}
