use crate::action::{Action, Effect};
use crate::app::{App, Mode};
use crate::events::{Event, EventHandler};
use crate::models::{FindingSummary, RunDetail, StatusResponse};
use crate::render::{render_finding_lines, render_status_block};
use crate::theme::Theme;
use crate::ui;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::env;
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

pub enum ConsoleExit<T> {
    Quit,
    Action(T),
}

pub fn should_use_tui() -> bool {
    stdout().is_terminal()
}

pub fn run_startup_splash() -> Result<bool> {
    if !should_use_tui() || !startup_matrix_enabled() {
        return Ok(true);
    }

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut events = EventHandler::new(Duration::from_millis(90));
    let theme = Theme::from_name(crate::theme::ThemeName::Matrix);
    let mut splash = StartupSplash::default();

    let result = loop {
        terminal.draw(|frame| draw_startup_splash(frame, &mut splash, &theme))?;

        match events.next()? {
            Event::Tick => {
                let size = terminal.size()?;
                splash.tick(size.width, size.height);
            }
            Event::Resize => {
                let size = terminal.size()?;
                splash.ensure_columns(size.width, size.height);
            }
            Event::Key(key) => match key.code {
                KeyCode::Char('1') | KeyCode::Enter => break Ok(true),
                KeyCode::Char('?') => splash.show_help = !splash.show_help,
                KeyCode::Esc | KeyCode::Char('q') => break Ok(false),
                _ => {}
            },
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

pub fn boot_sequence(target: &str, pipeline: &str) -> Result<()> {
    let mut stdout = stdout();
    execute!(
        stdout,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )?;
    let target_line = format!("Target: {}   Pipeline: {}", target, pipeline);
    let lines = vec![
        "  ____ _   _ ___ __  __ _____ ____   _",
        " / ___| | | |_ _|  \\/  | ____|  _ \\ / \\",
        "| |   | |_| || || |\\/| |  _| | |_) / _ \\",
        "| |___|  _  || || |  | | |___|  _ < ___ \\",
        " \\____|_| |_|___|_|  |_|_____|_| \\_\\_/   \\_\\",
        "",
        "AI-assisted terminal interface",
        target_line.as_str(),
    ];
    for line in lines {
        println!("\x1b[32m{}\x1b[0m", line);
        std::thread::sleep(Duration::from_millis(40));
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
    let theme = Theme::from_name(crate::theme::ThemeName::Matrix);

    let result = loop {
        if let Some(state) = fetch()? {
            terminal.draw(|frame| draw_dashboard(frame, &state, &theme))?;
        }

        if crossterm::event::poll(Duration::from_millis(200))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
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

pub fn run_console<F, T>(app: &mut App, mut handle_effect: F) -> Result<ConsoleExit<T>>
where
    F: FnMut(Effect, &mut App) -> Result<Option<ConsoleExit<T>>>,
{
    if !should_use_tui() {
        return Ok(ConsoleExit::Quit);
    }

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut events = EventHandler::new(Duration::from_millis(250));
    let mut last_refresh = Instant::now() - Duration::from_secs(1);

    let result = loop {
        if last_refresh.elapsed() >= Duration::from_millis(900) {
            if let Some(exit) = dispatch(app, Action::Refresh, &mut handle_effect)? {
                break Ok(exit);
            }
            last_refresh = Instant::now();
        }

        let theme = Theme::from_name(app.theme);
        terminal.draw(|frame| ui::draw(frame, app, &theme))?;

        if !app.running {
            break Ok(ConsoleExit::Quit);
        }

        match events.next()? {
            Event::Tick => {
                if let Some(exit) = dispatch(app, Action::Tick, &mut handle_effect)? {
                    break Ok(exit);
                }
            }
            Event::Resize => {}
            Event::Key(key) => {
                if let Some(action) = map_key_event(app.mode, key) {
                    if let Some(exit) = dispatch(app, action, &mut handle_effect)? {
                        break Ok(exit);
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn dispatch<T, F>(
    app: &mut App,
    action: Action,
    handle_effect: &mut F,
) -> Result<Option<ConsoleExit<T>>>
where
    F: FnMut(Effect, &mut App) -> Result<Option<ConsoleExit<T>>>,
{
    let effects = app.update(action)?;
    for effect in effects {
        if let Some(exit) = handle_effect(effect, app)? {
            return Ok(Some(exit));
        }
    }
    Ok(None)
}

fn map_key_event(mode: Mode, key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return Some(Action::Quit);
    }

    match mode {
        Mode::Help => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => Some(Action::HideHelp),
            _ => None,
        },
        Mode::Command | Mode::Nlp => match key.code {
            KeyCode::Esc => Some(Action::ExitInputMode),
            KeyCode::Enter => Some(Action::SubmitInput),
            KeyCode::Backspace => Some(Action::PopInput),
            KeyCode::Up => Some(Action::HistoryPrev),
            KeyCode::Down => Some(Action::HistoryNext),
            KeyCode::Char('?') => Some(Action::ShowHelp),
            KeyCode::Tab => Some(Action::PushInput(' ')),
            KeyCode::Char(ch) => Some(Action::PushInput(ch)),
            _ => None,
        },
        Mode::Normal => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(Action::Back),
            KeyCode::Char('?') => Some(Action::ShowHelp),
            KeyCode::Char(':') => Some(Action::EnterCommandMode(None)),
            KeyCode::Char('/') => Some(Action::EnterNlpMode),
            KeyCode::Tab | KeyCode::Right => Some(Action::FocusNext),
            KeyCode::BackTab | KeyCode::Left => Some(Action::FocusPrev),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::MoveUp),
            KeyCode::Char('r') => Some(Action::Refresh),
            KeyCode::Enter => Some(Action::Select),
            _ => None,
        },
    }
}

fn draw_dashboard(frame: &mut Frame, state: &DashboardState, theme: &Theme) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(layout[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[1]);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "CHIMERA ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("// Live Monitor", Style::default().fg(theme.text)),
        ]),
        Line::from(format!(
            "run={}   pipeline={}   target={}",
            state.run_id, state.pipeline, state.title
        )),
        Line::from(format!("phase={}   q=disconnect", state.phase)),
    ])
    .block(
        Block::default()
            .title("Run Monitor")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent)),
    );
    frame.render_widget(header, layout[0]);

    let status_lines = render_status_block(&state.status, state.run_detail.as_ref());
    let status = Paragraph::new(status_lines.join("\n"))
        .block(
            Block::default()
                .title("Run State")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent_alt)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(status, body[0]);

    let event_items = state
        .events
        .iter()
        .rev()
        .take(16)
        .map(|line| ListItem::new(line.clone()))
        .collect::<Vec<_>>();
    let events = List::new(event_items).block(
        Block::default()
            .title("Telemetry")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent)),
    );
    frame.render_widget(events, right[0]);

    let findings = Paragraph::new(
        render_finding_lines(&state.findings, (right[1].width as usize).saturating_sub(6))
            .join("\n"),
    )
    .block(
        Block::default()
            .title("Confirmed Findings")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(findings, right[1]);

    let footer = Paragraph::new("Live scan monitor active. Findings remain replayable.").block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.muted)),
    );
    frame.render_widget(footer, layout[2]);
}

const MATRIX_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*!?<>/\\[]{}|=+-_";
const BIG_SPLASH_LOGO: &[&str] = &[
    " ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗ ",
    "██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗",
    "██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║",
    "██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║",
    "╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║",
    " ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝",
];
const SMALL_SPLASH_LOGO: &[&str] = &[
    "  ____ _   _ ___ __  __ _____ ____   _",
    " / ___| | | |_ _|  \\/  | ____|  _ \\ / \\",
    "| |   | |_| || || |\\/| |  _| | |_) / _ \\",
    "| |___|  _  || || |  | | |___|  _ < ___ \\",
    " \\____|_| |_|___|_|  |_|_____|_| \\_\\_/   \\_\\",
];

#[derive(Debug, Clone)]
struct RainColumn {
    head: i16,
    length: u16,
    speed: u16,
}

#[derive(Debug, Clone)]
struct StartupSplash {
    seed: u64,
    frame: u64,
    columns: Vec<RainColumn>,
    show_help: bool,
}

impl Default for StartupSplash {
    fn default() -> Self {
        Self {
            seed: 0xC0FFEE_5EED_u64,
            frame: 0,
            columns: Vec::new(),
            show_help: false,
        }
    }
}

impl StartupSplash {
    fn ensure_columns(&mut self, width: u16, height: u16) {
        if self.columns.len() == width as usize {
            return;
        }

        self.columns = (0..width)
            .map(|index| self.make_column(index as usize, height))
            .collect();
    }

    fn tick(&mut self, width: u16, height: u16) {
        self.frame = self.frame.wrapping_add(1);
        self.ensure_columns(width, height);

        for idx in 0..self.columns.len() {
            let speed = self.columns[idx].speed.max(1) as u64;
            if !(self.frame + idx as u64).is_multiple_of(speed) {
                continue;
            }

            self.columns[idx].head += 1;
            if self.columns[idx].head - self.columns[idx].length as i16 > height as i16 {
                self.columns[idx] = self.make_column(idx, height);
            }
        }
    }

    fn make_column(&mut self, offset: usize, height: u16) -> RainColumn {
        let height = height.max(10) as i16;
        RainColumn {
            head: -((self.next_u32() as i16 % height) + (offset as i16 % 7)),
            length: 6 + (self.next_u32() % 12) as u16,
            speed: 1 + (self.next_u32() % 4) as u16,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed as u32
    }

    fn glyph(&self, x: u16, y: u16) -> char {
        let idx = ((x as usize * 31) + (y as usize * 17) + (self.frame as usize * 13))
            % MATRIX_CHARS.len();
        MATRIX_CHARS[idx] as char
    }
}

fn startup_matrix_enabled() -> bool {
    !matches!(
        env::var("CHIMERA_MATRIX")
            .unwrap_or_else(|_| "1".to_string())
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no"
    )
}

fn draw_startup_splash(frame: &mut Frame, splash: &mut StartupSplash, theme: &Theme) {
    let area = frame.area();
    splash.ensure_columns(area.width, area.height);

    let mut lines = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let mut spans = Vec::with_capacity(area.width as usize);
        for x in 0..area.width {
            let column = &splash.columns[x as usize];
            let head = column.head;
            let row = y as i16;
            if row <= head && row > head - column.length as i16 {
                let distance = (head - row) as u16;
                let color = match distance {
                    0 => Color::White,
                    1..=2 => theme.accent,
                    3..=5 => theme.accent_alt,
                    _ => theme.muted,
                };
                spans.push(Span::styled(
                    splash.glyph(x, y).to_string(),
                    Style::default().fg(color),
                ));
            } else {
                spans.push(Span::styled(" ", Style::default().bg(Color::Black)));
            }
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), area);

    let card = centered_rect(84, 56, area);
    frame.render_widget(Clear, card);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.panel_alt)),
        card,
    );

    let inner = Rect {
        x: card.x.saturating_add(2),
        y: card.y.saturating_add(1),
        width: card.width.saturating_sub(4),
        height: card.height.saturating_sub(2),
    };

    let logo = if inner.width >= 68 {
        BIG_SPLASH_LOGO
    } else {
        SMALL_SPLASH_LOGO
    };
    render_logo_layer(
        frame,
        shifted_rect(inner, 2, 1),
        logo,
        Style::default().fg(theme.muted),
    );
    render_logo_layer(
        frame,
        shifted_rect(inner, 1, 0),
        logo,
        Style::default().fg(theme.accent_alt),
    );
    render_logo_layer(
        frame,
        inner,
        logo,
        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
    );

    let subtitle_y = inner.y.saturating_add(logo.len() as u16).saturating_add(1);
    let subtitle_area = Rect {
        x: inner.x,
        y: subtitle_y,
        width: inner.width,
        height: 3,
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "AI-assisted terminal interface",
                Style::default().fg(theme.text),
            )),
            Line::from(Span::styled(
                "[1] Continue   [Enter] Continue   [?] Help   [q] Quit",
                Style::default().fg(theme.accent),
            )),
        ]),
        subtitle_area,
    );

    if splash.show_help {
        let help = centered_rect(48, 34, area);
        frame.render_widget(Clear, help);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "Startup",
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from("1 or Enter opens the Chimera operator console."),
                Line::from("? toggles this help."),
                Line::from("q or Esc exits before the console loads."),
                Line::from("Set CHIMERA_MATRIX=0 to skip this startup splash."),
            ])
            .block(
                Block::default()
                    .title("Help")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.accent_alt)),
            )
            .wrap(Wrap { trim: true }),
            help,
        );
    }
}

fn render_logo_layer(frame: &mut Frame, area: Rect, logo: &[&str], style: Style) {
    let lines = logo
        .iter()
        .map(|line| Line::from(Span::styled((*line).to_string(), style)))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn shifted_rect(area: Rect, dx: u16, dy: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(dx),
        y: area.y.saturating_add(dy),
        width: area.width.saturating_sub(dx),
        height: area.height.saturating_sub(dy),
    }
}
