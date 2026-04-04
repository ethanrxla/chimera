use crate::app::{App, FocusedPane};
use crate::render::stat_u64;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

pub fn render_context(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let lines = app
        .context_lines()
        .into_iter()
        .map(|line| {
            if line.starts_with("- ") {
                let body = line.trim_start_matches("- ").to_string();
                Line::from(vec![
                    Span::styled("- ", Style::default().fg(theme.accent_alt)),
                    Span::styled(body, Style::default().fg(theme.text)),
                ])
            } else {
                Line::from(Span::styled(line, Style::default().fg(theme.text)))
            }
        })
        .collect::<Vec<_>>();

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Context")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if app.focus == FocusedPane::Main {
                    theme.accent
                } else {
                    theme.muted
                })),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(widget, area);
}

pub fn render_runs(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let items = if app.snapshot.runs.is_empty() {
        vec![ListItem::new("No runs available")]
    } else {
        app.snapshot
            .runs
            .iter()
            .take(10)
            .map(|run| {
                let findings = stat_u64(&run.stats, "findings_total");
                let chains = stat_u64(&run.stats, "exploit_chains");
                ListItem::new(format!(
                    "{}  {:<10}  f={} c={}",
                    abbreviate(&run.run_id, 12),
                    run.status,
                    findings,
                    chains
                ))
            })
            .collect()
    };

    let mut state = ListState::default();
    if !app.snapshot.runs.is_empty() {
        state.select(Some(app.highlighted_run.min(app.snapshot.runs.len() - 1)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title("Recent Runs")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if app.focus == FocusedPane::Main {
                    theme.accent_alt
                } else {
                    theme.muted
                })),
        )
        .highlight_style(
            Style::default()
                .fg(theme.highlight_fg)
                .bg(theme.panel_alt)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state);
}

fn abbreviate(value: &str, width: usize) -> String {
    if value.len() <= width {
        return value.to_string();
    }
    let keep = width.saturating_sub(3);
    format!("{}...", &value[..keep])
}
