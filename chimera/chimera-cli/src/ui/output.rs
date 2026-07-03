use crate::app::{App, FocusedPane};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let max_offset = app.output_lines.len().saturating_sub(inner_height);
    let offset = app.output_scroll.min(max_offset);
    let visible = app
        .output_lines
        .iter()
        .skip(offset)
        .take(inner_height)
        .map(|line| style_output_line(line, theme))
        .collect::<Vec<_>>();

    let widget = Paragraph::new(visible)
        .block(
            Block::default()
                .title(if app.run_is_active() {
                    "Output / Live Telemetry"
                } else {
                    "Output / Logs"
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if app.focus == FocusedPane::Output {
                    theme.accent
                } else {
                    theme.muted
                })),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(widget, area);

    let mut scrollbar_state =
        ScrollbarState::new(app.output_lines.len().max(inner_height)).position(offset);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
    frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}

fn style_output_line(line: &str, theme: &Theme) -> Line<'static> {
    let (prefix, body, prefix_style, body_style) = if let Some(body) = line.strip_prefix("[+] ") {
        (
            "[+] ",
            body,
            Style::default()
                .fg(theme.success)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("[!] ") {
        (
            "[!] ",
            body,
            Style::default()
                .fg(theme.accent_alt)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("[x] ") {
        (
            "[x] ",
            body,
            Style::default()
                .fg(theme.danger)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("[*] ") {
        (
            "[*] ",
            body,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("[cmd] ") {
        (
            "[cmd] ",
            body,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.accent_alt),
        )
    } else if let Some(body) = line.strip_prefix("[ai] ") {
        (
            "[ai] ",
            body,
            Style::default()
                .fg(theme.accent_alt)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("[tool] ") {
        (
            "[tool] ",
            body,
            Style::default()
                .fg(ratatui::style::Color::Cyan)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(ratatui::style::Color::Cyan),
        )
    } else if let Some(body) = line.strip_prefix("[artifact] ") {
        (
            "[artifact] ",
            body,
            Style::default().fg(theme.muted),
            Style::default().fg(theme.text),
        )
    } else if let Some((badge, rest)) = split_severity_badge(line) {
        (
            badge,
            rest,
            Style::default()
                .fg(severity_color(theme, badge))
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else if let Some(body) = line.strip_prefix("oracle: ") {
        (
            "oracle: ",
            body,
            Style::default()
                .fg(theme.accent_alt)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(theme.text),
        )
    } else {
        return Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(theme.text),
        ));
    };

    Line::from(vec![
        Span::styled(prefix.to_string(), prefix_style),
        Span::styled(body.to_string(), body_style),
    ])
}

fn split_severity_badge(line: &str) -> Option<(&str, &str)> {
    for badge in ["[CRIT] ", "[HIGH] ", "[MED] ", "[LOW] ", "[INFO] "] {
        if let Some(rest) = line.strip_prefix(badge) {
            return Some((badge, rest));
        }
    }
    None
}

fn severity_color(theme: &Theme, badge: &str) -> ratatui::style::Color {
    match badge {
        "[CRIT] " | "[HIGH] " => theme.danger,
        "[MED] " => theme.accent_alt,
        "[LOW] " => theme.success,
        _ => theme.accent,
    }
}
