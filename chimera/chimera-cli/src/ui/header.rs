use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let status_color = if app.status.error {
        theme.danger
    } else {
        theme.success
    };
    let content = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "CHIMERA",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" // Operator Console", Style::default().fg(theme.text)),
            Span::styled(
                format!("   [{}]", app.mode.label()),
                Style::default()
                    .fg(theme.accent_alt)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!(
            "Focus: {}   Theme: {}   Model: {}   Workflow: {}",
            app.focus.label(),
            app.theme.label(),
            app.connection_label(),
            app.workflow.label()
        )),
        Line::from(vec![
            Span::styled(
                format!("Target: {}   ", app.target.as_deref().unwrap_or("not set")),
                Style::default().fg(theme.text),
            ),
            Span::styled(
                format!("Status: {}", app.status.text),
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .block(
        Block::default()
            .title("Console")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent)),
    );

    frame.render_widget(content, area);
}
