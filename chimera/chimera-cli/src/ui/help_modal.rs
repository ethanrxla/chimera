use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = centered_rect(74, 72, frame.area());
    frame.render_widget(Clear, area);

    let lines = app
        .help_lines()
        .into_iter()
        .map(|line| {
            if line == "Modes" || line == "Examples" {
                Line::from(Span::styled(
                    line,
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(line, Style::default().fg(theme.text)))
            }
        })
        .collect::<Vec<_>>();

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
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
