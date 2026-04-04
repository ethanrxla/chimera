use crate::app::{App, FocusedPane};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
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
        .cloned()
        .map(Line::from)
        .collect::<Vec<_>>();

    let widget = Paragraph::new(visible)
        .block(
            Block::default()
                .title("Output / Logs")
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
