use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let widget = Paragraph::new(app.footer_hint())
        .style(
            Style::default()
                .fg(theme.muted)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.panel_alt)),
        );
    frame.render_widget(widget, area);
}
