use crate::app::{App, FocusedPane, MenuItem};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let items = MenuItem::ALL
        .iter()
        .map(|item| ListItem::new(item.title()))
        .collect::<Vec<_>>();

    let mut state = ListState::default();
    state.select(Some(app.selected_menu));

    let list = List::new(items)
        .block(
            Block::default()
                .title("Menu")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if app.focus == FocusedPane::Menu {
                    theme.accent
                } else {
                    theme.muted
                })),
        )
        .highlight_style(
            Style::default()
                .fg(theme.highlight_fg)
                .bg(theme.highlight_bg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state);
}
