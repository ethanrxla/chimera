use crate::app::{App, Mode};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let content = if matches!(app.mode, Mode::Command | Mode::Nlp) {
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", app.input_prompt()),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    if app.input.is_empty() {
                        " ".to_string()
                    } else {
                        app.input.clone()
                    },
                    Style::default().fg(theme.text),
                ),
            ]),
            Line::from(Span::styled(
                app.input_hint(),
                Style::default().fg(theme.muted),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Press : for commands or / for NLP input.",
                Style::default().fg(theme.text),
            )),
            Line::from(Span::styled(
                app.input_hint(),
                Style::default().fg(theme.muted),
            )),
        ]
    };

    let widget = Paragraph::new(content).block(
        Block::default()
            .title(match app.mode {
                Mode::Command => "Command Bar",
                Mode::Nlp => "NLP Prompt",
                _ => "Input",
            })
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent)),
    );
    frame.render_widget(widget, area);

    let suggestions = app.command_suggestions();
    if matches!(app.mode, Mode::Command) && !suggestions.is_empty() {
        let popup_height = suggestions.len() as u16 + 2;
        let popup_width = area.width.min(40);
        let popup = Rect {
            x: area.x.saturating_add(1),
            y: area.y.saturating_sub(popup_height),
            width: popup_width,
            height: popup_height,
        };
        frame.render_widget(Clear, popup);
        let items = suggestions
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let list = List::new(items).block(
            Block::default()
                .title("Suggestions")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent_alt)),
        );
        frame.render_widget(list, popup);
    }
}
