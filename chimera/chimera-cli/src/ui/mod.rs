pub mod context;
pub mod footer;
pub mod header;
pub mod help_modal;
pub mod input_bar;
pub mod menu;
pub mod output;

use crate::app::App;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

pub fn draw(frame: &mut Frame, app: &App, theme: &Theme) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(2),
            Constraint::Length(4),
        ])
        .split(frame.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24),
            Constraint::Percentage(36),
            Constraint::Percentage(44),
        ])
        .split(layout[1]);

    let center = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(16), Constraint::Min(8)])
        .split(body[1]);

    header::render(frame, layout[0], app, theme);
    menu::render(frame, body[0], app, theme);
    context::render_context(frame, center[0], app, theme);
    context::render_runs(frame, center[1], app, theme);
    output::render(frame, body[2], app, theme);
    footer::render(frame, layout[2], app, theme);
    input_bar::render(frame, layout[3], app, theme);

    if app.show_help {
        help_modal::render(frame, app, theme);
    }
}
