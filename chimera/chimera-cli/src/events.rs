use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use std::time::{Duration, Instant};

pub enum Event {
    Tick,
    Key(KeyEvent),
    Resize,
}

pub struct EventHandler {
    tick_rate: Duration,
    last_tick: Instant,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self {
            tick_rate,
            last_tick: Instant::now(),
        }
    }

    pub fn next(&mut self) -> Result<Event> {
        let timeout = self
            .tick_rate
            .checked_sub(self.last_tick.elapsed())
            .unwrap_or_default();

        if event::poll(timeout)? {
            match event::read()? {
                CrosstermEvent::Key(key)
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    return Ok(Event::Key(key));
                }
                CrosstermEvent::Resize(_, _) => return Ok(Event::Resize),
                _ => {}
            }
        }

        if self.last_tick.elapsed() >= self.tick_rate {
            self.last_tick = Instant::now();
            return Ok(Event::Tick);
        }

        Ok(Event::Tick)
    }
}
