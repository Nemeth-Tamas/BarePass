mod app;
mod crypto;
mod model;
mod storage;
mod ui;

use std::{error::Error, io, time::Duration};

use app::App;
use crossterm::cursor::Show;
#[cfg(target_os = "macos")]
use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

struct TerminalCleanupGuard {
    active: bool,
    #[cfg(target_os = "macos")]
    keyboard_enhancement_enabled: bool,
}

impl TerminalCleanupGuard {
    fn new() -> Self {
        Self {
            active: true,
            #[cfg(target_os = "macos")]
            keyboard_enhancement_enabled: false,
        }
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        let mut first_error = None;

        #[cfg(target_os = "macos")]
        if self.keyboard_enhancement_enabled {
            if let Err(error) = execute!(io::stdout(), PopKeyboardEnhancementFlags) {
                first_error = Some(error);
            }

            self.keyboard_enhancement_enabled = false;
        }

        if let Err(error) = disable_raw_mode()
            && first_error.is_none()
        {
            first_error = Some(error);
        }

        if let Err(error) = execute!(io::stdout(), LeaveAlternateScreen, Show)
            && first_error.is_none()
        {
            first_error = Some(error);
        }

        self.active = false;

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for TerminalCleanupGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut cleanup = TerminalCleanupGuard::new();

    #[cfg(target_os = "macos")]
    let keyboard_enhancement_enabled =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    #[cfg(target_os = "macos")]
    if keyboard_enhancement_enabled {
        execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
        cleanup.keyboard_enhancement_enabled = true;
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let run_result = run_app(&mut terminal);

    drop(terminal);
    cleanup.restore()?;

    run_result
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), Box<dyn Error>> {
    let mut app = App::new();

    loop {
        terminal.draw(|frame| ui::draw(frame, &app))?;

        if app.should_quit() {
            break;
        }

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    Ok(())
}
