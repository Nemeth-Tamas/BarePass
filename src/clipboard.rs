use std::time::{Duration, Instant};

use arboard::Clipboard;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const CLIPBOARD_CLEAR_SECS: u64 = 30;
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(CLIPBOARD_CLEAR_SECS);

pub(crate) struct ClipboardManager {
    clipboard: Clipboard,
    tracked_text: Zeroizing<String>,
    clear_at: Option<Instant>,
}

impl ClipboardManager {
    pub(crate) fn new() -> Result<Self, String> {
        let clipboard = Clipboard::new()
            .map_err(|error| format!("could not access system clipboard: {error}"))?;

        Ok(Self {
            clipboard,
            tracked_text: Zeroizing::new(String::new()),
            clear_at: None,
        })
    }

    pub(crate) fn copy_text(&mut self, text: &str) -> Result<(), String> {
        self.clipboard
            .set_text(text)
            .map_err(|error| format!("could not copy text to system clipboard: {error}"))?;

        self.tracked_text.zeroize();
        self.tracked_text.clear();
        self.tracked_text.push_str(text);
        self.clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);

        Ok(())
    }

    pub(crate) fn clear_if_due(&mut self) -> Result<bool, String> {
        let Some(clear_at) = self.clear_at else {
            return Ok(false);
        };

        if Instant::now() < clear_at {
            return Ok(false);
        }

        self.clear_tracked_now()
    }

    pub(crate) fn clear_tracked_now(&mut self) -> Result<bool, String> {
        if self.tracked_text.is_empty() {
            self.clear_at = None;
            return Ok(false);
        }

        let current_text = match self.clipboard.get_text() {
            Ok(text) => Zeroizing::new(text),
            Err(_) => {
                self.forget_tracked_text();
                return Ok(false);
            }
        };

        if current_text.as_str() != self.tracked_text.as_str() {
            self.forget_tracked_text();
            return Ok(false);
        }

        self.clipboard
            .clear()
            .map_err(|error| format!("could not clear system clipboard: {error}"))?;

        self.forget_tracked_text();

        Ok(true)
    }

    fn forget_tracked_text(&mut self) {
        self.tracked_text.zeroize();
        self.tracked_text.clear();
        self.clear_at = None;
    }
}

impl Drop for ClipboardManager {
    fn drop(&mut self) {
        let _ = self.clear_tracked_now();
    }
}
