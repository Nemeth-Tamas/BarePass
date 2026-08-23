use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    model::Vault,
    storage::{UnlockedVault, create_unlocked_vault, load_unlocked_vault, save_unlocked_vault},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Create,
    Confirm,
    Unlock,
    Vault,
}

pub(crate) struct App {
    mode: Mode,
    input: Zeroizing<String>,
    pending_password: Zeroizing<String>,
    vault: Option<UnlockedVault>,
    vault_path: PathBuf,
    status: String,
    should_quit: bool,
}

impl App {
    pub(crate) fn new() -> Self {
        let vault_path = PathBuf::from("barepass.vault");

        let (mode, status) = if vault_path.exists() {
            (
                Mode::Unlock,
                "Encrypted vault found. Enter the master password.".to_string(),
            )
        } else {
            (
                Mode::Create,
                "No vault exists yet. Create a master password.".to_string(),
            )
        };

        Self {
            mode,
            input: Zeroizing::new(String::new()),
            pending_password: Zeroizing::new(String::new()),
            vault: None,
            vault_path,
            status,
            should_quit: false,
        }
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn input_len(&self) -> usize {
        self.input.chars().count()
    }

    pub(crate) fn vault(&self) -> Option<&UnlockedVault> {
        self.vault.as_ref()
    }

    pub(crate) fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    pub(crate) fn status(&self) -> &str {
        &self.status
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match self.mode {
            Mode::Vault => self.handle_vault_key(key),
            Mode::Create | Mode::Confirm | Mode::Unlock => {
                self.handle_secret_key(key);
            }
        }
    }

    fn handle_vault_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('l') => self.lock_vault(),
            _ => {}
        }
    }

    fn handle_secret_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.submit_secret(),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Esc => {
                if self.mode == Mode::Confirm {
                    self.input.zeroize();
                    self.pending_password.zeroize();

                    self.mode = Mode::Create;
                    self.status = "Master password creation cancelled. Start again.".into();
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.input.push(character);
            }
            _ => {}
        }
    }

    fn submit_secret(&mut self) {
        match self.mode {
            Mode::Create => self.begin_confirmation(),
            Mode::Confirm => self.finish_creation(),
            Mode::Unlock => self.unlock_existing(),
            Mode::Vault => {}
        }
    }

    fn begin_confirmation(&mut self) {
        if self.input.chars().count() < 12 {
            self.status = "Use at least 12 characters for the master password.".into();
            return;
        }

        self.pending_password.zeroize();
        self.pending_password.push_str(&self.input);
        self.input.zeroize();

        self.mode = Mode::Confirm;
        self.status = "Type the same master password again.".into();
    }

    fn finish_creation(&mut self) {
        if self.input.as_str() != self.pending_password.as_str() {
            self.input.zeroize();
            self.pending_password.zeroize();

            self.mode = Mode::Create;
            self.status = "Passwords did not match. Start again.".into();

            return;
        }

        let data = Vault::new();

        match create_unlocked_vault(data, self.input.as_str()) {
            Ok(unlocked) => match save_unlocked_vault(&self.vault_path, &unlocked) {
                Ok(()) => {
                    self.vault = Some(unlocked);

                    self.input.zeroize();
                    self.pending_password.zeroize();

                    self.mode = Mode::Vault;
                    self.status = "Vault created, encrypted, written to disk, and unlocked.".into();
                }
                Err(error) => {
                    self.status = format!("Could not save the vault: {error}");
                }
            },
            Err(error) => {
                self.status = format!("Could not create the vault: {error}");
            }
        }
    }

    fn unlock_existing(&mut self) {
        match load_unlocked_vault(&self.vault_path, self.input.as_str()) {
            Ok(unlocked) => {
                self.vault = Some(unlocked);

                self.input.zeroize();
                self.pending_password.zeroize();

                self.mode = Mode::Vault;
                self.status = "Vault unlocked successfully.".into();
            }
            Err(_) => {
                self.input.zeroize();

                self.status = "Unlock failed: wrong master password or damaged vault.".into();
            }
        }
    }

    fn lock_vault(&mut self) {
        self.vault = None;

        self.input.zeroize();
        self.pending_password.zeroize();

        self.mode = Mode::Unlock;
        self.status = "Vault locked. Encryption key cleared from memory.".into();
    }
}
