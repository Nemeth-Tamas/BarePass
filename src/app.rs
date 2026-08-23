use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    model::{PasswordEntry, Vault},
    storage::{UnlockedVault, create_unlocked_vault, load_unlocked_vault, save_unlocked_vault},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Create,
    Confirm,
    Unlock,
    Vault,
    AddEntry,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddField {
    Title,
    Username,
    Password,
    Url,
    Notes,
}

impl AddField {
    fn next(self) -> Self {
        match self {
            Self::Title => Self::Username,
            Self::Username => Self::Password,
            Self::Password => Self::Url,
            Self::Url => Self::Notes,
            Self::Notes => Self::Notes,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Title => Self::Title,
            Self::Username => Self::Title,
            Self::Password => Self::Username,
            Self::Url => Self::Password,
            Self::Notes => Self::Url,
        }
    }
}

pub(crate) struct AddEntryForm {
    field: AddField,
    title: String,
    username: String,
    password: Zeroizing<String>,
    url: String,
    notes: String,
}

impl AddEntryForm {
    fn new() -> Self {
        Self {
            field: AddField::Title,
            title: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            url: String::new(),
            notes: String::new(),
        }
    }

    pub(crate) fn field(&self) -> AddField {
        self.field
    }

    pub(crate) fn value(&self, field: AddField) -> &str {
        match field {
            AddField::Title => &self.title,
            AddField::Username => &self.username,
            AddField::Password => self.password.as_str(),
            AddField::Url => &self.url,
            AddField::Notes => &self.notes,
        }
    }

    fn current_value_mut(&mut self) -> &mut String {
        match self.field {
            AddField::Title => &mut self.title,
            AddField::Username => &mut self.username,
            AddField::Password => &mut self.password,
            AddField::Url => &mut self.url,
            AddField::Notes => &mut self.notes,
        }
    }

    fn next_field(&mut self) {
        self.field = self.field.next();
    }

    fn previous_field(&mut self) {
        self.field = self.field.previous();
    }

    fn reset(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();

        self.title.clear();
        self.username.clear();
        self.password.clear();
        self.url.clear();
        self.notes.clear();

        self.field = AddField::Title;
    }
}

impl Drop for AddEntryForm {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
    }
}

pub(crate) struct App {
    mode: Mode,
    input: Zeroizing<String>,
    pending_password: Zeroizing<String>,
    vault: Option<UnlockedVault>,
    vault_path: PathBuf,
    selected: usize,
    add_form: AddEntryForm,
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
            selected: 0,
            add_form: AddEntryForm::new(),
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

    pub(crate) fn selected_index(&self) -> usize {
        self.selected
    }

    pub(crate) fn selected_entry(&self) -> Option<&PasswordEntry> {
        self.vault
            .as_ref()?
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_none())
            .nth(self.selected)
    }

    pub(crate) fn add_form(&self) -> &AddEntryForm {
        &self.add_form
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
            Mode::AddEntry => self.handle_add_entry_key(key),
            Mode::Create | Mode::Confirm | Mode::Unlock => {
                self.handle_secret_key(key);
            }
        }
    }

    fn handle_vault_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('l') => self.lock_vault(),
            KeyCode::Char('a') => self.open_add_entry(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(),
            _ => {}
        }
    }

    fn handle_add_entry_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        {
            self.save_add_entry();
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.add_form.reset();
                self.mode = Mode::Vault;
                self.status = "New password entry cancelled.".into();
            }
            KeyCode::Tab => self.add_form.next_field(),
            KeyCode::BackTab => self.add_form.previous_field(),
            KeyCode::Enter => {
                if self.add_form.field() == AddField::Notes {
                    self.save_add_entry();
                } else {
                    self.add_form.next_field();
                }
            }
            KeyCode::Backspace => {
                self.add_form.current_value_mut().pop();
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.add_form.current_value_mut().push(character);
            }
            _ => {}
        }
    }

    fn open_add_entry(&mut self) {
        self.add_form.reset();
        self.mode = Mode::AddEntry;
        self.status = "Adding a new password entry.".into();
    }

    fn move_selection_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn move_selection_down(&mut self) {
        let active_count = self
            .vault
            .as_ref()
            .map(|vault| {
                vault
                    .data()
                    .entries
                    .iter()
                    .filter(|entry| entry.deleted_unix.is_none())
                    .count()
            })
            .unwrap_or(0);

        if self.selected + 1 < active_count {
            self.selected += 1;
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
            Mode::Vault | Mode::AddEntry => {}
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

    fn save_add_entry(&mut self) {
        let title = self.add_form.value(AddField::Title).trim();

        if title.is_empty() {
            self.add_form.field = AddField::Title;
            self.status = "A password entry needs a title.".into();
            return;
        }

        let title = title.to_string();
        let username = self.add_form.value(AddField::Username).to_string();
        let password = self.add_form.value(AddField::Password).to_string();
        let url = self.add_form.value(AddField::Url).to_string();
        let notes = self.add_form.value(AddField::Notes).to_string();
        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.add_form.reset();
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        let id = match vault
            .data_mut()
            .add_password_entry(title, username, password, url, notes)
        {
            Ok(id) => id,
            Err(error) => {
                self.status = format!("Could not add password entry: {error}");
                return;
            }
        };

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();

            if data.entries.last().is_some_and(|entry| entry.id == id) {
                data.entries.pop();
                data.updated_unix = previous_updated;
            }

            self.status = format!("Could not save password entry: {error}");
            return;
        }

        let active_count = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_none())
            .count();

        self.selected = active_count.saturating_sub(1);
        self.add_form.reset();
        self.mode = Mode::Vault;
        self.status = format!("Password entry #{id} saved to the encrypted vault.");
    }

    fn lock_vault(&mut self) {
        self.vault = None;

        self.input.zeroize();
        self.pending_password.zeroize();
        self.add_form.reset();

        self.selected = 0;
        self.mode = Mode::Unlock;
        self.status = "Vault locked. Encryption key cleared from memory.".into();
    }
}
