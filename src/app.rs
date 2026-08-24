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
    EditEntry,
    ConfirmDelete,
    RecentlyDeleted,
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

    fn load_from_entry(&mut self, entry: &PasswordEntry) {
        self.reset();

        self.title.push_str(&entry.title);
        self.username.push_str(&entry.username);
        self.password.push_str(&entry.password);
        self.url.push_str(&entry.url);
        self.notes.push_str(&entry.notes);
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
    deleted_selected: usize,
    add_form: AddEntryForm,
    editing_entry_id: Option<u64>,
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
            deleted_selected: 0,
            add_form: AddEntryForm::new(),
            editing_entry_id: None,
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

    pub(crate) fn deleted_selected_index(&self) -> usize {
        self.deleted_selected
    }

    pub(crate) fn selected_deleted_entry(&self) -> Option<&PasswordEntry> {
        self.vault
            .as_ref()?
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_some())
            .nth(self.deleted_selected)
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
            Mode::RecentlyDeleted => self.handle_recently_deleted_key(key),
            Mode::AddEntry | Mode::EditEntry => self.handle_entry_form_key(key),
            Mode::ConfirmDelete => self.handle_delete_confirmation_key(key),
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
            KeyCode::Char('e') => self.open_edit_entry(),
            KeyCode::Char('d') => self.open_delete_confirmation(),
            KeyCode::Tab => self.open_recently_deleted(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(),
            _ => {}
        }
    }

    fn handle_recently_deleted_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('l') => self.lock_vault(),
            KeyCode::Tab | KeyCode::Esc => {
                self.mode = Mode::Vault;
                self.status = "Returned to active vault.".into();
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.restore_selected_deleted_entry();
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_deleted_selection_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_deleted_selection_down(),
            _ => {}
        }
    }

    fn handle_delete_confirmation_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.move_selected_entry_to_deleted();
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.mode = Mode::Vault;
                self.status = "Delete cancelled.".into();
            }
            _ => {}
        }
    }

    fn handle_entry_form_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        {
            self.save_entry_form();
            return;
        }

        match key.code {
            KeyCode::Esc => {
                let was_editing = self.mode == Mode::EditEntry;

                self.add_form.reset();
                self.editing_entry_id = None;
                self.mode = Mode::Vault;

                self.status = if was_editing {
                    "Password edit cancelled.".into()
                } else {
                    "New password entry cancelled.".into()
                };
            }
            KeyCode::Tab => self.add_form.next_field(),
            KeyCode::BackTab => self.add_form.previous_field(),
            KeyCode::Enter => {
                if self.add_form.field() == AddField::Notes {
                    self.save_entry_form();
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

    fn save_entry_form(&mut self) {
        match self.mode {
            Mode::AddEntry => self.save_add_entry(),
            Mode::EditEntry => self.save_edit_entry(),
            Mode::Create
            | Mode::Confirm
            | Mode::Unlock
            | Mode::Vault
            | Mode::ConfirmDelete
            | Mode::RecentlyDeleted => {}
        }
    }

    fn open_add_entry(&mut self) {
        self.add_form.reset();
        self.editing_entry_id = None;
        self.mode = Mode::AddEntry;
        self.status = "Adding a new password entry.".into();
    }

    fn open_recently_deleted(&mut self) {
        self.deleted_selected = 0;
        self.mode = Mode::RecentlyDeleted;

        let deleted_count = self
            .vault
            .as_ref()
            .map(|vault| {
                vault
                    .data()
                    .entries
                    .iter()
                    .filter(|entry| entry.deleted_unix.is_some())
                    .count()
            })
            .unwrap_or(0);

        self.status = if deleted_count == 0 {
            "Recently Deleted is empty.".into()
        } else {
            format!("Recently Deleted contains {deleted_count} item(s).")
        };
    }

    fn open_delete_confirmation(&mut self) {
        let Some(entry_id) = self.selected_entry().map(|entry| entry.id) else {
            self.status = "There is no password entry selected to delete.".into();
            return;
        };

        self.mode = Mode::ConfirmDelete;
        self.status = format!("Confirm moving password entry #{entry_id} to Recently Deleted.");
    }

    fn open_edit_entry(&mut self) {
        let Some(vault) = self.vault.as_ref() else {
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let Some(entry) = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_none())
            .nth(self.selected)
        else {
            self.status = "There is no password entry selected to edit.".into();
            return;
        };

        let entry_id = entry.id;

        self.add_form.load_from_entry(entry);
        self.editing_entry_id = Some(entry_id);
        self.mode = Mode::EditEntry;
        self.status = format!("Editing password entry #{entry_id}.");
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

    fn move_deleted_selection_up(&mut self) {
        self.deleted_selected = self.deleted_selected.saturating_sub(1);
    }

    fn move_deleted_selection_down(&mut self) {
        let deleted_count = self
            .vault
            .as_ref()
            .map(|vault| {
                vault
                    .data()
                    .entries
                    .iter()
                    .filter(|entry| entry.deleted_unix.is_some())
                    .count()
            })
            .unwrap_or(0);

        if self.deleted_selected + 1 < deleted_count {
            self.deleted_selected += 1;
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
            Mode::Vault
            | Mode::AddEntry
            | Mode::EditEntry
            | Mode::ConfirmDelete
            | Mode::RecentlyDeleted => {}
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
        self.editing_entry_id = None;
        self.mode = Mode::Vault;
        self.status = format!("Password entry #{id} saved to the encrypted vault.");
    }

    fn save_edit_entry(&mut self) {
        let Some(id) = self.editing_entry_id else {
            self.add_form.reset();
            self.mode = Mode::Vault;
            self.status = "No password entry is selected for editing.".into();
            return;
        };

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
            self.editing_entry_id = None;
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        let (old_title, old_username, old_password, old_url, old_notes) = {
            let Some(entry) = vault.data().entries.iter().find(|entry| entry.id == id) else {
                self.add_form.reset();
                self.editing_entry_id = None;
                self.mode = Mode::Vault;
                self.status = format!("Password entry #{id} no longer exists.");
                return;
            };

            (
                Zeroizing::new(entry.title.clone()),
                Zeroizing::new(entry.username.clone()),
                Zeroizing::new(entry.password.clone()),
                Zeroizing::new(entry.url.clone()),
                Zeroizing::new(entry.notes.clone()),
            )
        };

        if let Err(error) = vault
            .data_mut()
            .update_password_entry(id, title, username, password, url, notes)
        {
            self.status = format!("Could not update password entry: {error}");
            return;
        }

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();

            if let Some(entry) = data.entries.iter_mut().find(|entry| entry.id == id) {
                entry.title.zeroize();
                entry.username.zeroize();
                entry.password.zeroize();
                entry.url.zeroize();
                entry.notes.zeroize();

                entry.title.push_str(old_title.as_str());
                entry.username.push_str(old_username.as_str());
                entry.password.push_str(old_password.as_str());
                entry.url.push_str(old_url.as_str());
                entry.notes.push_str(old_notes.as_str());
            }

            data.updated_unix = previous_updated;

            self.status = format!("Could not save edited password entry: {error}");
            return;
        }

        self.add_form.reset();
        self.editing_entry_id = None;
        self.mode = Mode::Vault;
        self.status = format!("Password entry #{id} updated in the encrypted vault.");
    }

    fn move_selected_entry_to_deleted(&mut self) {
        let Some(id) = self.selected_entry().map(|entry| entry.id) else {
            self.mode = Mode::Vault;
            self.status = "There is no password entry selected to delete.".into();
            return;
        };

        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        let previous_deleted = vault
            .data()
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .and_then(|entry| entry.deleted_unix);

        if let Err(error) = vault.data_mut().move_password_entry_to_deleted(id) {
            self.mode = Mode::Vault;
            self.status = format!("Could not delete password entry: {error}");
            return;
        }

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();

            if let Some(entry) = data.entries.iter_mut().find(|entry| entry.id == id) {
                entry.deleted_unix = previous_deleted;
            }

            data.updated_unix = previous_updated;

            self.mode = Mode::Vault;
            self.status = format!("Could not save deleted password entry: {error}");
            return;
        }

        let active_count = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_none())
            .count();

        if self.selected >= active_count {
            self.selected = active_count.saturating_sub(1);
        }

        self.mode = Mode::Vault;
        self.status = format!("Password entry #{id} moved to Recently Deleted.");
    }

    fn restore_selected_deleted_entry(&mut self) {
        let Some((id, previous_deleted)) = self
            .selected_deleted_entry()
            .map(|entry| (entry.id, entry.deleted_unix))
        else {
            self.status = "There is no deleted password entry selected to restore.".into();
            return;
        };

        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        if let Err(error) = vault.data_mut().restore_password_entry(id) {
            self.status = format!("Could not restore password entry: {error}");
            return;
        }

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();

            if let Some(entry) = data.entries.iter_mut().find(|entry| entry.id == id) {
                entry.deleted_unix = previous_deleted;
            }

            data.updated_unix = previous_updated;

            self.status = format!("Could not save restored password entry: {error}");
            return;
        }

        let restored_active_index = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_none())
            .position(|entry| entry.id == id)
            .unwrap_or(0);

        let deleted_count = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_some())
            .count();

        self.selected = restored_active_index;

        if self.deleted_selected >= deleted_count {
            self.deleted_selected = deleted_count.saturating_sub(1);
        }

        self.status =
            format!("Password entry #{id} restored. Tab or Esc returns to the active vault.");
    }

    fn lock_vault(&mut self) {
        self.vault = None;

        self.input.zeroize();
        self.pending_password.zeroize();
        self.add_form.reset();
        self.editing_entry_id = None;

        self.selected = 0;
        self.deleted_selected = 0;
        self.mode = Mode::Unlock;
        self.status = "Vault locked. Encryption key cleared from memory.".into();
    }
}
