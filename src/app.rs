use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    clipboard::{CLIPBOARD_CLEAR_SECS, ClipboardManager},
    model::{PasswordEntry, Vault},
    storage::{
        UnlockedVault, VaultLock, acquire_vault_lock, create_unlocked_vault, load_unlocked_vault,
        prepare_vault_path, save_unlocked_vault,
    },
};

const AUTO_LOCK_ENV: &str = "BAREPASS_AUTO_LOCK_SECS";
const DEFAULT_AUTO_LOCK_SECS: u64 = 300;

fn auto_lock_timeout_from_value(value: Option<&OsStr>) -> Option<Duration> {
    let seconds = value
        .and_then(OsStr::to_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AUTO_LOCK_SECS);

    (seconds != 0).then_some(Duration::from_secs(seconds))
}

fn inactivity_expired(vault_unlocked: bool, timeout: Option<Duration>, idle_for: Duration) -> bool {
    vault_unlocked && timeout.is_some_and(|timeout| idle_for >= timeout)
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let needle = needle.as_bytes();

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn password_entry_matches_search(entry: &PasswordEntry, query: &str) -> bool {
    query.is_empty()
        || contains_ascii_case_insensitive(&entry.title, query)
        || contains_ascii_case_insensitive(&entry.username, query)
        || contains_ascii_case_insensitive(&entry.url, query)
        || contains_ascii_case_insensitive(&entry.notes, query)
}

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
    title: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    url: Zeroizing<String>,
    notes: Zeroizing<String>,
}

impl AddEntryForm {
    fn new() -> Self {
        Self {
            field: AddField::Title,
            title: Zeroizing::new(String::new()),
            username: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            url: Zeroizing::new(String::new()),
            notes: Zeroizing::new(String::new()),
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
            AddField::Title => self.title.as_str(),
            AddField::Username => self.username.as_str(),
            AddField::Password => self.password.as_str(),
            AddField::Url => self.url.as_str(),
            AddField::Notes => self.notes.as_str(),
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

fn delete_previous_word(value: &mut String) {
    while value.chars().next_back().is_some_and(char::is_whitespace) {
        value.pop();
    }

    while value
        .chars()
        .next_back()
        .is_some_and(|character| !character.is_whitespace())
    {
        value.pop();
    }
}

fn clear_text_input(value: &mut String) {
    value.zeroize();
    value.clear();
}

#[cfg(target_os = "macos")]
fn is_delete_word_shortcut(key: &KeyEvent) -> bool {
    key.code == KeyCode::Backspace && key.modifiers.contains(KeyModifiers::ALT)
}

#[cfg(not(target_os = "macos"))]
fn is_delete_word_shortcut(key: &KeyEvent) -> bool {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);

    (control
        && matches!(
            key.code,
            KeyCode::Backspace | KeyCode::Char('h') | KeyCode::Char('w')
        ))
        || matches!(key.code, KeyCode::Char('\u{8}') | KeyCode::Char('\u{17}'))
}

#[cfg(target_os = "macos")]
fn is_clear_input_shortcut(key: &KeyEvent) -> bool {
    key.code == KeyCode::Backspace && key.modifiers.contains(KeyModifiers::SUPER)
}

#[cfg(not(target_os = "macos"))]
fn is_clear_input_shortcut(key: &KeyEvent) -> bool {
    key.code == KeyCode::Delete && key.modifiers.contains(KeyModifiers::CONTROL)
}

pub(crate) struct App {
    mode: Mode,
    input: Zeroizing<String>,
    pending_password: Zeroizing<String>,
    vault: Option<UnlockedVault>,
    vault_lock: Option<VaultLock>,
    vault_path: PathBuf,
    selected: usize,
    deleted_selected: usize,
    add_form: AddEntryForm,
    editing_entry_id: Option<u64>,
    permanent_delete_entry_id: Option<u64>,
    empty_recently_deleted_confirmation: bool,
    status: String,
    search_query: Zeroizing<String>,
    search_editing: bool,
    clipboard: Option<ClipboardManager>,
    auto_lock_timeout: Option<Duration>,
    last_activity: Instant,
    should_quit: bool,
}

impl App {
    pub(crate) fn new() -> Self {
        let legacy_fallback = PathBuf::from("barepass.vault");

        let auto_lock_timeout = auto_lock_timeout_from_value(env::var_os(AUTO_LOCK_ENV).as_deref());

        let (vault_path, storage_notice) = match prepare_vault_path() {
            Ok((path, notice)) => (path, notice),
            Err(error) => (
                legacy_fallback,
                Some(format!(
                    "OS-native vault storage setup failed; using the working directory: {error}"
                )),
            ),
        };

        let (mode, base_status) = if vault_path.exists() {
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

        let status = match storage_notice {
            Some(notice) => format!("{notice} {base_status}"),
            None => base_status,
        };

        Self {
            mode,
            input: Zeroizing::new(String::new()),
            pending_password: Zeroizing::new(String::new()),
            vault: None,
            vault_lock: None,
            vault_path,
            selected: 0,
            deleted_selected: 0,
            add_form: AddEntryForm::new(),
            editing_entry_id: None,
            permanent_delete_entry_id: None,
            empty_recently_deleted_confirmation: false,
            status,
            search_query: Zeroizing::new(String::new()),
            search_editing: false,
            clipboard: None,
            auto_lock_timeout,
            last_activity: Instant::now(),
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
            .filter(|entry| {
                entry.deleted_unix.is_none()
                    && password_entry_matches_search(entry, self.search_query.as_str())
            })
            .nth(self.selected)
    }

    pub(crate) fn entry_matches_search(&self, entry: &PasswordEntry) -> bool {
        password_entry_matches_search(entry, self.search_query.as_str())
    }

    pub(crate) fn search_query(&self) -> &str {
        self.search_query.as_str()
    }

    pub(crate) fn search_editing(&self) -> bool {
        self.search_editing
    }

    pub(crate) fn filtered_active_count(&self) -> usize {
        self.vault
            .as_ref()
            .map(|vault| {
                vault
                    .data()
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.deleted_unix.is_none()
                            && password_entry_matches_search(entry, self.search_query.as_str())
                    })
                    .count()
            })
            .unwrap_or(0)
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

    pub(crate) fn is_permanent_delete_confirmation(&self) -> bool {
        self.permanent_delete_entry_id.is_some()
    }

    pub(crate) fn is_empty_recently_deleted_confirmation(&self) -> bool {
        self.empty_recently_deleted_confirmation
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

    pub(crate) fn auto_lock_seconds(&self) -> Option<u64> {
        self.auto_lock_timeout.map(|timeout| timeout.as_secs())
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }

        self.last_activity = Instant::now();

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

    pub(crate) fn handle_tick(&mut self) {
        if let Some(clipboard) = self.clipboard.as_mut() {
            match clipboard.clear_if_due() {
                Ok(true) => {
                    self.status = "BarePass clipboard text cleared after 30 seconds.".into();
                }
                Ok(false) => {}
                Err(error) => self.status = format!("Could not auto-clear clipboard: {error}"),
            }
        }

        if !inactivity_expired(
            self.vault.is_some(),
            self.auto_lock_timeout,
            self.last_activity.elapsed(),
        ) {
            return;
        }

        let seconds = self
            .auto_lock_timeout
            .map(|timeout| timeout.as_secs())
            .unwrap_or_default();

        self.lock_vault();
        self.status = format!(
            "Vault auto-locked after {seconds} seconds of inactivity. Encryption key cleared from memory."
        );
    }

    fn handle_vault_key(&mut self, key: KeyEvent) {
        if self.search_editing {
            self.handle_search_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('l') => self.lock_vault(),
            KeyCode::Char('/') => {
                self.search_editing = true;
                self.selected = 0;
                self.update_search_status();
            }
            KeyCode::Esc if !self.search_query.is_empty() => {
                self.clear_search();
            }
            KeyCode::Char('a') => self.open_add_entry(),
            KeyCode::Char('e') => self.open_edit_entry(),
            KeyCode::Char('u') => self.copy_selected_username(),
            KeyCode::Char('p') => self.copy_selected_password(),
            KeyCode::Char('d') => self.open_delete_confirmation(),
            KeyCode::Tab => self.open_recently_deleted(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(),
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        if is_delete_word_shortcut(&key) {
            delete_previous_word(&mut self.search_query);
            self.selected = 0;
            self.update_search_status();
            return;
        }

        if is_clear_input_shortcut(&key) {
            clear_text_input(&mut self.search_query);
            self.selected = 0;
            self.update_search_status();
            return;
        }

        match key.code {
            KeyCode::Esc => self.clear_search(),
            KeyCode::Enter => {
                self.search_editing = false;
                self.update_search_status();
            }
            KeyCode::Up => self.move_selection_up(),
            KeyCode::Down => self.move_selection_down(),
            KeyCode::Backspace => {
                self.search_query.pop();
                self.selected = 0;
                self.update_search_status();
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.search_query.push(character);
                self.selected = 0;
                self.update_search_status();
            }
            _ => {}
        }
    }

    fn update_search_status(&mut self) {
        let count = self.filtered_active_count();

        self.status = if self.search_query.is_empty() {
            format!("Search active. {count} password entry(s) available.")
        } else {
            format!("Search filter matches {count} password entry(s).")
        };
    }

    fn clear_search(&mut self) {
        self.search_query.zeroize();
        self.search_query.clear();
        self.search_editing = false;
        self.selected = 0;
        self.status = "Search cleared.".into();
    }

    fn copy_selected_username(&mut self) {
        let username = match self.selected_entry() {
            Some(entry) if !entry.username.is_empty() => Zeroizing::new(entry.username.clone()),
            Some(_) => {
                self.status = "The selected password entry has no username to copy.".into();
                return;
            }
            None => {
                self.status = "There is no password entry selected to copy from.".into();
                return;
            }
        };

        self.copy_text_to_clipboard(username.as_str(), "Username");
    }

    fn copy_selected_password(&mut self) {
        let password = match self.selected_entry() {
            Some(entry) if !entry.password.is_empty() => Zeroizing::new(entry.password.clone()),
            Some(_) => {
                self.status = "The selected password entry has no password to copy.".into();
                return;
            }
            None => {
                self.status = "There is no password entry selected to copy from.".into();
                return;
            }
        };

        self.copy_text_to_clipboard(password.as_str(), "Password");
    }

    fn copy_text_to_clipboard(&mut self, text: &str, label: &str) {
        if self.clipboard.is_none() {
            match ClipboardManager::new() {
                Ok(clipboard) => self.clipboard = Some(clipboard),
                Err(error) => {
                    self.status = format!("Clipboard unavailable: {error}");
                    return;
                }
            }
        }

        let Some(clipboard) = self.clipboard.as_mut() else {
            self.status = "Clipboard unavailable.".into();
            return;
        };

        match clipboard.copy_text(text) {
            Ok(()) => {
                self.status = format!(
                    "{label} copied. BarePass will clear it after {CLIPBOARD_CLEAR_SECS} seconds if the clipboard is unchanged."
                );
            }
            Err(error) => {
                self.status = format!("Could not copy {label}: {error}");
            }
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
            KeyCode::Char('d') => {
                self.open_permanent_delete_confirmation();
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.open_empty_recently_deleted_confirmation();
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_deleted_selection_up(),
            KeyCode::Down | KeyCode::Char('j') => self.move_deleted_selection_down(),
            _ => {}
        }
    }

    fn handle_delete_confirmation_key(&mut self, key: KeyEvent) {
        let empty_all = self.empty_recently_deleted_confirmation;
        let permanent = self.permanent_delete_entry_id.is_some();

        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                if empty_all {
                    self.empty_recently_deleted();
                } else if permanent {
                    self.permanently_delete_selected_entry();
                } else {
                    self.move_selected_entry_to_deleted();
                }
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.mode = if permanent || empty_all {
                    Mode::RecentlyDeleted
                } else {
                    Mode::Vault
                };
                self.permanent_delete_entry_id = None;
                self.empty_recently_deleted_confirmation = false;
                self.status = "Delete cancelled.".into();
            }
            _ => {}
        }
    }

    fn handle_entry_form_key(&mut self, key: KeyEvent) {
        if is_delete_word_shortcut(&key) {
            delete_previous_word(self.add_form.current_value_mut());
            return;
        }

        if is_clear_input_shortcut(&key) {
            clear_text_input(self.add_form.current_value_mut());
            return;
        }

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
        self.search_query.zeroize();
        self.search_query.clear();
        self.search_editing = false;
        self.selected = 0;
        self.add_form.reset();
        self.editing_entry_id = None;
        self.mode = Mode::AddEntry;
        self.status = "Adding a new password entry.".into();
    }

    fn open_recently_deleted(&mut self) {
        self.search_query.zeroize();
        self.search_query.clear();
        self.search_editing = false;
        self.selected = 0;
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

    fn open_empty_recently_deleted_confirmation(&mut self) {
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

        if deleted_count == 0 {
            self.status = "Recently Deleted is already empty.".into();
            return;
        }

        self.permanent_delete_entry_id = None;
        self.empty_recently_deleted_confirmation = true;
        self.mode = Mode::ConfirmDelete;
        self.status = format!(
            "Confirm permanently deleting all {deleted_count} item(s) from Recently Deleted."
        );
    }

    fn open_permanent_delete_confirmation(&mut self) {
        let Some(entry_id) = self.selected_deleted_entry().map(|entry| entry.id) else {
            self.status =
                "There is no deleted password entry selected to permanently delete.".into();
            return;
        };

        self.empty_recently_deleted_confirmation = false;
        self.permanent_delete_entry_id = Some(entry_id);
        self.mode = Mode::ConfirmDelete;
        self.status = format!(
            "Confirm permanently deleting password entry #{entry_id}. This cannot be undone."
        );
    }

    fn open_delete_confirmation(&mut self) {
        let Some(entry_id) = self.selected_entry().map(|entry| entry.id) else {
            self.status = "There is no password entry selected to delete.".into();
            return;
        };

        self.empty_recently_deleted_confirmation = false;
        self.permanent_delete_entry_id = None;
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
            .filter(|entry| {
                entry.deleted_unix.is_none()
                    && password_entry_matches_search(entry, self.search_query.as_str())
            })
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
        let active_count = self.filtered_active_count();

        if self.selected + 1 < active_count {
            self.selected += 1;
        }
    }

    fn clamp_active_selection(&mut self) {
        let active_count = self.filtered_active_count();

        if self.selected >= active_count {
            self.selected = active_count.saturating_sub(1);
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
        if is_delete_word_shortcut(&key) {
            delete_previous_word(&mut self.input);
            return;
        }

        if is_clear_input_shortcut(&key) {
            clear_text_input(&mut self.input);
            return;
        }

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

        let vault_lock = match acquire_vault_lock(&self.vault_path) {
            Ok(lock) => lock,
            Err(error) => {
                self.input.zeroize();
                self.pending_password.zeroize();
                self.status = error;
                return;
            }
        };

        if self.vault_path.exists() {
            self.input.zeroize();
            self.pending_password.zeroize();

            self.mode = Mode::Unlock;
            self.status =
                "A vault appeared while this BarePass process was creating one. Unlock it instead."
                    .into();
            return;
        }

        let data = Vault::new();

        match create_unlocked_vault(data, self.input.as_str()) {
            Ok(unlocked) => match save_unlocked_vault(&self.vault_path, &unlocked) {
                Ok(()) => {
                    self.vault = Some(unlocked);
                    self.vault_lock = Some(vault_lock);
                    self.last_activity = Instant::now();

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
        let vault_lock = match acquire_vault_lock(&self.vault_path) {
            Ok(lock) => lock,
            Err(error) => {
                self.input.zeroize();
                self.status = error;
                return;
            }
        };

        match load_unlocked_vault(&self.vault_path, self.input.as_str()) {
            Ok(unlocked) => {
                self.vault = Some(unlocked);
                self.vault_lock = Some(vault_lock);
                self.last_activity = Instant::now();

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

        let mut title = Zeroizing::new(title.to_string());
        let mut username = Zeroizing::new(self.add_form.value(AddField::Username).to_string());
        let mut password = Zeroizing::new(self.add_form.value(AddField::Password).to_string());
        let mut url = Zeroizing::new(self.add_form.value(AddField::Url).to_string());
        let mut notes = Zeroizing::new(self.add_form.value(AddField::Notes).to_string());
        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.add_form.reset();
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        let id = match vault.data_mut().add_password_entry(
            std::mem::take(&mut *title),
            std::mem::take(&mut *username),
            std::mem::take(&mut *password),
            std::mem::take(&mut *url),
            std::mem::take(&mut *notes),
        ) {
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

        self.selected = self.filtered_active_count().saturating_sub(1);
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

        let mut title = Zeroizing::new(title.to_string());
        let mut username = Zeroizing::new(self.add_form.value(AddField::Username).to_string());
        let mut password = Zeroizing::new(self.add_form.value(AddField::Password).to_string());
        let mut url = Zeroizing::new(self.add_form.value(AddField::Url).to_string());
        let mut notes = Zeroizing::new(self.add_form.value(AddField::Notes).to_string());
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

        if let Err(error) = vault.data_mut().update_password_entry(
            id,
            std::mem::take(&mut *title),
            std::mem::take(&mut *username),
            std::mem::take(&mut *password),
            std::mem::take(&mut *url),
            std::mem::take(&mut *notes),
        ) {
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
        self.clamp_active_selection();
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

        self.clamp_active_selection();
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

    fn permanently_delete_selected_entry(&mut self) {
        let Some(id) = self.permanent_delete_entry_id else {
            self.mode = Mode::RecentlyDeleted;
            self.status =
                "There is no deleted password entry selected to permanently delete.".into();
            return;
        };

        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.permanent_delete_entry_id = None;
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;

        let (removed_index, removed_entry) =
            match vault.data_mut().permanently_delete_password_entry(id) {
                Ok(removed) => removed,
                Err(error) => {
                    self.permanent_delete_entry_id = None;
                    self.mode = Mode::RecentlyDeleted;
                    self.status = format!("Could not permanently delete password entry: {error}");
                    return;
                }
            };

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();
            data.entries.insert(removed_index, removed_entry);
            data.updated_unix = previous_updated;

            self.permanent_delete_entry_id = None;
            self.mode = Mode::RecentlyDeleted;
            self.status = format!("Could not save permanent deletion: {error}");
            return;
        }

        let deleted_count = vault
            .data()
            .entries
            .iter()
            .filter(|entry| entry.deleted_unix.is_some())
            .count();

        if self.deleted_selected >= deleted_count {
            self.deleted_selected = deleted_count.saturating_sub(1);
        }

        self.permanent_delete_entry_id = None;
        self.mode = Mode::RecentlyDeleted;
        self.status = format!("Password entry #{id} permanently deleted.");
    }

    fn empty_recently_deleted(&mut self) {
        if !self.empty_recently_deleted_confirmation {
            self.mode = Mode::RecentlyDeleted;
            self.status = "Recently Deleted empty confirmation is not active.".into();
            return;
        }

        let vault_path = self.vault_path.clone();

        let Some(vault) = self.vault.as_mut() else {
            self.empty_recently_deleted_confirmation = false;
            self.mode = Mode::Unlock;
            self.status = "Vault is no longer unlocked.".into();
            return;
        };

        let previous_updated = vault.data().updated_unix;
        let removed = vault.data_mut().permanently_delete_all_deleted_entries();
        let removed_count = removed.len();

        if removed_count == 0 {
            self.empty_recently_deleted_confirmation = false;
            self.mode = Mode::RecentlyDeleted;
            self.status = "Recently Deleted is already empty.".into();
            return;
        }

        if let Err(error) = save_unlocked_vault(&vault_path, vault) {
            let data = vault.data_mut();

            for (index, entry) in removed.into_iter().rev() {
                data.entries.insert(index, entry);
            }

            data.updated_unix = previous_updated;

            self.empty_recently_deleted_confirmation = false;
            self.mode = Mode::RecentlyDeleted;
            self.status = format!("Could not save empty Recently Deleted operation: {error}");
            return;
        }

        self.deleted_selected = 0;
        self.empty_recently_deleted_confirmation = false;
        self.mode = Mode::RecentlyDeleted;
        self.status = format!("Permanently deleted {removed_count} item(s) from Recently Deleted.");
    }

    fn lock_vault(&mut self) {
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.clear_tracked_now();
        }

        self.vault = None;
        self.vault_lock = None;

        self.input.zeroize();
        self.pending_password.zeroize();
        self.add_form.reset();
        self.editing_entry_id = None;
        self.permanent_delete_entry_id = None;
        self.empty_recently_deleted_confirmation = false;
        self.search_query.zeroize();
        self.search_query.clear();
        self.search_editing = false;

        self.selected = 0;
        self.deleted_selected = 0;
        self.mode = Mode::Unlock;
        self.last_activity = Instant::now();
        self.status = "Vault locked. Encryption key cleared from memory.".into();
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, time::Duration};

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{
        auto_lock_timeout_from_value, clear_text_input, delete_previous_word, inactivity_expired,
        is_delete_word_shortcut, password_entry_matches_search,
    };
    use crate::model::PasswordEntry;

    #[test]
    fn delete_previous_word_handles_unicode_and_trailing_whitespace() {
        let mut value = "alpha béta gamma   ".to_string();

        delete_previous_word(&mut value);
        assert_eq!(value, "alpha béta ");

        delete_previous_word(&mut value);
        assert_eq!(value, "alpha ");

        delete_previous_word(&mut value);
        assert_eq!(value, "");
    }

    #[test]
    fn clear_text_input_removes_the_entire_value() {
        let mut value = "remove everything".to_string();

        clear_text_input(&mut value);

        assert!(value.is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn delete_word_shortcut_accepts_common_terminal_encodings() {
        let backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::CONTROL);
        let ctrl_h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL);
        let ctrl_w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL);
        let raw_backspace = KeyEvent::new(KeyCode::Char('\u{8}'), KeyModifiers::NONE);
        let raw_ctrl_w = KeyEvent::new(KeyCode::Char('\u{17}'), KeyModifiers::NONE);

        assert!(is_delete_word_shortcut(&backspace));
        assert!(is_delete_word_shortcut(&ctrl_h));
        assert!(is_delete_word_shortcut(&ctrl_w));
        assert!(is_delete_word_shortcut(&raw_backspace));
        assert!(is_delete_word_shortcut(&raw_ctrl_w));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn delete_word_shortcut_does_not_capture_plain_backspace() {
        let plain_backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);

        assert!(!is_delete_word_shortcut(&plain_backspace));
    }

    #[test]
    fn auto_lock_configuration_supports_default_override_disable_and_invalid_fallback() {
        assert_eq!(
            auto_lock_timeout_from_value(None),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            auto_lock_timeout_from_value(Some(OsStr::new("15"))),
            Some(Duration::from_secs(15))
        );
        assert_eq!(auto_lock_timeout_from_value(Some(OsStr::new("0"))), None);
        assert_eq!(
            auto_lock_timeout_from_value(Some(OsStr::new("not-a-number"))),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn inactivity_expiration_requires_an_unlocked_vault_and_enabled_timeout() {
        let timeout = Some(Duration::from_secs(5));

        assert!(!inactivity_expired(false, timeout, Duration::from_secs(10)));
        assert!(!inactivity_expired(true, timeout, Duration::from_secs(4)));
        assert!(inactivity_expired(true, timeout, Duration::from_secs(5)));
        assert!(!inactivity_expired(true, None, Duration::from_secs(10)));
    }

    #[test]
    fn search_matches_visible_metadata_but_never_password_contents() {
        let entry = PasswordEntry {
            id: 1,
            title: "GitHub Work".into(),
            username: "Tamas@Example.Test".into(),
            password: "hidden-search-secret".into(),
            url: "https://github.com".into(),
            notes: "Documentation account".into(),
            deleted_unix: None,
        };

        assert!(password_entry_matches_search(&entry, ""));
        assert!(password_entry_matches_search(&entry, "github"));
        assert!(password_entry_matches_search(&entry, "EXAMPLE.TEST"));
        assert!(password_entry_matches_search(&entry, "documentation"));
        assert!(!password_entry_matches_search(
            &entry,
            "hidden-search-secret"
        ));
        assert!(!password_entry_matches_search(&entry, "missing"));
    }
}
