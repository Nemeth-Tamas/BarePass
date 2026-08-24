use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Vault {
    pub(crate) format_version: u32,
    pub(crate) created_unix: u64,
    pub(crate) updated_unix: u64,
    pub(crate) entries: Vec<PasswordEntry>,
}

impl Vault {
    pub(crate) fn new() -> Self {
        let now = now_unix();

        Self {
            format_version: 1,
            created_unix: now,
            updated_unix: now,
            entries: Vec::new(),
        }
    }

    pub(crate) fn add_password_entry(
        &mut self,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    ) -> Result<u64, String> {
        let id = self
            .entries
            .iter()
            .map(|entry| entry.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| "vault entry ID space exhausted".to_string())?;

        self.entries.push(PasswordEntry {
            id,
            title,
            username,
            password,
            url,
            notes,
            deleted_unix: None,
        });

        self.updated_unix = now_unix();

        Ok(id)
    }

    pub(crate) fn update_password_entry(
        &mut self,
        id: u64,
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    ) -> Result<(), String> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && entry.deleted_unix.is_none())
            .ok_or_else(|| format!("password entry #{id} was not found"))?;

        entry.title.zeroize();
        entry.username.zeroize();
        entry.password.zeroize();
        entry.url.zeroize();
        entry.notes.zeroize();

        entry.title = title;
        entry.username = username;
        entry.password = password;
        entry.url = url;
        entry.notes = notes;

        self.updated_unix = now_unix();

        Ok(())
    }

    pub(crate) fn move_password_entry_to_deleted(&mut self, id: u64) -> Result<u64, String> {
        let deleted_unix = now_unix();

        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && entry.deleted_unix.is_none())
            .ok_or_else(|| format!("password entry #{id} was not found"))?;

        entry.deleted_unix = Some(deleted_unix);
        self.updated_unix = deleted_unix;

        Ok(deleted_unix)
    }

    pub(crate) fn restore_password_entry(&mut self, id: u64) -> Result<(), String> {
        let restored_unix = now_unix();

        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && entry.deleted_unix.is_some())
            .ok_or_else(|| format!("deleted password entry #{id} was not found"))?;

        entry.deleted_unix = None;
        self.updated_unix = restored_unix;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PasswordEntry {
    pub(crate) id: u64,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    pub(crate) deleted_unix: Option<u64>,
}

impl Drop for PasswordEntry {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_entries_receive_unique_monotonic_ids() {
        let mut vault = Vault::new();

        let first = vault
            .add_password_entry(
                "GitHub".into(),
                "first@example.test".into(),
                "first-secret".into(),
                "https://github.com".into(),
                String::new(),
            )
            .unwrap();

        let second = vault
            .add_password_entry(
                "GitLab".into(),
                "second@example.test".into(),
                "second-secret".into(),
                "https://gitlab.com".into(),
                String::new(),
            )
            .unwrap();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(vault.entries.len(), 2);
        assert_eq!(vault.entries[0].id, first);
        assert_eq!(vault.entries[1].id, second);
        assert!(
            vault
                .entries
                .iter()
                .all(|entry| entry.deleted_unix.is_none())
        );
    }

    #[test]
    fn editing_password_entry_preserves_id_and_replaces_fields() {
        let mut vault = Vault::new();

        let id = vault
            .add_password_entry(
                "Old title".into(),
                "old-user".into(),
                "old-password".into(),
                "https://old.example".into(),
                "old notes".into(),
            )
            .unwrap();

        vault.updated_unix = 0;

        vault
            .update_password_entry(
                id,
                "New title".into(),
                "new-user".into(),
                "new-password".into(),
                "https://new.example".into(),
                "new notes".into(),
            )
            .unwrap();

        let entry = &vault.entries[0];

        assert_eq!(entry.id, id);
        assert_eq!(entry.title, "New title");
        assert_eq!(entry.username, "new-user");
        assert_eq!(entry.password, "new-password");
        assert_eq!(entry.url, "https://new.example");
        assert_eq!(entry.notes, "new notes");
        assert_eq!(entry.deleted_unix, None);
        assert!(vault.updated_unix > 0);
    }

    #[test]
    fn deleting_password_entry_moves_it_to_recently_deleted_without_destroying_data() {
        let mut vault = Vault::new();

        let id = vault
            .add_password_entry(
                "Important account".into(),
                "keep-this-user".into(),
                "keep-this-password".into(),
                "https://important.example".into(),
                "keep these notes".into(),
            )
            .unwrap();

        vault.updated_unix = 0;

        let deleted_unix = vault.move_password_entry_to_deleted(id).unwrap();
        let entry = &vault.entries[0];

        assert_eq!(vault.entries.len(), 1);
        assert_eq!(entry.id, id);
        assert_eq!(entry.title, "Important account");
        assert_eq!(entry.username, "keep-this-user");
        assert_eq!(entry.password, "keep-this-password");
        assert_eq!(entry.url, "https://important.example");
        assert_eq!(entry.notes, "keep these notes");
        assert_eq!(entry.deleted_unix, Some(deleted_unix));
        assert_eq!(vault.updated_unix, deleted_unix);
    }
}
