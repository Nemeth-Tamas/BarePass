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
}
