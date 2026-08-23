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
