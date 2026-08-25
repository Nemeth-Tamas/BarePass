use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeserializeError, IgnoredAny, MapAccess, Visitor},
    ser::SerializeStruct,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const CURRENT_VAULT_FORMAT_VERSION: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Vault {
    pub(crate) format_version: u32,
    pub(crate) created_unix: u64,
    pub(crate) updated_unix: u64,
    pub(crate) entries: Vec<PasswordEntry>,
    pub(crate) notes: Vec<SecureNote>,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum VaultItemRef<'a> {
    Password(&'a PasswordEntry),
    SecureNote(&'a SecureNote),
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
enum VaultItemOwned {
    Password(PasswordEntry),
    SecureNote(SecureNote),
}

impl Serialize for Vault {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let items: Vec<_> = self
            .entries
            .iter()
            .map(VaultItemRef::Password)
            .chain(self.notes.iter().map(VaultItemRef::SecureNote))
            .collect();
        let mut vault = serializer.serialize_struct("Vault", 4)?;

        vault.serialize_field("format_version", &CURRENT_VAULT_FORMAT_VERSION)?;
        vault.serialize_field("created_unix", &self.created_unix)?;
        vault.serialize_field("updated_unix", &self.updated_unix)?;
        vault.serialize_field("items", &items)?;
        vault.end()
    }
}

impl<'de> Deserialize<'de> for Vault {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VaultVisitor)
    }
}

struct VaultVisitor;

impl<'de> Visitor<'de> for VaultVisitor {
    type Value = Vault;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a BarePass vault payload")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut format_version = None;
        let mut created_unix = None;
        let mut updated_unix = None;
        let mut legacy_entries: Option<Vec<PasswordEntry>> = None;
        let mut items: Option<Vec<VaultItemOwned>> = None;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "format_version" => {
                    if format_version.is_some() {
                        return Err(M::Error::duplicate_field("format_version"));
                    }
                    format_version = Some(map.next_value::<u32>()?);
                }
                "created_unix" => {
                    if created_unix.is_some() {
                        return Err(M::Error::duplicate_field("created_unix"));
                    }
                    created_unix = Some(map.next_value::<u64>()?);
                }
                "updated_unix" => {
                    if updated_unix.is_some() {
                        return Err(M::Error::duplicate_field("updated_unix"));
                    }
                    updated_unix = Some(map.next_value::<u64>()?);
                }
                "entries" => {
                    if legacy_entries.is_some() {
                        return Err(M::Error::duplicate_field("entries"));
                    }
                    legacy_entries = Some(map.next_value::<Vec<PasswordEntry>>()?);
                }
                "items" => {
                    if items.is_some() {
                        return Err(M::Error::duplicate_field("items"));
                    }
                    items = Some(map.next_value::<Vec<VaultItemOwned>>()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let format_version =
            format_version.ok_or_else(|| M::Error::missing_field("format_version"))?;
        let created_unix = created_unix.ok_or_else(|| M::Error::missing_field("created_unix"))?;
        let updated_unix = updated_unix.ok_or_else(|| M::Error::missing_field("updated_unix"))?;

        let (entries, notes) = match format_version {
            1 => {
                if items.is_some() {
                    return Err(M::Error::custom(
                        "vault format 1 cannot contain generic items",
                    ));
                }

                (legacy_entries.unwrap_or_default(), Vec::new())
            }
            CURRENT_VAULT_FORMAT_VERSION => {
                if legacy_entries.is_some() {
                    return Err(M::Error::custom(
                        "vault format 2 cannot contain legacy entries",
                    ));
                }

                let mut entries = Vec::new();
                let mut notes = Vec::new();

                for item in items.unwrap_or_default() {
                    match item {
                        VaultItemOwned::Password(entry) => entries.push(entry),
                        VaultItemOwned::SecureNote(note) => notes.push(note),
                    }
                }

                (entries, notes)
            }
            unsupported => {
                return Err(M::Error::custom(format!(
                    "unsupported vault payload format version {unsupported}"
                )));
            }
        };

        Ok(Vault {
            format_version: CURRENT_VAULT_FORMAT_VERSION,
            created_unix,
            updated_unix,
            entries,
            notes,
        })
    }
}

impl Vault {
    pub(crate) fn new() -> Self {
        let now = now_unix();

        Self {
            format_version: CURRENT_VAULT_FORMAT_VERSION,
            created_unix: now,
            updated_unix: now,
            entries: Vec::new(),
            notes: Vec::new(),
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
        let mut title = Zeroizing::new(title);
        let mut username = Zeroizing::new(username);
        let mut password = Zeroizing::new(password);
        let mut url = Zeroizing::new(url);
        let mut notes = Zeroizing::new(notes);

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
            title: std::mem::take(&mut *title),
            username: std::mem::take(&mut *username),
            password: std::mem::take(&mut *password),
            url: std::mem::take(&mut *url),
            notes: std::mem::take(&mut *notes),
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
        let mut title = Zeroizing::new(title);
        let mut username = Zeroizing::new(username);
        let mut password = Zeroizing::new(password);
        let mut url = Zeroizing::new(url);
        let mut notes = Zeroizing::new(notes);

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

        entry.title = std::mem::take(&mut *title);
        entry.username = std::mem::take(&mut *username);
        entry.password = std::mem::take(&mut *password);
        entry.url = std::mem::take(&mut *url);
        entry.notes = std::mem::take(&mut *notes);

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

    pub(crate) fn permanently_delete_password_entry(
        &mut self,
        id: u64,
    ) -> Result<(usize, PasswordEntry), String> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id && entry.deleted_unix.is_some())
            .ok_or_else(|| format!("deleted password entry #{id} was not found"))?;

        let entry = self.entries.remove(index);
        self.updated_unix = now_unix();

        Ok((index, entry))
    }

    pub(crate) fn permanently_delete_all_deleted_entries(&mut self) -> Vec<(usize, PasswordEntry)> {
        let mut removed = Vec::new();

        for index in (0..self.entries.len()).rev() {
            if self.entries[index].deleted_unix.is_some() {
                removed.push((index, self.entries.remove(index)));
            }
        }

        if !removed.is_empty() {
            self.updated_unix = now_unix();
        }

        removed
    }

    pub(crate) fn purge_deleted_before(&mut self, cutoff_unix: u64) -> Vec<(usize, PasswordEntry)> {
        let mut removed = Vec::new();

        for index in (0..self.entries.len()).rev() {
            if self.entries[index]
                .deleted_unix
                .is_some_and(|deleted_unix| deleted_unix <= cutoff_unix)
            {
                removed.push((index, self.entries.remove(index)));
            }
        }

        if !removed.is_empty() {
            self.updated_unix = now_unix();
        }

        removed
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SecureNote {
    pub(crate) id: u64,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) deleted_unix: Option<u64>,
}

impl Drop for SecureNote {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
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
    fn new_vault_uses_the_current_generic_item_format_version() {
        let vault = Vault::new();

        assert_eq!(vault.format_version, CURRENT_VAULT_FORMAT_VERSION);
    }

    #[test]
    fn current_vault_serialization_uses_tagged_generic_items() {
        let mut vault = Vault::new();

        vault
            .add_password_entry(
                "Serialized login".into(),
                "user@example.test".into(),
                "test-secret".into(),
                "https://example.test".into(),
                "test notes".into(),
            )
            .unwrap();

        vault.notes.push(SecureNote {
            id: 2,
            title: "Recovery codes".into(),
            body: "encrypted note contents".into(),
            deleted_unix: None,
        });

        let serialized = serde_json::to_string(&vault).unwrap();

        assert!(serialized.contains("\"format_version\":2"));
        assert!(serialized.contains("\"items\":[{\"type\":\"password\",\"data\":"));
        assert!(serialized.contains("\"type\":\"secure_note\""));
        assert!(!serialized.contains("\"entries\":"));

        let reopened: Vault = serde_json::from_str(&serialized).unwrap();

        assert_eq!(reopened, vault);
    }

    #[test]
    fn legacy_v1_entries_migrate_into_the_current_generic_item_model() {
        let legacy = r#"{
            "format_version": 1,
            "created_unix": 10,
            "updated_unix": 20,
            "entries": [
                {
                    "id": 7,
                    "title": "Legacy login",
                    "username": "legacy-user",
                    "password": "legacy-password",
                    "url": "https://legacy.example",
                    "notes": "legacy notes",
                    "deleted_unix": null
                }
            ]
        }"#;

        let vault: Vault = serde_json::from_str(legacy).unwrap();

        assert_eq!(vault.format_version, CURRENT_VAULT_FORMAT_VERSION);
        assert_eq!(vault.created_unix, 10);
        assert_eq!(vault.updated_unix, 20);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].id, 7);
        assert_eq!(vault.entries[0].title, "Legacy login");
        assert_eq!(vault.entries[0].password, "legacy-password");
        assert!(vault.notes.is_empty());

        let migrated = serde_json::to_string(&vault).unwrap();
        assert!(migrated.contains("\"format_version\":2"));
        assert!(migrated.contains("\"type\":\"password\""));
        assert!(!migrated.contains("\"entries\":"));
    }

    #[test]
    fn unsupported_payload_format_versions_are_rejected() {
        let unsupported = r#"{
            "format_version": 99,
            "created_unix": 0,
            "updated_unix": 0,
            "items": []
        }"#;

        assert!(serde_json::from_str::<Vault>(unsupported).is_err());
    }

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

    #[test]
    fn permanent_delete_only_removes_an_entry_after_soft_delete() {
        let mut vault = Vault::new();

        let id = vault
            .add_password_entry(
                "Disposable account".into(),
                "delete-this-user".into(),
                "delete-this-password".into(),
                "https://delete.example".into(),
                "delete these notes".into(),
            )
            .unwrap();

        assert!(vault.permanently_delete_password_entry(id).is_err());

        vault.move_password_entry_to_deleted(id).unwrap();

        let (index, removed) = vault.permanently_delete_password_entry(id).unwrap();

        assert_eq!(index, 0);
        assert!(vault.entries.is_empty());
        assert_eq!(removed.id, id);
        assert_eq!(removed.title, "Disposable account");
        assert_eq!(removed.username, "delete-this-user");
        assert_eq!(removed.password, "delete-this-password");
        assert_eq!(removed.url, "https://delete.example");
        assert_eq!(removed.notes, "delete these notes");
        assert!(removed.deleted_unix.is_some());
    }

    #[test]
    fn empty_recently_deleted_removes_only_deleted_entries() {
        let mut vault = Vault::new();

        let active_id = vault
            .add_password_entry(
                "Keep me".into(),
                "active-user".into(),
                "active-password".into(),
                "https://active.example".into(),
                "active notes".into(),
            )
            .unwrap();

        let deleted_one = vault
            .add_password_entry(
                "Delete one".into(),
                "deleted-one".into(),
                "deleted-password-one".into(),
                "https://deleted-one.example".into(),
                String::new(),
            )
            .unwrap();

        let deleted_two = vault
            .add_password_entry(
                "Delete two".into(),
                "deleted-two".into(),
                "deleted-password-two".into(),
                "https://deleted-two.example".into(),
                String::new(),
            )
            .unwrap();

        vault.move_password_entry_to_deleted(deleted_one).unwrap();
        vault.move_password_entry_to_deleted(deleted_two).unwrap();

        let removed = vault.permanently_delete_all_deleted_entries();

        assert_eq!(removed.len(), 2);
        assert_eq!(removed[0].0, 2);
        assert_eq!(removed[1].0, 1);
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].id, active_id);
        assert_eq!(vault.entries[0].title, "Keep me");
        assert_eq!(vault.entries[0].deleted_unix, None);
    }

    #[test]
    fn purge_deleted_before_removes_only_expired_deleted_entries() {
        let mut vault = Vault::new();

        let active_id = vault
            .add_password_entry(
                "Active".into(),
                "active-user".into(),
                "active-password".into(),
                String::new(),
                String::new(),
            )
            .unwrap();

        let expired_id = vault
            .add_password_entry(
                "Expired deleted".into(),
                "expired-user".into(),
                "expired-password".into(),
                String::new(),
                String::new(),
            )
            .unwrap();

        let recent_id = vault
            .add_password_entry(
                "Recent deleted".into(),
                "recent-user".into(),
                "recent-password".into(),
                String::new(),
                String::new(),
            )
            .unwrap();

        vault.move_password_entry_to_deleted(expired_id).unwrap();
        vault.move_password_entry_to_deleted(recent_id).unwrap();

        vault
            .entries
            .iter_mut()
            .find(|entry| entry.id == expired_id)
            .unwrap()
            .deleted_unix = Some(100);
        vault
            .entries
            .iter_mut()
            .find(|entry| entry.id == recent_id)
            .unwrap()
            .deleted_unix = Some(200);

        vault.updated_unix = 0;

        let removed = vault.purge_deleted_before(100);

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, 1);
        assert_eq!(removed[0].1.id, expired_id);
        assert_eq!(vault.entries.len(), 2);
        assert_eq!(vault.entries[0].id, active_id);
        assert_eq!(vault.entries[0].deleted_unix, None);
        assert_eq!(vault.entries[1].id, recent_id);
        assert_eq!(vault.entries[1].deleted_unix, Some(200));
        assert!(vault.updated_unix > 0);
    }
}
