use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use zeroize::Zeroize;

use crate::{
    crypto::{
        CURRENT_KDF, KdfConfig, NONCE_LEN, SALT_LEN, VaultKey, decrypt, derive_key, encrypt,
        random_nonce, random_salt,
    },
    model::Vault,
};

const MAGIC: &[u8; 8] = b"BRPASS01";
const HEADER_LEN: usize = 8 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const MIN_CIPHERTEXT_LEN: usize = 16;

pub(crate) struct UnlockedVault {
    data: Vault,
    key: VaultKey,
    kdf: KdfConfig,
    salt: [u8; SALT_LEN],
}

impl UnlockedVault {
    pub(crate) fn data(&self) -> &Vault {
        &self.data
    }

    pub(crate) fn data_mut(&mut self) -> &mut Vault {
        &mut self.data
    }

    pub(crate) fn kdf(&self) -> KdfConfig {
        self.kdf
    }
}

pub(crate) fn create_unlocked_vault(
    data: Vault,
    master_password: &str,
) -> Result<UnlockedVault, String> {
    let salt = random_salt()?;
    let key = derive_key(master_password, &salt, CURRENT_KDF)?;

    Ok(UnlockedVault {
        data,
        key,
        kdf: CURRENT_KDF,
        salt,
    })
}

pub(crate) fn save_unlocked_vault(path: &Path, vault: &UnlockedVault) -> Result<(), String> {
    let encrypted = encrypt_unlocked_vault(vault)?;

    let temp_path = write_vault_temp(path, &encrypted)?;

    let replace_result = replace_vault_file(path, &temp_path);

    if replace_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    replace_result
}

fn write_vault_temp(path: &Path, encrypted: &[u8]) -> Result<PathBuf, String> {
    let temp_path = atomic_temp_path(path)?;

    let write_result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;

        file.write_all(encrypted)?;
        file.sync_all()?;

        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);

        return Err(format!(
            "could not stage atomic vault write {}: {error}",
            temp_path.display()
        ));
    }

    Ok(temp_path)
}

fn replace_vault_file(path: &Path, temp_path: &Path) -> Result<(), String> {
    fs::rename(temp_path, path).map_err(|error| {
        format!(
            "could not atomically replace {} with {}: {error}",
            path.display(),
            temp_path.display()
        )
    })?;

    sync_parent_directory(path)
}

fn atomic_temp_path(path: &Path) -> Result<PathBuf, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let token = random_nonce()?;
    let mut token_hex = String::with_capacity(24);

    for byte in token.iter().take(12) {
        token_hex.push(HEX[(byte >> 4) as usize] as char);
        token_hex.push(HEX[(byte & 0x0f) as usize] as char);
    }

    let stem = path
        .file_stem()
        .or_else(|| path.file_name())
        .ok_or_else(|| format!("vault path {} has no file name", path.display()))?;

    let mut temp_name = OsString::from(stem);
    temp_name.push(format!(".{token_hex}"));

    if let Some(extension) = path.extension() {
        temp_name.push(".");
        temp_name.push(extension);
    }

    temp_name.push(".tmp");

    Ok(parent_directory(path).join(temp_name))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = parent_directory(path);
    let directory = fs::File::open(parent)
        .map_err(|error| format!("could not open {} for sync: {error}", parent.display()))?;

    directory
        .sync_all()
        .map_err(|error| format!("could not sync {}: {error}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn load_unlocked_vault(
    path: &Path,
    master_password: &str,
) -> Result<UnlockedVault, String> {
    let encrypted =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;

    decrypt_vault_blob(&encrypted, master_password)
}

fn encrypt_unlocked_vault(vault: &UnlockedVault) -> Result<Vec<u8>, String> {
    let nonce = random_nonce()?;
    let header = build_header(vault.kdf, &vault.salt, &nonce);

    let mut plaintext = serde_json::to_vec(&vault.data)
        .map_err(|error| format!("could not serialize vault: {error}"))?;

    let encryption_result = encrypt(&vault.key, &nonce, &plaintext, &header);

    plaintext.zeroize();

    let ciphertext = encryption_result?;

    let mut output = Vec::with_capacity(header.len() + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

fn decrypt_vault_blob(encrypted: &[u8], master_password: &str) -> Result<UnlockedVault, String> {
    if encrypted.len() < HEADER_LEN + MIN_CIPHERTEXT_LEN {
        return Err("vault file is too short".into());
    }

    let (kdf, salt, nonce) = parse_header(encrypted)?;
    let key = derive_key(master_password, &salt, kdf)?;

    let mut plaintext = decrypt(
        &key,
        &nonce,
        &encrypted[HEADER_LEN..],
        &encrypted[..HEADER_LEN],
    )?;

    let parse_result = serde_json::from_slice::<Vault>(&plaintext);

    plaintext.zeroize();

    let data =
        parse_result.map_err(|error| format!("decrypted vault payload is invalid: {error}"))?;

    Ok(UnlockedVault {
        data,
        key,
        kdf,
        salt,
    })
}

fn build_header(kdf: KdfConfig, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);

    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&kdf.memory_kib.to_le_bytes());
    header.extend_from_slice(&kdf.iterations.to_le_bytes());
    header.extend_from_slice(&kdf.parallelism.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);

    header
}

fn parse_header(encrypted: &[u8]) -> Result<(KdfConfig, [u8; SALT_LEN], [u8; NONCE_LEN]), String> {
    if encrypted.len() < HEADER_LEN {
        return Err("vault header is incomplete".into());
    }

    if &encrypted[..MAGIC.len()] != MAGIC {
        return Err("not a BarePass vault or unsupported vault version".into());
    }

    let kdf = KdfConfig {
        memory_kib: read_u32_le(encrypted, 8),
        iterations: read_u32_le(encrypted, 12),
        parallelism: read_u32_le(encrypted, 16),
    };

    kdf.validate()?;

    let mut salt = [0_u8; SALT_LEN];
    salt.copy_from_slice(&encrypted[20..20 + SALT_LEN]);

    let nonce_start = 20 + SALT_LEN;

    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&encrypted[nonce_start..nonce_start + NONCE_LEN]);

    Ok((kdf, salt, nonce))
}

fn read_u32_le(bytes: &[u8], start: usize) -> u32 {
    let mut buffer = [0_u8; 4];
    buffer.copy_from_slice(&bytes[start..start + 4]);

    u32::from_le_bytes(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PasswordEntry;

    const MASTER_PASSWORD: &str = "correct horse battery staple";

    fn sample_vault() -> Vault {
        Vault {
            format_version: 1,
            created_unix: 123,
            updated_unix: 456,
            entries: vec![PasswordEntry {
                id: 1,
                title: "GitHub".into(),
                username: "tamas@example.test".into(),
                password: "very-secret-password".into(),
                url: "https://github.com".into(),
                notes: "BarePass encrypted-vault round-trip test".into(),
                deleted_unix: None,
            }],
        }
    }

    #[test]
    fn encrypted_vault_round_trip_preserves_secret_data() {
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();
        let encrypted = encrypt_unlocked_vault(&unlocked).unwrap();

        assert!(
            !encrypted
                .windows(b"very-secret-password".len())
                .any(|window| window == b"very-secret-password")
        );

        let reopened = decrypt_vault_blob(&encrypted, MASTER_PASSWORD).unwrap();

        assert_eq!(reopened.data, sample_vault());
    }

    #[test]
    fn wrong_master_password_cannot_decrypt_vault() {
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();
        let encrypted = encrypt_unlocked_vault(&unlocked).unwrap();

        assert!(decrypt_vault_blob(&encrypted, "absolutely the wrong password").is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();
        let mut encrypted = encrypt_unlocked_vault(&unlocked).unwrap();

        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        assert!(decrypt_vault_blob(&encrypted, MASTER_PASSWORD).is_err());
    }

    #[test]
    fn tampered_header_is_rejected() {
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();
        let mut encrypted = encrypt_unlocked_vault(&unlocked).unwrap();

        encrypted[20] ^= 0x01;

        assert!(decrypt_vault_blob(&encrypted, MASTER_PASSWORD).is_err());
    }

    #[test]
    fn staged_atomic_write_does_not_touch_existing_vault() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-atomic-stage-{}-{unique}.vault",
            std::process::id()
        ));

        let original = b"original vault bytes";
        let replacement = b"replacement vault bytes";

        fs::write(&path, original).unwrap();

        let temp_path = write_vault_temp(&path, replacement).unwrap();

        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(&temp_path).unwrap(), replacement);
        assert_ne!(temp_path, path);
        assert_eq!(
            temp_path
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("tmp")
        );

        fs::remove_file(&temp_path).unwrap();
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn delete_restore_save_reopen_recovery_round_trip() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-recovery-{}-{unique}.vault",
            std::process::id()
        ));

        let result = (|| -> Result<(), String> {
            let mut unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD)?;

            unlocked.data_mut().move_password_entry_to_deleted(1)?;
            save_unlocked_vault(&path, &unlocked)?;

            let mut reopened = load_unlocked_vault(&path, MASTER_PASSWORD)?;

            let deleted = &reopened.data().entries[0];

            assert!(deleted.deleted_unix.is_some());
            assert_eq!(deleted.title, "GitHub");
            assert_eq!(deleted.password, "very-secret-password");

            reopened.data_mut().restore_password_entry(1)?;
            save_unlocked_vault(&path, &reopened)?;

            let restored = load_unlocked_vault(&path, MASTER_PASSWORD)?;
            let entry = &restored.data().entries[0];

            assert_eq!(entry.deleted_unix, None);
            assert_eq!(entry.id, 1);
            assert_eq!(entry.title, "GitHub");
            assert_eq!(entry.username, "tamas@example.test");
            assert_eq!(entry.password, "very-secret-password");
            assert_eq!(entry.url, "https://github.com");
            assert_eq!(entry.notes, "BarePass encrypted-vault round-trip test");

            Ok(())
        })();

        let _ = std::fs::remove_file(&path);

        result.unwrap();
    }
}
