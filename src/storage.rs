use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions, TryLockError},
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

pub(crate) struct VaultLock {
    _file: fs::File,
}

pub(crate) struct VaultLoad {
    pub(crate) vault: UnlockedVault,
    pub(crate) recovered_from_backup: bool,
    pub(crate) backup_warning: Option<String>,
}

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

pub(crate) fn acquire_vault_lock(path: &Path) -> Result<VaultLock, String> {
    let lock_path = vault_lock_path(path);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            format!(
                "could not open vault lock file {}: {error}",
                lock_path.display()
            )
        })?;

    match file.try_lock() {
        Ok(()) => Ok(VaultLock { _file: file }),
        Err(TryLockError::WouldBlock) => {
            Err("Vault is already open in another BarePass process.".into())
        }
        Err(TryLockError::Error(error)) => Err(format!(
            "could not lock vault through {}: {error}",
            lock_path.display()
        )),
    }
}

fn vault_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn vault_backup_path(path: &Path) -> PathBuf {
    let mut backup_path = path.as_os_str().to_os_string();
    backup_path.push(".bak");
    PathBuf::from(backup_path)
}

pub(crate) fn vault_or_backup_exists(path: &Path) -> bool {
    path.exists() || vault_backup_path(path).exists()
}

pub(crate) fn prepare_vault_path() -> Result<(PathBuf, Option<String>), String> {
    let native_path = native_vault_path()?;
    let legacy_path = PathBuf::from("barepass.vault");

    if vault_or_backup_exists(&native_path) || !legacy_path.exists() {
        return Ok((native_path, None));
    }

    let notice = migrate_legacy_vault(&legacy_path, &native_path)?;

    Ok((native_path, Some(notice)))
}

fn native_vault_path() -> Result<PathBuf, String> {
    let base = native_data_directory()?;
    let app_directory = base.join("BarePass");

    fs::create_dir_all(&app_directory).map_err(|error| {
        format!(
            "could not create BarePass data directory {}: {error}",
            app_directory.display()
        )
    })?;

    Ok(app_directory.join("barepass.vault"))
}

#[cfg(target_os = "windows")]
fn native_data_directory() -> Result<PathBuf, String> {
    environment_path("LOCALAPPDATA")
        .ok_or_else(|| "LOCALAPPDATA is not available for OS-native vault storage".into())
}

#[cfg(target_os = "macos")]
fn native_data_directory() -> Result<PathBuf, String> {
    let home = environment_path("HOME")
        .ok_or_else(|| "HOME is not available for OS-native vault storage".to_string())?;

    Ok(home.join("Library").join("Application Support"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn native_data_directory() -> Result<PathBuf, String> {
    if let Some(data_home) = environment_path("XDG_DATA_HOME").filter(|path| path.is_absolute()) {
        return Ok(data_home);
    }

    let home = environment_path("HOME")
        .ok_or_else(|| "HOME is not available for OS-native vault storage".to_string())?;

    Ok(home.join(".local").join("share"))
}

#[cfg(not(any(target_os = "windows", unix)))]
fn native_data_directory() -> Result<PathBuf, String> {
    Err("OS-native vault storage is not implemented for this platform".into())
}

fn environment_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn migrate_legacy_vault(legacy_path: &Path, native_path: &Path) -> Result<String, String> {
    let legacy_lock = acquire_vault_lock(legacy_path)?;
    let _native_lock = acquire_vault_lock(native_path)?;

    if native_path.exists() {
        return Ok(format!(
            "OS-native vault already exists at {}.",
            native_path.display()
        ));
    }

    let encrypted = fs::read(legacy_path).map_err(|error| {
        format!(
            "could not read legacy vault {} for migration: {error}",
            legacy_path.display()
        )
    })?;

    atomic_write_bytes(&vault_backup_path(native_path), &encrypted)?;
    atomic_write_bytes(native_path, &encrypted)?;

    let removal_warning = match fs::remove_file(legacy_path) {
        Ok(()) => {
            sync_parent_directory(legacy_path)?;
            None
        }
        Err(error) => Some(format!(
            " The encrypted legacy copy at {} could not be removed: {error}",
            legacy_path.display()
        )),
    };

    drop(legacy_lock);

    if !legacy_path.exists() {
        let _ = fs::remove_file(vault_lock_path(legacy_path));
    }

    Ok(format!(
        "Migrated encrypted vault to {}.{}",
        native_path.display(),
        removal_warning.unwrap_or_default()
    ))
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

    prepare_backup_before_save(path, vault, &encrypted)?;
    atomic_write_bytes(path, &encrypted)
}

fn prepare_backup_before_save(
    path: &Path,
    vault: &UnlockedVault,
    replacement: &[u8],
) -> Result<(), String> {
    let backup_path = vault_backup_path(path);

    if !path.exists() {
        return atomic_write_bytes(&backup_path, replacement);
    }

    let current = fs::read(path)
        .map_err(|error| format!("could not read {} before backup: {error}", path.display()))?;

    if encrypted_blob_matches_unlocked_vault(&current, vault) {
        return atomic_write_bytes(&backup_path, &current);
    }

    let backup_is_valid = fs::read(&backup_path)
        .ok()
        .is_some_and(|backup| encrypted_blob_matches_unlocked_vault(&backup, vault));

    if backup_is_valid {
        return Ok(());
    }

    atomic_write_bytes(&backup_path, replacement)
}

fn ensure_valid_backup(path: &Path, vault: &UnlockedVault) -> Result<(), String> {
    let backup_path = vault_backup_path(path);

    let backup_is_valid = fs::read(&backup_path)
        .ok()
        .is_some_and(|backup| encrypted_blob_matches_unlocked_vault(&backup, vault));

    if backup_is_valid {
        return Ok(());
    }

    let primary = fs::read(path)
        .map_err(|error| format!("could not read {} for backup: {error}", path.display()))?;

    atomic_write_bytes(&backup_path, &primary).map_err(|error| {
        format!(
            "could not create or refresh encrypted backup {}: {error}",
            backup_path.display()
        )
    })
}

fn atomic_write_bytes(path: &Path, encrypted: &[u8]) -> Result<(), String> {
    let temp_path = write_vault_temp(path, encrypted)?;

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

pub(crate) fn load_unlocked_vault_with_recovery(
    path: &Path,
    master_password: &str,
) -> Result<VaultLoad, String> {
    match load_unlocked_vault(path, master_password) {
        Ok(vault) => {
            let backup_warning = ensure_valid_backup(path, &vault).err();

            Ok(VaultLoad {
                vault,
                recovered_from_backup: false,
                backup_warning,
            })
        }
        Err(primary_error) => {
            let backup_path = vault_backup_path(path);
            let vault =
                load_unlocked_vault(&backup_path, master_password).map_err(|_| primary_error)?;

            let encrypted_backup = fs::read(&backup_path).map_err(|error| {
                format!(
                    "verified backup {} could not be read for recovery: {error}",
                    backup_path.display()
                )
            })?;

            atomic_write_bytes(path, &encrypted_backup).map_err(|error| {
                format!(
                    "verified backup was available, but {} could not be restored: {error}",
                    path.display()
                )
            })?;

            Ok(VaultLoad {
                vault,
                recovered_from_backup: true,
                backup_warning: None,
            })
        }
    }
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

fn encrypted_blob_matches_unlocked_vault(encrypted: &[u8], vault: &UnlockedVault) -> bool {
    if encrypted.len() < HEADER_LEN + MIN_CIPHERTEXT_LEN {
        return false;
    }

    let Ok((kdf, salt, nonce)) = parse_header(encrypted) else {
        return false;
    };

    if kdf.memory_kib != vault.kdf.memory_kib
        || kdf.iterations != vault.kdf.iterations
        || kdf.parallelism != vault.kdf.parallelism
        || salt != vault.salt
    {
        return false;
    }

    let Ok(mut plaintext) = decrypt(
        &vault.key,
        &nonce,
        &encrypted[HEADER_LEN..],
        &encrypted[..HEADER_LEN],
    ) else {
        return false;
    };

    let valid = serde_json::from_slice::<Vault>(&plaintext).is_ok();
    plaintext.zeroize();

    valid
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
    use crate::model::{CURRENT_VAULT_FORMAT_VERSION, PasswordEntry};

    const MASTER_PASSWORD: &str = "correct horse battery staple";

    fn sample_vault() -> Vault {
        Vault {
            format_version: CURRENT_VAULT_FORMAT_VERSION,
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
    fn vault_lock_blocks_a_second_holder_until_the_first_is_dropped() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-lock-{}-{unique}.vault",
            std::process::id()
        ));
        let lock_path = vault_lock_path(&path);

        let first = acquire_vault_lock(&path).unwrap();

        let second_error = match acquire_vault_lock(&path) {
            Ok(_) => panic!("a second vault lock unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(second_error.contains("already open"));

        drop(first);

        let third = acquire_vault_lock(&path).unwrap();
        drop(third);

        fs::remove_file(lock_path).unwrap();
    }

    #[test]
    fn legacy_vault_migration_preserves_encrypted_bytes_and_removes_old_copy() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let root = std::env::temp_dir().join(format!(
            "barepass-migration-{}-{unique}",
            std::process::id()
        ));
        let legacy_path = root.join("barepass.vault");
        let native_directory = root.join("native");
        let native_path = native_directory.join("barepass.vault");
        let native_backup_path = vault_backup_path(&native_path);
        let encrypted = b"already encrypted legacy vault bytes";

        fs::create_dir_all(&native_directory).unwrap();
        fs::write(&legacy_path, encrypted).unwrap();

        let notice = migrate_legacy_vault(&legacy_path, &native_path).unwrap();

        assert_eq!(fs::read(&native_path).unwrap(), encrypted);
        assert_eq!(fs::read(&native_backup_path).unwrap(), encrypted);
        assert!(!legacy_path.exists());
        assert!(notice.contains("Migrated encrypted vault"));

        fs::remove_file(&native_path).unwrap();
        fs::remove_file(&native_backup_path).unwrap();
        fs::remove_file(vault_lock_path(&native_path)).unwrap();
        fs::remove_dir(&native_directory).unwrap();
        fs::remove_dir(&root).unwrap();
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
    fn first_save_creates_an_encrypted_recovery_backup() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-first-backup-{}-{unique}.vault",
            std::process::id()
        ));
        let backup_path = vault_backup_path(&path);
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();

        save_unlocked_vault(&path, &unlocked).unwrap();

        let primary = load_unlocked_vault(&path, MASTER_PASSWORD).unwrap();
        let backup = load_unlocked_vault(&backup_path, MASTER_PASSWORD).unwrap();

        assert_eq!(primary.data, sample_vault());
        assert_eq!(backup.data, sample_vault());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&backup_path).unwrap();
    }

    #[test]
    fn later_save_keeps_the_previous_authenticated_primary_as_backup() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-previous-backup-{}-{unique}.vault",
            std::process::id()
        ));
        let backup_path = vault_backup_path(&path);
        let mut unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();

        save_unlocked_vault(&path, &unlocked).unwrap();

        unlocked
            .data_mut()
            .update_password_entry(
                1,
                "Updated GitHub".into(),
                "new-user@example.test".into(),
                "new-secret".into(),
                "https://github.com/new".into(),
                "updated notes".into(),
            )
            .unwrap();

        save_unlocked_vault(&path, &unlocked).unwrap();

        let primary = load_unlocked_vault(&path, MASTER_PASSWORD).unwrap();
        let backup = load_unlocked_vault(&backup_path, MASTER_PASSWORD).unwrap();

        assert_eq!(primary.data.entries[0].title, "Updated GitHub");
        assert_eq!(backup.data.entries[0].title, "GitHub");
        assert_eq!(backup.data.entries[0].password, "very-secret-password");

        fs::remove_file(&path).unwrap();
        fs::remove_file(&backup_path).unwrap();
    }

    #[test]
    fn verified_backup_recovers_a_damaged_primary() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-damaged-recovery-{}-{unique}.vault",
            std::process::id()
        ));
        let backup_path = vault_backup_path(&path);
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();

        save_unlocked_vault(&path, &unlocked).unwrap();
        fs::write(&path, b"damaged primary vault").unwrap();

        let recovered = load_unlocked_vault_with_recovery(&path, MASTER_PASSWORD).unwrap();

        assert!(recovered.recovered_from_backup);
        assert_eq!(recovered.vault.data, sample_vault());

        let restored_primary = load_unlocked_vault(&path, MASTER_PASSWORD).unwrap();
        assert_eq!(restored_primary.data, sample_vault());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&backup_path).unwrap();
    }

    #[test]
    fn verified_backup_recovers_a_missing_primary() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "barepass-missing-recovery-{}-{unique}.vault",
            std::process::id()
        ));
        let backup_path = vault_backup_path(&path);
        let unlocked = create_unlocked_vault(sample_vault(), MASTER_PASSWORD).unwrap();

        save_unlocked_vault(&path, &unlocked).unwrap();
        fs::remove_file(&path).unwrap();

        assert!(vault_or_backup_exists(&path));

        let recovered = load_unlocked_vault_with_recovery(&path, MASTER_PASSWORD).unwrap();

        assert!(recovered.recovered_from_backup);
        assert!(path.exists());
        assert_eq!(recovered.vault.data, sample_vault());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&backup_path).unwrap();
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
        let backup_path = vault_backup_path(&path);

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
        let _ = std::fs::remove_file(&backup_path);

        result.unwrap();
    }
}
