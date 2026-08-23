use std::{fs, path::Path};

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

    fs::write(path, encrypted)
        .map_err(|error| format!("could not write {}: {error}", path.display()))
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
}
