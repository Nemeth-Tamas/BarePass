use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use zeroize::Zeroizing;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;

pub(crate) type VaultKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KdfConfig {
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
}

pub(crate) const CURRENT_KDF: KdfConfig = KdfConfig {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 1,
};

impl KdfConfig {
    pub(crate) fn validate(self) -> Result<(), String> {
        if !(8 * 1024..=256 * 1024).contains(&self.memory_kib) {
            return Err("vault KDF memory setting is outside BarePass safety limits".into());
        }

        if !(1..=10).contains(&self.iterations) {
            return Err("vault KDF iteration setting is outside BarePass safety limits".into());
        }

        if !(1..=16).contains(&self.parallelism) {
            return Err("vault KDF parallelism setting is outside BarePass safety limits".into());
        }

        Ok(())
    }
}

pub(crate) fn derive_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfConfig,
) -> Result<VaultKey, String> {
    kdf.validate()?;

    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| format!("invalid Argon2 parameters: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);

    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key[..])
        .map_err(|error| format!("Argon2 key derivation failed: {error}"))?;

    Ok(key)
}

pub(crate) fn random_salt() -> Result<[u8; SALT_LEN], String> {
    random_bytes()
}

pub(crate) fn random_nonce() -> Result<[u8; NONCE_LEN], String> {
    random_bytes()
}

pub(crate) fn encrypt(
    key: &VaultKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "invalid encryption key length".to_string())?;

    let nonce = Array(*nonce);

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "vault encryption failed".to_string())
}

pub(crate) fn decrypt(
    key: &VaultKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "invalid encryption key length".to_string())?;

    let nonce = Array(*nonce);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "authentication failed".to_string())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0_u8; N];

    getrandom::fill(&mut bytes).map_err(|error| format!("OS random generator failed: {error}"))?;

    Ok(bytes)
}
