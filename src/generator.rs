use zeroize::{Zeroize, Zeroizing};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/~";

pub(crate) const MIN_PASSWORD_LENGTH: usize = 8;
pub(crate) const MAX_PASSWORD_LENGTH: usize = 128;
pub(crate) const DEFAULT_PASSWORD_LENGTH: usize = 20;

#[derive(Clone, Copy)]
pub(crate) enum CharacterSet {
    Lowercase,
    Uppercase,
    Digits,
    Symbols,
}

pub(crate) struct PasswordGenerator {
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    password: Zeroizing<String>,
}

impl PasswordGenerator {
    pub(crate) fn new() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            password: Zeroizing::new(String::new()),
        }
    }

    pub(crate) fn length(&self) -> usize {
        self.length
    }

    pub(crate) fn password(&self) -> &str {
        self.password.as_str()
    }

    pub(crate) fn lowercase_enabled(&self) -> bool {
        self.lowercase
    }

    pub(crate) fn uppercase_enabled(&self) -> bool {
        self.uppercase
    }

    pub(crate) fn digits_enabled(&self) -> bool {
        self.digits
    }

    pub(crate) fn symbols_enabled(&self) -> bool {
        self.symbols
    }

    pub(crate) fn alphabet_len(&self) -> usize {
        let mut length = 0;

        if self.lowercase {
            length += LOWERCASE.len();
        }
        if self.uppercase {
            length += UPPERCASE.len();
        }
        if self.digits {
            length += DIGITS.len();
        }
        if self.symbols {
            length += SYMBOLS.len();
        }

        length
    }

    pub(crate) fn increase_length(&mut self) -> bool {
        if self.length >= MAX_PASSWORD_LENGTH {
            return false;
        }

        self.length += 1;
        true
    }

    pub(crate) fn decrease_length(&mut self) -> bool {
        if self.length <= MIN_PASSWORD_LENGTH {
            return false;
        }

        self.length -= 1;
        true
    }

    pub(crate) fn toggle(&mut self, set: CharacterSet) -> Result<(), String> {
        if self.set_enabled(set) && self.enabled_set_count() == 1 {
            return Err("At least one password character set must remain enabled.".into());
        }

        match set {
            CharacterSet::Lowercase => self.lowercase = !self.lowercase,
            CharacterSet::Uppercase => self.uppercase = !self.uppercase,
            CharacterSet::Digits => self.digits = !self.digits,
            CharacterSet::Symbols => self.symbols = !self.symbols,
        }

        Ok(())
    }

    pub(crate) fn regenerate(&mut self) -> Result<(), String> {
        let alphabet = self.alphabet();

        if alphabet.is_empty() {
            return Err("No password character sets are enabled.".into());
        }

        self.clear_password();
        self.password.reserve(self.length);

        let result = (|| -> Result<(), String> {
            while self.password.len() < self.length {
                let mut random = [0_u8; 64];

                getrandom::fill(&mut random)
                    .map_err(|error| format!("OS random generator failed: {error}"))?;

                for byte in random {
                    let Some(index) = rejection_sample_index(byte, alphabet.len()) else {
                        continue;
                    };

                    self.password.push(alphabet[index] as char);

                    if self.password.len() == self.length {
                        break;
                    }
                }
            }

            Ok(())
        })();

        if result.is_err() {
            self.clear_password();
        }

        result
    }

    pub(crate) fn clear_password(&mut self) {
        self.password.zeroize();
        self.password.clear();
    }

    fn set_enabled(&self, set: CharacterSet) -> bool {
        match set {
            CharacterSet::Lowercase => self.lowercase,
            CharacterSet::Uppercase => self.uppercase,
            CharacterSet::Digits => self.digits,
            CharacterSet::Symbols => self.symbols,
        }
    }

    fn enabled_set_count(&self) -> usize {
        [self.lowercase, self.uppercase, self.digits, self.symbols]
            .into_iter()
            .filter(|enabled| *enabled)
            .count()
    }

    fn alphabet(&self) -> Vec<u8> {
        let mut alphabet =
            Vec::with_capacity(LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len());

        if self.lowercase {
            alphabet.extend_from_slice(LOWERCASE);
        }
        if self.uppercase {
            alphabet.extend_from_slice(UPPERCASE);
        }
        if self.digits {
            alphabet.extend_from_slice(DIGITS);
        }
        if self.symbols {
            alphabet.extend_from_slice(SYMBOLS);
        }

        alphabet
    }
}

fn rejection_sample_index(byte: u8, alphabet_len: usize) -> Option<usize> {
    if alphabet_len == 0 || alphabet_len > 256 {
        return None;
    }

    let acceptance_limit = 256 - (256 % alphabet_len);
    let value = usize::from(byte);

    (value < acceptance_limit).then_some(value % alphabet_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_uses_the_requested_length_and_enabled_alphabet() {
        let mut generator = PasswordGenerator::new();

        generator.regenerate().unwrap();

        let alphabet = generator.alphabet();

        assert_eq!(generator.password().len(), DEFAULT_PASSWORD_LENGTH);
        assert!(
            generator
                .password()
                .bytes()
                .all(|byte| alphabet.contains(&byte))
        );
    }

    #[test]
    fn generator_refuses_to_disable_the_last_character_set() {
        let mut generator = PasswordGenerator::new();

        generator.toggle(CharacterSet::Lowercase).unwrap();
        generator.toggle(CharacterSet::Uppercase).unwrap();
        generator.toggle(CharacterSet::Digits).unwrap();

        assert!(generator.symbols_enabled());
        assert!(generator.toggle(CharacterSet::Symbols).is_err());
        assert!(generator.symbols_enabled());
    }

    #[test]
    fn rejection_sampling_is_uniform_for_representative_alphabet_sizes() {
        for alphabet_len in [10, 26, 62, 87] {
            let mut counts = vec![0_usize; alphabet_len];

            for value in 0_u16..=255 {
                if let Some(index) = rejection_sample_index(value as u8, alphabet_len) {
                    counts[index] += 1;
                }
            }

            assert!(
                counts.windows(2).all(|pair| pair[0] == pair[1]),
                "alphabet length {alphabet_len} produced uneven buckets: {counts:?}"
            );
        }
    }
}
