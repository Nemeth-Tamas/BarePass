use crate::model::PasswordEntry;

pub(crate) struct WeakPasswordFinding<'a> {
    pub(crate) entry: &'a PasswordEntry,
    pub(crate) reasons: Vec<&'static str>,
}

const COMMON_EXACT: &[&[u8]] = &[
    b"123456",
    b"12345678",
    b"123456789",
    b"111111",
    b"000000",
    b"abc123",
    b"qwerty",
];
const COMMON_STEMS: &[&[u8]] = &[
    b"password",
    b"welcome",
    b"letmein",
    b"qwerty",
    b"admin",
    b"iloveyou",
    b"monkey",
    b"dragon",
    b"football",
];

pub(crate) fn reused_password_groups(entries: &[PasswordEntry]) -> Vec<Vec<&PasswordEntry>> {
    let mut groups = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        if entry.deleted_unix.is_some() || entry.password.is_empty() {
            continue;
        }

        let already_grouped = entries[..index].iter().any(|previous| {
            previous.deleted_unix.is_none()
                && !previous.password.is_empty()
                && previous.password.as_str() == entry.password.as_str()
        });

        if already_grouped {
            continue;
        }

        let group: Vec<_> = entries[index..]
            .iter()
            .filter(|candidate| {
                candidate.deleted_unix.is_none()
                    && !candidate.password.is_empty()
                    && candidate.password.as_str() == entry.password.as_str()
            })
            .collect();

        if group.len() > 1 {
            groups.push(group);
        }
    }

    groups
}

pub(crate) fn weak_password_findings(entries: &[PasswordEntry]) -> Vec<WeakPasswordFinding<'_>> {
    entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_none() && !entry.password.is_empty())
        .filter_map(|entry| {
            let reasons = weakness_reasons(entry.password.as_str());

            (!reasons.is_empty()).then_some(WeakPasswordFinding { entry, reasons })
        })
        .collect()
}

fn weakness_reasons(password: &str) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    let character_count = password.chars().count();
    let single_character_repetition = is_single_character_repetition(password);

    if character_count < 12 {
        reasons.push("Fewer than 12 characters.");
    }

    if matches_common_password_pattern(password) {
        reasons.push("Matches a common password pattern or predictable variation.");
    }

    if single_character_repetition {
        reasons.push("Repeats the same character throughout.");
    } else if is_repeated_ascii_pattern(password.as_bytes()) {
        reasons.push("Built by repeating a short pattern.");
    }

    if has_obvious_ascii_sequence(password.as_bytes()) {
        reasons.push("Contains an obvious ascending or descending sequence.");
    }

    if character_count < 16 && character_class_count(password) == 1 {
        reasons.push("Uses only one character class while shorter than 16 characters.");
    }

    reasons
}

fn matches_common_password_pattern(password: &str) -> bool {
    let bytes = password.as_bytes();

    if !bytes.is_ascii() {
        return false;
    }

    if COMMON_EXACT
        .iter()
        .any(|candidate| bytes.eq_ignore_ascii_case(candidate))
    {
        return true;
    }

    let mut stem_end = bytes.len();

    while stem_end > 0 && !bytes[stem_end - 1].is_ascii_alphabetic() {
        stem_end -= 1;
    }

    let stem = &bytes[..stem_end];

    COMMON_STEMS
        .iter()
        .any(|candidate| stem.eq_ignore_ascii_case(candidate))
}

fn is_single_character_repetition(password: &str) -> bool {
    let mut characters = password.chars();
    let Some(first) = characters.next() else {
        return false;
    };

    characters.clone().next().is_some() && characters.all(|character| character == first)
}

fn is_repeated_ascii_pattern(bytes: &[u8]) -> bool {
    if !bytes.is_ascii() || bytes.len() < 6 {
        return false;
    }

    (2..=bytes.len() / 2).any(|pattern_len| {
        bytes.len().is_multiple_of(pattern_len)
            && bytes[pattern_len..]
                .chunks(pattern_len)
                .all(|chunk| chunk == &bytes[..pattern_len])
    })
}

fn has_obvious_ascii_sequence(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|window| {
        let all_digits = window.iter().all(u8::is_ascii_digit);
        let all_letters = window.iter().all(u8::is_ascii_alphabetic);

        if !all_digits && !all_letters {
            return false;
        }

        let normalized = |byte: u8| byte.to_ascii_lowercase();
        let ascending = window
            .windows(2)
            .all(|pair| normalized(pair[1]) == normalized(pair[0]).saturating_add(1));
        let descending = window
            .windows(2)
            .all(|pair| normalized(pair[0]) == normalized(pair[1]).saturating_add(1));

        ascending || descending
    })
}

fn character_class_count(password: &str) -> usize {
    let mut lowercase = false;
    let mut uppercase = false;
    let mut digits = false;
    let mut other = false;

    for character in password.chars() {
        lowercase |= character.is_ascii_lowercase();
        uppercase |= character.is_ascii_uppercase();
        digits |= character.is_ascii_digit();
        other |= !character.is_ascii_alphanumeric();
    }

    [lowercase, uppercase, digits, other]
        .into_iter()
        .filter(|present| *present)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, title: &str, password: &str, deleted_unix: Option<u64>) -> PasswordEntry {
        PasswordEntry {
            id,
            title: title.into(),
            username: format!("user-{id}"),
            password: password.into(),
            url: String::new(),
            notes: String::new(),
            deleted_unix,
        }
    }

    #[test]
    fn reused_password_groups_find_exact_active_reuse_without_empty_or_deleted_entries() {
        let entries = vec![
            entry(1, "Alpha", "same-secret", None),
            entry(2, "Beta", "different-secret", None),
            entry(3, "Gamma", "same-secret", None),
            entry(4, "Deleted duplicate", "same-secret", Some(123)),
            entry(5, "Empty one", "", None),
            entry(6, "Empty two", "", None),
            entry(7, "Delta", "other-reuse", None),
            entry(8, "Epsilon", "other-reuse", None),
        ];

        let groups = reused_password_groups(&entries);

        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(
            groups[1].iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![7, 8]
        );
    }

    #[test]
    fn reused_password_groups_return_empty_when_active_passwords_are_unique() {
        let entries = vec![
            entry(1, "Alpha", "first", None),
            entry(2, "Beta", "second", None),
            entry(3, "Gamma", "", None),
        ];

        assert!(reused_password_groups(&entries).is_empty());
    }

    #[test]
    fn weak_password_findings_flag_concrete_patterns_without_showing_deleted_or_empty_entries() {
        let entries = vec![
            entry(1, "Short", "abc123", None),
            entry(2, "Common variation", "Password123!", None),
            entry(3, "Repeated", "abcabcabcabc", None),
            entry(4, "Sequence", "zzabcdZZ!!22", None),
            entry(5, "Deleted weak", "123456", Some(123)),
            entry(6, "Empty", "", None),
            entry(7, "Long passphrase", "correct horse battery staple", None),
            entry(8, "Generated-ish", "N7!xQ2@vL9#pR4$kT8", None),
        ];

        let findings = weak_password_findings(&entries);
        let ids = findings
            .iter()
            .map(|finding| finding.entry.id)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec![1, 2, 3, 4]);
        assert!(findings.iter().all(|finding| !finding.reasons.is_empty()));
    }

    #[test]
    fn common_password_stems_catch_predictable_suffixes() {
        assert!(matches_common_password_pattern("Password123!"));
        assert!(matches_common_password_pattern("WELCOME2026"));
        assert!(matches_common_password_pattern("qwerty!"));
        assert!(!matches_common_password_pattern(
            "correct-horse-battery-staple"
        ));
    }

    #[test]
    fn repeated_and_sequence_detection_are_deliberately_narrow() {
        assert!(is_single_character_repetition("aaaaaaaa"));
        assert!(is_repeated_ascii_pattern(b"passpasspass"));
        assert!(is_repeated_ascii_pattern(b"abcabcabc"));
        assert!(has_obvious_ascii_sequence(b"xx1234yy"));
        assert!(has_obvious_ascii_sequence(b"xxDCBAyy"));

        assert!(!is_repeated_ascii_pattern(b"not-a-repeat"));
        assert!(!has_obvious_ascii_sequence(b"N7!xQ2@vL9"));
    }
}
