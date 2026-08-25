use crate::model::PasswordEntry;

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
}
