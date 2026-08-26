use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::{
    app::{AddField, App, Mode, NoteField},
    generator::PasswordStrength,
    password_analysis::{reused_password_groups, weak_password_findings},
};

pub(crate) fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_header(frame, chunks[0]);

    match app.mode() {
        Mode::Vault => {
            if app.password_audit_open() {
                draw_password_audit(frame, app, chunks[1]);
            } else {
                draw_vault(frame, app, chunks[1]);
            }
        }
        Mode::RecentlyDeleted => draw_recently_deleted(frame, app, chunks[1]),
        Mode::Generator => draw_password_generator(frame, app, chunks[1]),
        Mode::AddEntry | Mode::EditEntry => {
            draw_vault(frame, app, chunks[1]);
            draw_entry_form(frame, app, chunks[1]);
        }
        Mode::AddNote => {
            draw_vault(frame, app, chunks[1]);
            draw_note_form(frame, app, chunks[1]);
        }
        Mode::ConfirmDelete => {
            if app.is_empty_recently_deleted_confirmation() {
                draw_recently_deleted(frame, app, chunks[1]);
                draw_empty_recently_deleted_confirmation(frame, app, chunks[1]);
            } else if app.is_permanent_delete_confirmation() {
                draw_recently_deleted(frame, app, chunks[1]);
                draw_permanent_delete_confirmation(frame, app, chunks[1]);
            } else {
                draw_vault(frame, app, chunks[1]);
                draw_delete_confirmation(frame, app, chunks[1]);
            }
        }
        Mode::Create | Mode::Confirm | Mode::Unlock => {
            draw_secret_screen(frame, app, chunks[1]);
        }
    }

    draw_footer(frame, app, chunks[2]);
}

fn draw_header(frame: &mut Frame, area: Rect) {
    let title = Line::from(vec![
        Span::styled(
            " BARE",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "PASS",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  v{}  //  encrypted terminal vault",
                env!("CARGO_PKG_VERSION")
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let header = Paragraph::new(title).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(header, area);
}

fn draw_secret_screen(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(68, 13, area);

    frame.render_widget(Clear, popup);

    let (title, description) = match app.mode() {
        Mode::Create => (
            " Create vault ",
            "Choose the master password that will derive your vault encryption key.",
        ),
        Mode::Confirm => (
            " Confirm master password ",
            "Type it again. BarePass never writes the master password to disk.",
        ),
        Mode::Unlock => (
            " Unlock BarePass ",
            "Enter your master password to decrypt the local vault.",
        ),
        Mode::Vault
        | Mode::AddEntry
        | Mode::EditEntry
        | Mode::AddNote
        | Mode::ConfirmDelete
        | Mode::RecentlyDeleted
        | Mode::Generator => return,
    };

    let outer = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(description)
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true }),
        rows[0],
    );

    let masked = "•".repeat(app.input_len());

    let input = Paragraph::new(if masked.is_empty() {
        " ".to_string()
    } else {
        masked
    })
    .style(
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .title(" Master password ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(input, rows[1]);

    let hint = match app.mode() {
        Mode::Create => "Minimum 12 characters  •  Enter continue  •  Esc quit",
        Mode::Confirm => "Enter create vault  •  Esc start over",
        Mode::Unlock => "Enter unlock  •  Esc quit",
        Mode::Vault
        | Mode::AddEntry
        | Mode::EditEntry
        | Mode::AddNote
        | Mode::ConfirmDelete
        | Mode::RecentlyDeleted
        | Mode::Generator => "",
    };

    frame.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        rows[2],
    );
}

fn draw_password_generator(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(84, 23, area);

    frame.render_widget(Clear, popup);

    let generator = app.generator();
    let outer = Block::default()
        .title(" Password generator ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(
            "Standalone CSPRNG password generation. Nothing is saved unless you explicitly copy it.",
        )
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new(if generator.password().is_empty() {
            Line::from(Span::styled(
                "Generation failed — see status line.",
                Style::default().fg(Color::Red),
            ))
        } else {
            Line::from(Span::styled(
                generator.password(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
        })
        .block(
            Block::default()
                .title(" Generated password ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false }),
        rows[1],
    );

    let strength = generator.strength();
    let strength_color = match strength {
        PasswordStrength::Weak => Color::Red,
        PasswordStrength::Fair => Color::Yellow,
        PasswordStrength::Strong => Color::Cyan,
        PasswordStrength::VeryStrong => Color::Green,
        PasswordStrength::Ludicrous => Color::Magenta,
    };

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(
                    "Length: {}   •   Alphabet: {}   •   Entropy: {:.1} bits   •   ",
                    generator.length(),
                    generator.alphabet_len(),
                    generator.entropy_bits()
                ),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                strength.label(),
                Style::default()
                    .fg(strength_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ])),
        rows[2],
    );

    let toggle_line = |number: &str, label: &str, enabled: bool| {
        Line::from(vec![
            Span::styled(
                format!("  [{number}] "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(format!("{label:<10}"), Style::default().fg(Color::White)),
            Span::styled(
                if enabled { "ON" } else { "OFF" },
                if enabled {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ])
    };

    frame.render_widget(
        Paragraph::new(vec![
            toggle_line("1", "Lowercase", generator.lowercase_enabled()),
            toggle_line("2", "Uppercase", generator.uppercase_enabled()),
            toggle_line("3", "Digits", generator.digits_enabled()),
            toggle_line("4", "Symbols", generator.symbols_enabled()),
        ]),
        rows[3],
    );

    frame.render_widget(
        Paragraph::new(
            "←/→ length   •   1–4 toggle character sets   •   r regenerate   •   c secure copy",
        )
        .style(Style::default().fg(Color::DarkGray))
        .wrap(Wrap { trim: true }),
        rows[4],
    );
}

fn draw_password_audit(frame: &mut Frame, app: &App, area: Rect) {
    let audit_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);

    draw_password_audit_tabs(frame, app, audit_rows[0]);

    let Some(unlocked) = app.vault() else {
        return;
    };

    if app.password_audit_show_weak() {
        draw_weak_password_audit(frame, app, audit_rows[1]);
        return;
    }

    let groups = reused_password_groups(&unlocked.data().entries);
    let affected_count: usize = groups.iter().map(Vec::len).sum();
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(audit_rows[1]);

    let group_lines = if groups.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No reused passwords found.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Active passwords are unique.",
                Style::default().fg(Color::Gray),
            )),
        ]
    } else {
        groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                let selected = index == app.password_audit_selected();
                let marker = if selected { " > " } else { "   " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                Line::from(vec![
                    Span::styled(marker, Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!("Reuse group {}  •  {} entries", index + 1, group.len()),
                        style,
                    ),
                ])
            })
            .collect()
    };

    let groups_panel = Paragraph::new(group_lines)
        .block(
            Block::default()
                .title(format!(
                    " Reused passwords  {} group(s) / {} affected ",
                    groups.len(),
                    affected_count
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(groups_panel, columns[0]);

    let detail_lines = if let Some(group) = groups.get(app.password_audit_selected()) {
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "SAME PASSWORD USED BY:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        for entry in group {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("#{}  ", entry.id),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(entry.title.as_str(), Style::default().fg(Color::White)),
            ]));

            if !entry.username.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(entry.username.as_str(), Style::default().fg(Color::Gray)),
                ]));
            }

            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            "Password text is intentionally never displayed here.",
            Style::default().fg(Color::Green),
        )));

        lines
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "NO REUSE DETECTED",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Comparison is exact, local, and performed only in memory.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "No password hashes or fingerprints are persisted.",
                Style::default().fg(Color::Gray),
            )),
        ]
    };

    let details = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title(" Reuse details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(details, columns[1]);
}

fn draw_password_audit_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let reused_active = !app.password_audit_show_weak();
    let active_style = |color| {
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD)
    };

    let line = Line::from(vec![
        Span::styled(
            " SECURITY AUDIT  ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " REUSED ",
            if reused_active {
                active_style(Color::Yellow)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
        Span::raw("  "),
        Span::styled(
            " WEAK ",
            if reused_active {
                Style::default().fg(Color::Red)
            } else {
                active_style(Color::Red)
            },
        ),
        Span::styled(
            "    Tab switches view",
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let tabs = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(tabs, area);
}

fn draw_weak_password_audit(frame: &mut Frame, app: &App, area: Rect) {
    let Some(unlocked) = app.vault() else {
        return;
    };

    let findings = weak_password_findings(&unlocked.data().entries);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(area);

    let finding_lines = if findings.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No weak passwords flagged.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Conservative heuristics found nothing obvious.",
                Style::default().fg(Color::Gray),
            )),
        ]
    } else {
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| {
                let selected = index == app.password_audit_selected();
                let marker = if selected { " > " } else { "   " };
                let style = if selected {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                Line::from(vec![
                    Span::styled(marker, Style::default().fg(Color::Red)),
                    Span::styled(format!("#{}  ", finding.entry.id), style),
                    Span::styled(finding.entry.title.as_str(), style),
                ])
            })
            .collect()
    };

    let findings_panel = Paragraph::new(finding_lines)
        .block(
            Block::default()
                .title(format!(" Weak passwords  {} finding(s) ", findings.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(findings_panel, columns[0]);

    let detail_lines = if let Some(finding) = findings.get(app.password_audit_selected()) {
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("#{}  ", finding.entry.id),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    finding.entry.title.as_str(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "FLAGGED BECAUSE:",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        for reason in &finding.reasons {
            lines.push(Line::from(vec![
                Span::styled("• ", Style::default().fg(Color::Red)),
                Span::styled(*reason, Style::default().fg(Color::Gray)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Password text is intentionally never displayed by the audit.",
            Style::default().fg(Color::Green),
        )));
        lines
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "NO OBVIOUS WEAKNESS DETECTED",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "This is a conservative heuristic check, not an entropy claim.",
                Style::default().fg(Color::Gray),
            )),
        ]
    };

    let details = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title(" Weakness details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(details, columns[1]);
}

fn draw_vault_tabs(frame: &mut Frame, recently_deleted: bool, area: Rect) {
    let active_style = |color| {
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD)
    };

    let line = Line::from(vec![
        Span::styled(
            " VAULT  ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " ACTIVE ",
            if recently_deleted {
                Style::default().fg(Color::Cyan)
            } else {
                active_style(Color::Cyan)
            },
        ),
        Span::raw("  "),
        Span::styled(
            " RECENTLY DELETED ",
            if recently_deleted {
                active_style(Color::Red)
            } else {
                Style::default().fg(Color::Red)
            },
        ),
        Span::styled(
            "    Tab switches view",
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn draw_active_item_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let passwords_active = !app.vault_show_notes();
    let active_style = |color| {
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD)
    };

    let line = Line::from(vec![
        Span::styled(
            " ACTIVE ITEMS  ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " [1] PASSWORDS ",
            if passwords_active {
                active_style(Color::Cyan)
            } else {
                Style::default().fg(Color::Cyan)
            },
        ),
        Span::raw("  "),
        Span::styled(
            " [2] NOTES ",
            if passwords_active {
                Style::default().fg(Color::Yellow)
            } else {
                active_style(Color::Yellow)
            },
        ),
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

fn draw_secure_notes(frame: &mut Frame, app: &App, area: Rect) {
    let Some(unlocked) = app.vault() else {
        return;
    };

    let active_notes: Vec<_> = unlocked
        .data()
        .notes
        .iter()
        .filter(|note| note.deleted_unix.is_none())
        .collect();

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let list_lines = if active_notes.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No secure notes yet.",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press a to create one.",
                Style::default().fg(Color::Yellow),
            )),
        ]
    } else {
        active_notes
            .iter()
            .enumerate()
            .map(|(index, note)| {
                let selected = index == app.note_selected_index();
                let marker = if selected { " > " } else { "   " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                Line::from(vec![
                    Span::styled(marker, Style::default().fg(Color::Yellow)),
                    Span::styled(format!("#{}  ", note.id), style),
                    Span::styled(note.title.as_str(), style),
                ])
            })
            .collect()
    };

    frame.render_widget(
        Paragraph::new(list_lines)
            .block(
                Block::default()
                    .title(format!(" Secure Notes  {} active ", active_notes.len()))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false }),
        columns[0],
    );

    let detail_lines = if let Some(note) = app.selected_note() {
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "SECURE NOTE",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Title       ", Style::default().fg(Color::DarkGray)),
                Span::styled(note.title.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(""),
        ];

        if note.body.is_empty() {
            lines.push(Line::from(Span::styled(
                "(empty note body)",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
        } else {
            for body_line in note.body.lines() {
                lines.push(Line::from(Span::styled(
                    body_line,
                    Style::default().fg(Color::Gray),
                )));
            }
        }

        lines
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "SECURE NOTES",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Encrypted note browsing is ready.",
                Style::default().fg(Color::Green),
            )),
        ]
    };

    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(
                Block::default()
                    .title(" Note details ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false }),
        columns[1],
    );
}

fn draw_vault(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(area);

    draw_vault_tabs(frame, false, rows[0]);
    draw_active_item_tabs(frame, app, rows[1]);

    if app.vault_show_notes() {
        draw_secure_notes(frame, app, rows[2]);
        return;
    }

    let Some(unlocked) = app.vault() else {
        return;
    };

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[2]);

    let total_active_count = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_none())
        .count();

    let active_entries: Vec<_> = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_none() && app.entry_matches_search(entry))
        .collect();

    let deleted_count = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_some())
        .count();

    let list_lines = if active_entries.is_empty() && total_active_count != 0 {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No entries match your search.",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Esc clears the current filter.",
                Style::default().fg(Color::Cyan),
            )),
        ]
    } else if active_entries.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Your vault is empty.",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  The encryption core is alive.",
                Style::default().fg(Color::Cyan),
            )),
            Line::from(Span::styled(
                "  Entry CRUD comes next.",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    } else {
        active_entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let selected = index == app.selected_index();

                let marker = if selected { " > " } else { "   " };

                let style = if selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                Line::from(vec![
                    Span::styled(marker, Style::default().fg(Color::Cyan)),
                    Span::styled(format!("#{}  ", entry.id), style),
                    Span::styled(entry.title.as_str(), style),
                ])
            })
            .collect()
    };

    let list_title = if app.search_editing() || !app.search_query().is_empty() {
        Line::from(vec![
            Span::raw(format!(
                " Vault  {}/{} match  /  {} deleted  |  Search: ",
                active_entries.len(),
                total_active_count,
                deleted_count
            )),
            Span::styled(
                app.search_query(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ])
    } else {
        Line::from(format!(
            " Vault  {} active  /  {} deleted ",
            total_active_count, deleted_count
        ))
    };

    let list = Paragraph::new(list_lines)
        .block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(list, columns[0]);

    let auto_lock = match app.auto_lock_seconds() {
        Some(seconds) => format!("{seconds} seconds inactivity"),
        None => "Disabled".to_string(),
    };

    let auto_purge = match app.auto_purge_days() {
        Some(days) => format!("{days} days"),
        None => "Disabled".to_string(),
    };

    let details = if let Some(entry) = app.selected_entry() {
        let password_line = if app.selected_password_revealed() {
            Line::from(vec![
                Span::styled("Password    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    entry.password.as_str(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled("Password    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "•".repeat(entry.password.chars().count()),
                    Style::default().fg(Color::Magenta),
                ),
            ])
        };

        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Title       ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.title.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Username    ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.username.as_str(), Style::default().fg(Color::White)),
            ]),
            password_line,
            Line::from(vec![
                Span::styled("URL         ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.url.as_str(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Notes       ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.notes.as_str(), Style::default().fg(Color::Gray)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Auto-lock   ", Style::default().fg(Color::DarkGray)),
                Span::styled(auto_lock, Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Auto-purge  ", Style::default().fg(Color::DarkGray)),
                Span::styled(auto_purge, Style::default().fg(Color::Green)),
            ]),
        ]
    } else {
        let kdf = unlocked.kdf();

        vec![
            Line::from(""),
            Line::from(Span::styled(
                "VAULT UNLOCKED",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!(
                "Format      BRPASS01 / payload v{}",
                unlocked.data().format_version
            )),
            Line::from(format!(
                "KDF         Argon2id  m={} KiB  t={}  p={}",
                kdf.memory_kib, kdf.iterations, kdf.parallelism
            )),
            Line::from("Cipher      XChaCha20-Poly1305"),
            Line::from(format!("Created     {}", unlocked.data().created_unix)),
            Line::from(format!("Updated     {}", unlocked.data().updated_unix)),
            Line::from(format!("Vault file  {}", app.vault_path().display())),
            Line::from(format!("Auto-lock   {auto_lock}")),
            Line::from(format!("Auto-purge  {auto_purge}")),
            Line::from(""),
            Line::from(Span::styled(
                "Master password is not retained.",
                Style::default().fg(Color::Green),
            )),
            Line::from(Span::styled(
                "The derived key lives only while unlocked.",
                Style::default().fg(Color::Green),
            )),
        ]
    };

    let details = Paragraph::new(details)
        .block(
            Block::default()
                .title(" Item / vault details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(details, columns[1]);
}

fn draw_recently_deleted(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);

    draw_vault_tabs(frame, true, rows[0]);

    let Some(unlocked) = app.vault() else {
        return;
    };

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[1]);

    let deleted_entries: Vec<_> = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_some())
        .collect();

    let list_lines = if deleted_entries.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Recently Deleted is empty.",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Nothing needs rescuing. Nice.",
                Style::default().fg(Color::Green),
            )),
        ]
    } else {
        deleted_entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let selected = index == app.deleted_selected_index();
                let marker = if selected { " > " } else { "   " };

                let style = if selected {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };

                Line::from(vec![
                    Span::styled(marker, Style::default().fg(Color::Red)),
                    Span::styled(format!("#{}  ", entry.id), style),
                    Span::styled(entry.title.as_str(), style),
                ])
            })
            .collect()
    };

    let list = Paragraph::new(list_lines)
        .block(
            Block::default()
                .title(format!(
                    " Recently Deleted  {} item(s) ",
                    deleted_entries.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(list, columns[0]);

    let details = if let Some(entry) = app.selected_deleted_entry() {
        let deleted_at = entry
            .deleted_unix
            .map(format_unix_timestamp)
            .unwrap_or_else(|| "Unknown".into());

        vec![
            Line::from(""),
            Line::from(Span::styled(
                "RECOVERABLE ITEM",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Title       ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.title.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Username    ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.username.as_str(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Password    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "•".repeat(entry.password.chars().count()),
                    Style::default().fg(Color::Magenta),
                ),
            ]),
            Line::from(vec![
                Span::styled("URL         ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.url.as_str(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Deleted     ", Style::default().fg(Color::DarkGray)),
                Span::styled(deleted_at, Style::default().fg(Color::Red)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Notes       ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.notes.as_str(), Style::default().fg(Color::Gray)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "r restore  •  d delete forever  •  x empty all",
                Style::default().fg(Color::Green),
            )),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "NO DELETED ITEMS",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Deleted passwords will remain encrypted here",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "until explicitly restored or permanently removed.",
                Style::default().fg(Color::Gray),
            )),
        ]
    };

    let details = Paragraph::new(details)
        .block(
            Block::default()
                .title(" Recovery details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(details, columns[1]);
}

fn draw_entry_form(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(76, 23, area);

    frame.render_widget(Clear, popup);

    let (title, description) = match app.mode() {
        Mode::AddEntry => (
            " Add password ",
            "Create a login entry. Only the title is required.",
        ),
        Mode::EditEntry => (
            " Edit password ",
            "Update the selected login entry. Its vault ID will stay the same.",
        ),
        Mode::Create
        | Mode::Confirm
        | Mode::Unlock
        | Mode::Vault
        | Mode::AddNote
        | Mode::ConfirmDelete
        | Mode::RecentlyDeleted
        | Mode::Generator => return,
    };

    let outer = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(description).style(Style::default().fg(Color::Gray)),
        rows[0],
    );

    let fields = [
        AddField::Title,
        AddField::Username,
        AddField::Password,
        AddField::Url,
        AddField::Notes,
    ];

    for (index, field) in fields.into_iter().enumerate() {
        let label = match field {
            AddField::Title => " Title ",
            AddField::Username => " Username ",
            AddField::Password => " Password ",
            AddField::Url => " URL ",
            AddField::Notes => " Notes ",
        };

        let value = app.add_form().value(field);

        let display = if field == AddField::Password {
            Line::from("•".repeat(value.chars().count()))
        } else if value.is_empty() {
            Line::from(" ")
        } else {
            Line::from(value)
        };

        let selected = app.add_form().field() == field;

        let border_style = if selected {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let text_style = if field == AddField::Password {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default().fg(Color::White)
        };

        let field_widget = Paragraph::new(display).style(text_style).block(
            Block::default()
                .title(label)
                .borders(Borders::ALL)
                .border_style(border_style),
        );

        frame.render_widget(field_widget, rows[index + 1]);
    }

    frame.render_widget(
        Paragraph::new("Tab / Shift+Tab fields  •  Enter next/save  •  Ctrl+S save  •  Esc cancel")
            .style(Style::default().fg(Color::DarkGray)),
        rows[6],
    );
}

fn draw_note_form(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(80, 25, area);
    frame.render_widget(Clear, popup);

    let outer = Block::default()
        .title(" Add secure note ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(
            "Encrypted free-form note. Only the title is required; the body can span multiple lines.",
        )
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    let title_selected = app.note_form().field() == NoteField::Title;
    let title = app.note_form().value(NoteField::Title);
    frame.render_widget(
        Paragraph::new(if title.is_empty() { " " } else { title })
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .title(" Title ")
                    .borders(Borders::ALL)
                    .border_style(if title_selected {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    }),
            ),
        rows[1],
    );

    let body_selected = app.note_form().field() == NoteField::Body;
    let body = app.note_form().value(NoteField::Body);
    frame.render_widget(
        Paragraph::new(if body.is_empty() { " " } else { body })
            .style(Style::default().fg(Color::Gray))
            .block(
                Block::default()
                    .title(" Body ")
                    .borders(Borders::ALL)
                    .border_style(if body_selected {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    }),
            )
            .wrap(Wrap { trim: false }),
        rows[2],
    );

    frame.render_widget(
        Paragraph::new(
            "Tab fields  •  Enter title→body / new line  •  Ctrl+S or Ctrl+Enter save  •  Esc cancel",
        )
        .style(Style::default().fg(Color::DarkGray))
        .wrap(Wrap { trim: true }),
        rows[3],
    );
}

fn draw_delete_confirmation(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(66, 11, area);

    frame.render_widget(Clear, popup);

    let Some(entry) = app.selected_entry() else {
        return;
    };

    let outer = Block::default()
        .title(" Move to Recently Deleted ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("Move \""),
            Span::raw(entry.title.as_str()),
            Span::raw("\" out of the active vault?"),
        ]))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new("The entry will remain encrypted and recoverable.")
            .style(Style::default().fg(Color::Gray)),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new("Enter / y  Confirm    Esc / n  Cancel")
            .style(Style::default().fg(Color::DarkGray)),
        rows[2],
    );
}

fn draw_permanent_delete_confirmation(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(70, 13, area);

    frame.render_widget(Clear, popup);

    let Some(entry) = app.selected_deleted_entry() else {
        return;
    };

    let outer = Block::default()
        .title(" Permanently delete ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("Permanently delete \""),
            Span::raw(entry.title.as_str()),
            Span::raw("\"?"),
        ]))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new("This removes the item from the encrypted vault itself.")
            .style(Style::default().fg(Color::Red)),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new("This cannot be undone by BarePass.")
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        rows[2],
    );

    frame.render_widget(
        Paragraph::new("Enter / y  Delete forever    Esc / n  Keep item")
            .style(Style::default().fg(Color::DarkGray)),
        rows[3],
    );
}

fn draw_empty_recently_deleted_confirmation(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(72, 15, area);

    frame.render_widget(Clear, popup);

    let deleted_count = app
        .vault()
        .map(|vault| {
            vault
                .data()
                .entries
                .iter()
                .filter(|entry| entry.deleted_unix.is_some())
                .count()
        })
        .unwrap_or(0);

    let outer = Block::default()
        .title(" Empty Recently Deleted ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let inner = outer.inner(popup);

    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!(
            "Permanently delete all {deleted_count} recoverable item(s)?"
        ))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .wrap(Wrap { trim: true }),
        rows[0],
    );

    frame.render_widget(
        Paragraph::new("Every item in Recently Deleted will be destroyed.")
            .style(Style::default().fg(Color::Red)),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new("Active vault entries are not affected.")
            .style(Style::default().fg(Color::Green)),
        rows[2],
    );

    frame.render_widget(
        Paragraph::new("This cannot be undone by BarePass.")
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        rows[3],
    );

    frame.render_widget(
        Paragraph::new("Enter / y  Empty forever    Esc / n  Keep items")
            .style(Style::default().fg(Color::DarkGray)),
        rows[4],
    );
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let keys = match app.mode() {
        Mode::Vault if app.password_audit_open() => {
            if app.password_audit_show_weak() {
                "  Tab Reused   ↑↓/jk Findings   Esc Vault   l Lock   q Quit"
            } else {
                "  Tab Weak   ↑↓/jk Reuse groups   Esc Vault   l Lock   q Quit"
            }
        }
        Mode::Vault if app.vault_show_notes() => {
            "  Tab Deleted   g Generate   s Audit   a Add note   ↑↓/jk Select"
        }
        Mode::Vault if app.search_editing() => {
            "  Search typing   Enter Keep filter   Esc Clear   ↑↓ Select"
        }
        Mode::Vault if !app.search_query().is_empty() => {
            "  Tab Deleted   g Generate   s Audit   / Search   Esc Clear   u User   p Pass   v Reveal   e Edit"
        }
        Mode::Vault => {
            "  Tab Deleted   g Generate   s Audit   / Search   u User   p Pass   v Reveal   a Add   e Edit"
        }
        Mode::RecentlyDeleted => {
            "  r Restore   d Delete forever   x Empty all   Tab/Esc Active   ↑↓/jk Select"
        }
        Mode::AddEntry | Mode::EditEntry => {
            "  Tab Fields   Enter Next/Save   Ctrl+S Save   Esc Cancel"
        }
        Mode::AddNote => "  Ctrl+S Save   Tab Fields   Enter Next/New line   Esc Cancel",
        Mode::Generator => "  ←/→ Length   1-4 Sets   r Regenerate   c Copy   Esc Vault",
        Mode::ConfirmDelete => {
            if app.is_empty_recently_deleted_confirmation() {
                "  Enter/y Empty forever   Esc/n Cancel"
            } else if app.is_permanent_delete_confirmation() {
                "  Enter/y Delete forever   Esc/n Cancel"
            } else {
                "  Enter/y Confirm   Esc/n Cancel"
            }
        }
        Mode::Create | Mode::Confirm | Mode::Unlock => "  Enter Confirm   Esc Back/Quit",
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", app.status()),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(keys, Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}

fn format_unix_timestamp(timestamp: u64) -> String {
    let days_since_epoch = match i64::try_from(timestamp / 86_400) {
        Ok(days) => days,
        Err(_) => return format!("{timestamp} Unix seconds"),
    };

    let seconds_of_day = timestamp % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    let (year, month, day) = civil_from_days(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, u32, u32) {
    let adjusted = days_since_unix_epoch + 719_468;
    let era = if adjusted >= 0 {
        adjusted
    } else {
        adjusted - 146_096
    } / 146_097;

    let day_of_era = adjusted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;

    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);

    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };

    if month <= 2 {
        year += 1;
    }

    (year, month as u32, day as u32)
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);

    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}
