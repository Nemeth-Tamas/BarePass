use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::app::{App, Mode};

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
        Mode::Vault => draw_vault(frame, app, chunks[1]),
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
        Mode::Vault => return,
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
        Mode::Vault => "",
    };

    frame.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        rows[2],
    );
}

fn draw_vault(frame: &mut Frame, app: &App, area: Rect) {
    let Some(unlocked) = app.vault() else {
        return;
    };

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let active_entries: Vec<_> = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_none())
        .collect();

    let deleted_count = unlocked
        .data()
        .entries
        .iter()
        .filter(|entry| entry.deleted_unix.is_some())
        .count();

    let list_lines = if active_entries.is_empty() {
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
            .map(|entry| {
                Line::from(vec![
                    Span::styled(" > ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("#{}  {}", entry.id, entry.title),
                        Style::default().fg(Color::White),
                    ),
                ])
            })
            .collect()
    };

    let list = Paragraph::new(list_lines)
        .block(
            Block::default()
                .title(format!(
                    " Vault  {} active  /  {} deleted ",
                    active_entries.len(),
                    deleted_count
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(list, columns[0]);

    let details = if let Some(entry) = active_entries.first() {
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
            Line::from(""),
            Line::from(vec![
                Span::styled("Notes       ", Style::default().fg(Color::DarkGray)),
                Span::styled(entry.notes.as_str(), Style::default().fg(Color::Gray)),
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

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let keys = match app.mode() {
        Mode::Vault => "  l Lock   q Quit   Ctrl+C Quit",
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
