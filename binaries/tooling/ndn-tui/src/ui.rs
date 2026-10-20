//! Drawing the app: one function per screen and dialog, reading [`App`]
//! only. Every sentence comes from [`crate::words`] or is a label here;
//! names, keys, versions, fingerprints and codes appear in details.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};

use ndn_cert::report::{DataVerdict, MembershipRelation, RefreshState};
use ndn_cert::{InviteState, KitFormat};

use crate::app::{
    APPROVAL_ROLES, App, EXPIRIES, INVITE_ROLES, KIT_KINDS, KitAction, LinkKind, Modal,
    NEW_ROOT_STORES, Screen, Section, Started,
};
use crate::model::{Stream, Warning, now_secs};
use crate::words;

const ACCENT: Color = Color::Cyan;
const WARN: Color = Color::Yellow;
const BAD: Color = Color::Red;
const GOOD: Color = Color::Green;
const DIM: Color = Color::DarkGray;

fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

fn dim() -> Style {
    Style::new().fg(DIM)
}

fn selected() -> Style {
    Style::new().bg(Color::Blue).fg(Color::White)
}

/// The app drawn on a `width` × `height` screen, as text: one line per
/// row (for tests and screen captures).
pub fn render_text(app: &App, width: u16, height: u16) -> String {
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))
        .expect("a test backend never fails");
    terminal
        .draw(|f| draw(f, app))
        .expect("a test backend never fails");
    let buffer = terminal.backend().buffer();
    let mut out = String::with_capacity(usize::from(width + 1) * usize::from(height) * 3);
    for y in 0..buffer.area.height {
        let row: String = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect();
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

/// Draw the whole app.
pub fn draw(f: &mut Frame, app: &App) {
    // (The banner wraps: its height is measured at the screen's width.)
    let banner = banner(app);
    let hint_line = Line::from(Span::styled(hints_for(app), dim()));
    let hint_height = wrapped_height(std::slice::from_ref(&hint_line), f.area().width).min(3);
    let log_height = if app.details { 8 } else { 0 };
    let [title, banner_area, body, log, status, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(wrapped_height(&banner, f.area().width)),
        Constraint::Min(3),
        Constraint::Length(log_height),
        Constraint::Length(1),
        Constraint::Length(hint_height),
    ])
    .areas(f.area());
    draw_title(f, app, title);
    f.render_widget(
        Paragraph::new(banner).wrap(Wrap { trim: true }),
        banner_area,
    );
    match &app.screen {
        Screen::Prefixes => draw_prefixes(f, app, body),
        Screen::Prefix(ns) => draw_prefix(f, app, ns, body),
        Screen::Data => draw_data(f, app, body),
        Screen::Connections => draw_connections(f, app, body),
        Screen::Node => draw_node(f, app, body),
    }
    if app.details {
        draw_log(f, app, log);
    }
    if let Some((text, failed)) = &app.status {
        let style = if *failed {
            Style::new().fg(BAD)
        } else {
            Style::new().fg(GOOD)
        };
        f.render_widget(Paragraph::new(Span::styled(text.clone(), style)), status);
    }
    f.render_widget(Paragraph::new(hint_line).wrap(Wrap { trim: true }), hints);
    if let Some(modal) = &app.modal {
        draw_modal(f, app, modal);
    }
}

fn draw_title(f: &mut Frame, app: &App, area: Rect) {
    let node = app
        .model
        .identity
        .get()
        .and_then(|s| s.identity.clone())
        .unwrap_or_else(|| "no identity yet".into());
    let tab = |n: &str, label: &str, on: bool| {
        let style = if on {
            Style::new()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(ACCENT)
        };
        Span::styled(format!(" {n} {label} "), style)
    };
    let on_prefixes = matches!(app.screen, Screen::Prefixes | Screen::Prefix(_));
    let mut spans = vec![
        Span::styled(format!(" {} ", crate::APP_NAME), bold()),
        Span::raw("│ "),
        Span::raw(node),
        Span::raw(" │"),
        tab("1", "Trusted prefixes", on_prefixes),
        tab("2", "Data", app.screen == Screen::Data),
        tab("3", "Connections", app.screen == Screen::Connections),
        tab("4", "Node", app.screen == Screen::Node),
    ];
    if app.details {
        spans.push(Span::styled(" details ", Style::new().fg(WARN)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The lines above every screen: requests waiting for a decision, this
/// device's own waiting join, streams not followed.
fn banner(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let pending = app.model.pending();
    if !pending.is_empty() {
        let first = pending[0];
        let who = if first.device.is_empty() {
            first.key_name.clone()
        } else {
            first.device.clone()
        };
        let more = if pending.len() > 1 {
            format!(" (+{} more)", pending.len() - 1)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(" ! ", Style::new().fg(Color::Black).bg(WARN)),
            Span::styled(
                format!(
                    " {who} asks to join {} as {}. Code ",
                    first.namespace,
                    words::a_role(&first.role)
                ),
                Style::new().fg(WARN),
            ),
            Span::styled(
                first.code.clone(),
                Style::new().fg(WARN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{more}  [a] decide"), Style::new().fg(WARN)),
        ]));
    }
    if let Some(w) = &app.waiting {
        lines.push(Line::from(vec![
            Span::styled(" … ", Style::new().fg(Color::Black).bg(ACCENT)),
            Span::styled(
                format!(
                    " Waiting for an admin of {} to approve this device. Code ",
                    w.pending.namespace
                ),
                Style::new().fg(ACCENT),
            ),
            Span::styled(
                w.pending.code.clone(),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  [w] show", Style::new().fg(ACCENT)),
        ]));
    }
    for (stream, down) in [
        (Stream::Trust, &app.model.trust_stream),
        (Stream::Links, &app.model.links_stream),
    ] {
        if let Some(failure) = down {
            let what = match stream {
                Stream::Trust => "trust changes",
                Stream::Links => "connection changes",
            };
            lines.push(Line::from(Span::styled(
                format!(" Not following {what} live: {}", failure.words()),
                Style::new().fg(BAD),
            )));
        }
    }
    lines
}

fn hints_for(app: &App) -> String {
    if app.modal.is_some() {
        return String::new();
    }
    let common = "d details · u check now · j join/follow · q quit";
    match &app.screen {
        Screen::Prefixes => format!(
            "↑↓ select · Enter open · a decide requests · n new trusted prefix · r recover · {common}"
        ),
        Screen::Prefix(ns) => {
            let powers = app.model.powers(ns);
            let mut keys = vec!["Esc back", "Tab section"];
            match app.section {
                Section::Requests => keys.extend(["a approve", "n deny"]),
                Section::Members if powers.root => keys.push("x remove device"),
                Section::Invites => keys.push("w withdraw"),
                Section::Kits => keys.push("x revoke kit"),
                _ => {}
            }
            if powers.invite {
                keys.push("i invite");
            }
            if powers.root {
                keys.extend(["k new kit", "c check kit", "m move main key"]);
            }
            keys.push("s schema");
            format!("{} · {common}", keys.join(" · "))
        }
        Screen::Data => format!("↑↓ select · Enter fetch & check · / fetch a name · {common}"),
        Screen::Connections => {
            format!("↑↓ select · m change mode · c connect · x disconnect · {common}")
        }
        Screen::Node => common.to_owned(),
    }
}

/// How many rows `lines` take wrapped at `width` (word wrapping can take
/// a little more than the character count: one row of slack per line).
fn wrapped_height(lines: &[Line], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    lines
        .iter()
        .map(|l| {
            let len = l.width();
            if len <= width {
                1
            } else {
                len.div_ceil(width) + 1
            }
        })
        .sum::<usize>()
        .try_into()
        .unwrap_or(u16::MAX)
}

fn block(title: impl Into<String>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(dim())
        .title(Span::styled(format!(" {} ", title.into()), bold()))
}

/// A date of an ISO 8601 time (`2027-01-16T…`, `20270116T…`).
pub fn date(iso: &str) -> String {
    let digits: String = iso
        .chars()
        .take_while(|c| *c != 'T')
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.len() == 8 {
        format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..])
    } else {
        iso.to_owned()
    }
}

/// `secs` (Unix) relative to now: "in 3 h", "2 d ago".
pub fn relative(secs: u64) -> String {
    let now = now_secs();
    let (span, future) = if secs >= now {
        (secs - now, true)
    } else {
        (now - secs, false)
    };
    let text = if span < 120 {
        format!("{span} s")
    } else if span < 7_200 {
        format!("{} min", span / 60)
    } else if span < 172_800 {
        format!("{} h", span / 3_600)
    } else {
        format!("{} days", span / 86_400)
    };
    if future {
        format!("in {text}")
    } else {
        format!("{text} ago")
    }
}

fn trust_state(version: u64, state: Option<RefreshState>) -> (String, Style) {
    let (word, style) = match state {
        None => ("not checked yet", dim()),
        Some(RefreshState::Current) => ("current", Style::new().fg(GOOD)),
        Some(RefreshState::Updated) => ("just updated", Style::new().fg(GOOD)),
        Some(RefreshState::Source) => ("made here", Style::new().fg(GOOD)),
        Some(RefreshState::Behind) => ("behind", Style::new().fg(WARN)),
        Some(RefreshState::UpstreamOlder) => ("newer than what answered", Style::new().fg(WARN)),
        Some(RefreshState::Unreachable) => ("could not check", Style::new().fg(WARN)),
        Some(RefreshState::Failed) => ("check failed", Style::new().fg(BAD)),
    };
    (format!("version {version} · {word}"), style)
}

fn warning_line(w: &Warning) -> Line<'static> {
    let text = match w {
        Warning::NoRecoveryKit { namespace } => format!(
            "{namespace} has no recovery kit: if this main device is lost, so is the trusted prefix. Open it and press k."
        ),
        Warning::PlainRootKey { namespace, .. } => format!(
            "The main key of {namespace} is kept in a plain file that nothing protects. Open it and press m to move it."
        ),
    };
    Line::from(vec![
        Span::styled(" ⚠ ", Style::new().fg(Color::Black).bg(WARN)),
        Span::styled(format!(" {text}"), Style::new().fg(WARN)),
    ])
}

fn draw_prefixes(f: &mut Frame, app: &App, area: Rect) {
    let warnings: Vec<Line> = app.model.warnings().iter().map(warning_line).collect();
    let [warn_area, table_area] = Layout::vertical([
        Constraint::Length(wrapped_height(&warnings, area.width)),
        Constraint::Min(3),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(warnings).wrap(Wrap { trim: true }),
        warn_area,
    );

    let rows = app.model.prefixes();
    if rows.is_empty()
        && app.model.memberships.get().is_some()
        && app.model.memberships.failure.is_none()
    {
        draw_first_run(f, app, table_area);
        return;
    }
    let mut header = vec!["Trusted prefix", "This device", "Trust", "Waiting"];
    if app.details {
        header.extend(["Signs as", "Root fingerprint"]);
    }
    let table_rows: Vec<Row> = rows
        .iter()
        .map(|r| {
            let (trust, style) = trust_state(r.version, r.state);
            let waiting = if r.pending > 0 {
                Cell::from(Span::styled(
                    format!("{} to approve", r.pending),
                    Style::new().fg(WARN),
                ))
            } else {
                Cell::from("")
            };
            let mut cells = vec![
                Cell::from(Span::styled(r.namespace.clone(), bold())),
                Cell::from(words::relation(r.relation, &r.role)),
                Cell::from(Span::styled(trust, style)),
                waiting,
            ];
            if app.details {
                let m = app.model.membership(&r.namespace);
                cells.push(Cell::from(
                    m.map(|m| m.identity.clone()).unwrap_or_default(),
                ));
                cells.push(Cell::from(
                    m.map(|m| m.root_fingerprint.clone()).unwrap_or_default(),
                ));
            }
            Row::new(cells)
        })
        .collect();
    let mut widths = vec![
        Constraint::Percentage(28),
        Constraint::Percentage(22),
        Constraint::Min(28),
        Constraint::Length(13),
    ];
    if app.details {
        widths = vec![
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Length(28),
            Constraint::Length(13),
            Constraint::Length(26),
            Constraint::Min(16),
        ];
    }
    let title = match (&app.model.memberships.failure, rows.is_empty()) {
        (Some(f), _) => format!("Trusted prefixes — {}", f.words()),
        (None, true) => "Trusted prefixes — reading…".into(),
        (None, false) => "Trusted prefixes".into(),
    };
    let table = Table::new(table_rows, widths)
        .header(Row::new(header).style(dim()))
        .block(block(title))
        .row_highlight_style(selected());
    let mut state = TableState::default().with_selected((!rows.is_empty()).then_some(app.selected));
    f.render_stateful_widget(table, table_area, &mut state);
}

/// The home screen of a device that holds no trusted prefix yet: what it
/// can do first.
fn draw_first_run(f: &mut Frame, app: &App, area: Rect) {
    let node = app.model.identity.get().and_then(|s| s.identity.clone());
    let choice = |key: &str, what: &str, how: &str| {
        vec![
            Line::from(vec![
                Span::styled(format!(" {key} "), Style::new().fg(Color::Black).bg(ACCENT)),
                Span::styled(format!("  {what}"), bold()),
            ]),
            Line::from(Span::raw(format!("     {how}"))),
            Line::from(""),
        ]
    };
    let mut text = vec![
        Line::from(
            "This device holds no trusted prefix yet. A trusted prefix is a name, like /home, that your devices share: each trusts the data the others publish under it.",
        ),
        Line::from(""),
    ];
    text.extend(choice(
        "j",
        "Join or follow a trusted prefix",
        "Paste an invite, or an anchor link from a device that has the prefix.",
    ));
    text.extend(choice(
        "n",
        "Start a new trusted prefix",
        "This device becomes its main device: it holds the main key and lets other devices in.",
    ));
    text.extend(choice(
        "r",
        "I lost my main device",
        "Make this device the main device of a trusted prefix again, with its recovery kit.",
    ));
    if app.details {
        text.push(Line::from(Span::styled(
            format!(
                "node identity {} · key storage {}",
                node.unwrap_or_else(|| "none".into()),
                app.pib
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "not known yet".into())
            ),
            dim(),
        )));
    }
    f.render_widget(
        Paragraph::new(Text::from(text))
            .block(block("Welcome"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// A titled list of lines, the selected one highlighted when the section
/// has the focus.
fn section_block(
    f: &mut Frame,
    area: Rect,
    title: String,
    rows: Vec<Line<'static>>,
    focus: bool,
    at: usize,
    empty: &str,
) {
    let border = if focus {
        Style::new().fg(ACCENT)
    } else {
        dim()
    };
    let b = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(format!(" {title} "), bold()));
    if rows.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(empty.to_owned(), dim())).block(b),
            area,
        );
        return;
    }
    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(i, l)| {
            if focus && i == at {
                l.style(selected())
            } else {
                l
            }
        })
        .collect();
    let height = area.height.saturating_sub(2) as usize;
    let scroll = at.saturating_sub(height.saturating_sub(1)) as u16;
    f.render_widget(Paragraph::new(lines).block(b).scroll((scroll, 0)), area);
}

fn draw_prefix(f: &mut Frame, app: &App, ns: &str, area: Rect) {
    let model = &app.model;
    let membership = model.membership(ns);
    let powers = model.powers(ns);
    let sections = app.sections(ns);

    // About: what it is and this device's place in it.
    let mut about: Vec<Line> = Vec::new();
    match membership {
        Some(m) => {
            let (trust, style) = trust_state(m.version, model.refreshed.get(ns).map(|r| r.state));
            about.push(Line::from(vec![
                Span::raw("This device: "),
                Span::styled(words::relation(m.relation, &m.role).to_owned(), bold()),
                Span::raw("   "),
                Span::styled(trust, style),
            ]));
            if !m.identity.is_empty() {
                about.push(Line::from(format!(
                    "Publishes as {}{}",
                    m.identity,
                    if m.valid_until.is_empty() {
                        String::new()
                    } else {
                        format!(", certified until {}", date(&m.valid_until))
                    }
                )));
            } else if m.relation == MembershipRelation::Following {
                about.push(Line::from(
                    "Following: this device checks data of this prefix but does not publish in it.",
                ));
            }
            if app.details {
                about.push(Line::from(Span::styled(format!("key {}", m.key), dim())));
                about.push(Line::from(Span::styled(
                    format!("root fingerprint {}", m.root_fingerprint),
                    dim(),
                )));
                if let Some(r) = model.refreshed.get(ns) {
                    about.push(Line::from(Span::styled(
                        format!(
                            "last check [{}] {}",
                            r.detail.code,
                            words::detail(&r.detail)
                        ),
                        dim(),
                    )));
                }
            }
        }
        None => about.push(Line::from(
            "This device no longer holds this trusted prefix.",
        )),
    }
    if let Some(root) = model.root_of(ns) {
        let kits = root.kits().count();
        about.push(Line::from(vec![
            Span::raw(format!(
                "Main key: kept in {}. ",
                words::root_store(&root.store)
            )),
            if kits == 0 {
                Span::styled("No recovery kit yet.", Style::new().fg(WARN))
            } else {
                Span::raw(format!(
                    "{kits} recovery kit{}.",
                    if kits == 1 { "" } else { "s" }
                ))
            },
        ]));
        if app.details {
            about.push(Line::from(Span::styled(
                format!("main key {} at {}", root.key, root.location),
                dim(),
            )));
        }
    }

    let section_heights: Vec<Constraint> = sections.iter().map(|_| Constraint::Min(4)).collect();
    let mut constraints = vec![Constraint::Length(about.len() as u16 + 2)];
    constraints.extend(section_heights);
    let areas = Layout::vertical(constraints).split(area);
    f.render_widget(
        Paragraph::new(about)
            .block(block(ns.to_owned()))
            .wrap(Wrap { trim: true }),
        areas[0],
    );

    for (i, section) in sections.iter().enumerate() {
        let focus = app.section == *section;
        let at = if focus { app.selected } else { 0 };
        let area = areas[i + 1];
        match section {
            Section::Requests => {
                let rows: Vec<Line> = model
                    .pending_in(ns)
                    .iter()
                    .map(|r| {
                        let who = if r.device.is_empty() {
                            r.key_name.clone()
                        } else {
                            r.device.clone()
                        };
                        let mut spans = vec![
                            Span::styled(
                                format!("{:<8}", r.code),
                                Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(format!(" {who} asks to join as {}", words::a_role(&r.role))),
                            Span::styled(format!(" · expires {}", relative(r.expires_secs)), dim()),
                        ];
                        if app.details {
                            spans.push(Span::styled(
                                format!(" · {} · {}", r.request_id, r.key_name),
                                dim(),
                            ));
                        }
                        Line::from(spans)
                    })
                    .collect();
                section_block(
                    f,
                    area,
                    "Waiting for approval".into(),
                    rows,
                    focus,
                    at,
                    "Nobody is waiting.",
                );
            }
            Section::Members => {
                let members = model.members_in(ns);
                let rows: Vec<Line> = members
                    .iter()
                    .map(|m| {
                        let name = m.device.clone().unwrap_or_else(|| m.identity.clone());
                        let role = m.role.as_deref().map(words::role).unwrap_or_default();
                        let mut spans = vec![
                            Span::styled(
                                format!("{name:<16}"),
                                if m.revoked { dim() } else { bold() },
                            ),
                            Span::raw(format!(" {role:<17}")),
                            if m.revoked {
                                Span::styled(" removed", Style::new().fg(BAD))
                            } else {
                                Span::raw(format!(" certified until {}", date(&m.valid_until)))
                            },
                        ];
                        if app.details {
                            spans.push(Span::styled(
                                format!(" · {} · {}", m.identity, m.certificate),
                                dim(),
                            ));
                        }
                        Line::from(spans)
                    })
                    .collect();
                let empty = if model.issued.get().is_some() || powers.invite {
                    "No device was certified here yet."
                } else {
                    "Members are listed on the main device of this prefix."
                };
                section_block(f, area, "Members".into(), rows, focus, at, empty);
            }
            Section::Invites => {
                let rows: Vec<Line> = model
                    .invites_in(ns)
                    .iter()
                    .map(|i| {
                        let state = match i.info.state {
                            InviteState::Outstanding => Span::styled("open", Style::new().fg(GOOD)),
                            InviteState::Expired => Span::styled("expired", dim()),
                            InviteState::Redeemed => Span::styled("used", dim()),
                            InviteState::Withdrawn => Span::styled("withdrawn", dim()),
                        };
                        let mut spans = vec![
                            Span::raw(format!(
                                "{:<16} ",
                                i.info.role.as_deref().map(words::role).unwrap_or_default()
                            )),
                            state,
                        ];
                        if let Some(d) = &i.info.device {
                            spans.push(Span::raw(format!(" · for {d}")));
                        }
                        if i.info.state == InviteState::Outstanding {
                            spans.push(Span::styled(
                                match i.info.expires_secs {
                                    Some(e) => format!(" · expires {}", relative(e)),
                                    None => " · until used or withdrawn".into(),
                                },
                                dim(),
                            ));
                        }
                        if app.details {
                            if let Some(r) = &i.info.redeemed_for {
                                spans.push(Span::styled(format!(" · {r}"), dim()));
                            }
                            spans.push(Span::styled(
                                format!(" · id {} · made by {}", i.id, i.info.created_by),
                                dim(),
                            ));
                        }
                        Line::from(spans)
                    })
                    .collect();
                section_block(
                    f,
                    area,
                    "Invites".into(),
                    rows,
                    focus,
                    at,
                    "No invites. Press i to make one.",
                );
            }
            Section::Kits => {
                let rows: Vec<Line> = model
                    .root_of(ns)
                    .map(|r| {
                        r.kits()
                            .map(|k| {
                                let mut spans = vec![Span::raw(format!(
                                    "recovery kit {}",
                                    short(&k.fingerprint)
                                ))];
                                if app.details {
                                    spans.push(Span::styled(
                                        format!(" · {} · {}", k.key, k.fingerprint),
                                        dim(),
                                    ));
                                }
                                Line::from(spans)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                section_block(
                    f,
                    area,
                    "Recovery kits".into(),
                    rows,
                    focus,
                    at,
                    "No recovery kit. Press k to make one (24 words, a file, or a security key).",
                );
            }
        }
    }
}

/// The first 8 hex digits of a fingerprint.
fn short(hex: &str) -> &str {
    &hex[..hex.len().min(8)]
}

fn draw_data(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.data_rows();
    let cached = app.model.cached.get();
    let table_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, (name, served))| {
            let vouch = app
                .model
                .vouching(name)
                .map(str::to_owned)
                .unwrap_or_else(|| "none held".into());
            let mut cells = vec![
                Cell::from(name.clone()),
                Cell::from(if *served { "served here" } else { "cached" }),
                Cell::from(vouch),
            ];
            if app.details {
                let entry = (!served)
                    .then(|| cached.and_then(|c| c.entries.get(i - (rows.len() - c.entries.len()))))
                    .flatten();
                cells.push(Cell::from(match entry {
                    Some(e) => format!(
                        "{} bytes{}",
                        e.bytes,
                        if e.fresh { ", fresh" } else { ", stale" }
                    ),
                    None => String::new(),
                }));
            }
            Row::new(cells)
        })
        .collect();
    let mut widths = vec![
        Constraint::Percentage(55),
        Constraint::Length(12),
        Constraint::Percentage(30),
    ];
    if app.details {
        widths.push(Constraint::Length(20));
    }
    let mut title = "Data — what this device serves and holds".to_owned();
    if let Some(c) = cached
        && c.total > 0
    {
        // The list reads further pages as the selection nears its end.
        title.push_str(&format!(
            " ({} cached name{})",
            c.total,
            if c.total == 1 { "" } else { "s" }
        ));
    }
    if let Some(failure) = &app.model.cached.failure {
        title.push_str(&format!(" — cache: {}", failure.words()));
    }
    let mut header = vec!["Name", "Here", "Vouched for by"];
    if app.details {
        header.push("Cache entry");
    }
    let table = Table::new(table_rows, widths)
        .header(Row::new(header).style(dim()))
        .block(block(title))
        .row_highlight_style(selected());
    let mut state = TableState::default().with_selected((!rows.is_empty()).then_some(app.selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_connections(f: &mut Frame, app: &App, area: Rect) {
    let Some(listing) = app.model.links.get() else {
        let text = match &app.model.links.failure {
            Some(failure) => failure.words(),
            None => "Reading the connections…".into(),
        };
        f.render_widget(
            Paragraph::new(text)
                .block(block("Connections"))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };
    let relays: Vec<_> = listing.links.iter().filter(|l| l.relay.is_some()).collect();
    let [links_area, relays_area, serve_area] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(relays.len() as u16 + 3),
        Constraint::Length(if listing.serve.is_some() { 3 } else { 0 }),
    ])
    .areas(area);

    let rows: Vec<Row> = listing
        .links
        .iter()
        .map(|l| {
            let peer = match &l.device {
                Some(d) if d.to_string() != l.label => format!("{} ({d})", l.label),
                _ => l.label.clone(),
            };
            let carries = app.model.carried_by(l).join(", ");
            let (path, rtt) = match l
                .paths
                .iter()
                .find(|p| p.kind == "direct")
                .or(l.paths.first())
            {
                Some(p) => (
                    match p.kind.as_str() {
                        "direct" => "direct path".to_owned(),
                        "relay" => format!("through relay {}", p.via.clone().unwrap_or_default()),
                        _ => "connected".to_owned(),
                    },
                    p.rtt_micros
                        .map(|r| format!("{} ms", r / 1000))
                        .unwrap_or_default(),
                ),
                None if l.asleep.is_some() => ("asleep".to_owned(), String::new()),
                None => ("offline".to_owned(), String::new()),
            };
            let why = l
                .down
                .as_ref()
                .or(l.direct.as_ref())
                .map(words::link_detail)
                .unwrap_or_default();
            let mut cells = vec![
                Cell::from(peer),
                Cell::from(if carries.is_empty() {
                    "—".to_owned()
                } else {
                    carries
                }),
                Cell::from(path),
                Cell::from(rtt),
                Cell::from(
                    l.mode
                        .clone()
                        .map(|m| mode_words(&m).to_owned())
                        .unwrap_or_default(),
                ),
                Cell::from(why),
            ];
            if app.details {
                cells.push(Cell::from(format!(
                    "{} {}",
                    l.direct_state,
                    l.key.map(|k| crate::daemon::hex(&k)).unwrap_or_default()
                )));
            }
            Row::new(cells)
        })
        .collect();
    let mut widths = vec![
        Constraint::Percentage(24),
        Constraint::Percentage(16),
        Constraint::Percentage(15),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Min(10),
    ];
    let mut header = vec!["Device", "Carries", "Path", "RTT", "Mode", "Why"];
    if app.details {
        widths.push(Constraint::Length(30));
        header.push("Direct state · key");
    }
    let n = listing.links.len();
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(dim()))
        .block(block(
            "Connections — they carry the data of every trusted prefix",
        ))
        .row_highlight_style(selected());
    let mut state = TableState::default().with_selected((n > 0).then_some(app.selected));
    f.render_stateful_widget(table, links_area, &mut state);

    let relay_rows: Vec<Row> = relays
        .iter()
        .map(|l| {
            let r = l.relay.as_ref().expect("filtered");
            let source = match r.source.strip_prefix("namespace:") {
                Some(ns) => format!("from {ns}"),
                None => "added on this device".to_owned(),
            };
            Row::new(vec![
                Cell::from(l.label.clone()),
                Cell::from(source),
                Cell::from(
                    l.mode
                        .clone()
                        .map(|m| mode_words(&m).to_owned())
                        .unwrap_or_default(),
                ),
                Cell::from(
                    r.detail
                        .as_ref()
                        .map(words::link_detail)
                        .unwrap_or_else(|| r.state.clone()),
                ),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            relay_rows,
            [
                Constraint::Percentage(20),
                Constraint::Percentage(25),
                Constraint::Length(12),
                Constraint::Min(10),
            ],
        )
        .header(Row::new(vec!["Relay", "Source", "Mode", "State"]).style(dim()))
        .block(block(if relays.is_empty() {
            "Relays — none: devices are reached over their own links"
        } else {
            "Relays"
        })),
        relays_area,
    );
    if let Some(serve) = &listing.serve {
        f.render_widget(
            Paragraph::new(words::link_detail(serve))
                .block(block("As a relay"))
                .wrap(Wrap { trim: true }),
            serve_area,
        );
    }
}

fn mode_words(mode: &str) -> &'static str {
    match mode {
        "always" => "always",
        "on-demand" => "when needed",
        "off" => "off",
        _ => "other",
    }
}

fn draw_node(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match app.model.identity.get() {
        Some(s) => {
            lines.push(Line::from(vec![
                Span::raw("Node identity: "),
                Span::styled(s.identity.clone().unwrap_or_else(|| "none".into()), bold()),
            ]));
            if s.is_ephemeral {
                lines.push(Line::from(Span::styled(
                    "A temporary key made at startup: this device has no lasting identity yet.",
                    Style::new().fg(WARN),
                )));
            }
            if let Some(source) = s.node_identity_source {
                lines.push(Line::from(format!(
                    "Why this one: {}",
                    match source.as_str() {
                        "configured" => "the configuration names it",
                        "pib-default" => "it is the default identity of the key storage",
                        "root-device" => "this is the main device of its trusted prefix",
                        "first-enrolled" => "it is the oldest certified identity",
                        _ => "a key made at startup",
                    }
                )));
            }
            if let (Some(until), Some(days)) = (&s.valid_until, s.days_left) {
                let style = if days < 0.0 {
                    Style::new().fg(BAD)
                } else if days < 14.0 {
                    Style::new().fg(WARN)
                } else {
                    Style::default()
                };
                lines.push(Line::from(Span::styled(
                    format!("Certified until {} ({:.0} days)", date(until), days),
                    style,
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Signs data as", bold())));
            for id in &s.signing_identities {
                let mut spans = vec![Span::raw(format!("  {}", id.identity))];
                if app.details {
                    spans.push(Span::styled(format!("  {}", id.key), dim()));
                }
                lines.push(Line::from(spans));
            }
            if !s.root_stores.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled("Main device of", bold())));
                for r in &s.root_stores {
                    let mut spans = vec![Span::raw(format!(
                        "  {} — main key kept in {}",
                        r.namespace,
                        words::root_store(&r.kind)
                    ))];
                    if app.details {
                        spans.push(Span::styled(format!("  {}", r.key), dim()));
                    }
                    lines.push(Line::from(spans));
                }
            }
            if app.details {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("key {}", s.key.clone().unwrap_or_default()),
                    dim(),
                )));
                lines.push(Line::from(Span::styled(
                    format!("key storage {}", s.pib_path),
                    dim(),
                )));
                lines.push(Line::from(Span::styled(
                    format!("management socket {}", app.socket),
                    dim(),
                )));
            }
        }
        None => lines.push(Line::from(
            app.model
                .identity
                .failure
                .as_ref()
                .map(|f| f.words())
                .unwrap_or_else(|| "Reading…".into()),
        )),
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Node"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .model
        .log
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|l| {
            let secs = l.at % 86_400;
            Line::from(vec![
                Span::styled(
                    format!("{:02}:{:02}:{:02} ", secs / 3600, secs / 60 % 60, secs % 60),
                    dim(),
                ),
                Span::styled(format!("{:<19} ", l.kind), Style::new().fg(ACCENT)),
                Span::raw(l.text.clone()),
                Span::styled(format!("  #{}", l.seq), dim()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block("Events (UTC)")), area);
}

/// A centered area `w` × `h` (clamped to `area`).
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn dialog(f: &mut Frame, title: impl Into<String>, text: Text<'static>, w: u16, h: u16) {
    let area = centered(f.area(), w, h);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(ACCENT))
                    .title(Span::styled(format!(" {} ", title.into()), bold())),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// `482 913` spread out for comparing: `4 8 2   9 1 3`.
pub fn spread(code: &str) -> String {
    code.split_whitespace()
        .map(|group| {
            group
                .chars()
                .map(String::from)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("   ")
}

fn field(label: &str, value: String, focus: bool) -> Line<'static> {
    let style = if focus {
        Style::new().fg(Color::Black).bg(ACCENT)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(format!("{label:<14}"), dim()),
        Span::styled(value, style),
    ])
}

fn draw_modal(f: &mut Frame, app: &App, modal: &Modal) {
    let width = f.area().width.saturating_sub(4).min(90);
    match modal {
        Modal::Busy(what) => dialog(f, "Working", Text::from(what.clone()), 50, 3),
        Modal::Message { title, lines } => {
            let mut text: Vec<Line> = lines.iter().map(|l| Line::from(l.clone())).collect();
            text.push(Line::from(""));
            text.push(Line::from(Span::styled("Enter close", dim())));
            dialog(
                f,
                title.clone(),
                Text::from(text),
                width,
                lines.len() as u16 * 2 + 4,
            );
        }
        Modal::Approve(row) => {
            let who = if row.device.is_empty() {
                row.key_name.clone()
            } else {
                row.device.clone()
            };
            let text = vec![
                Line::from(format!(
                    "\"{who}\" asks to join {} as {}.",
                    row.namespace,
                    words::a_role(&row.role)
                )),
                Line::from(""),
                Line::from(format!("Check that {who} shows the same code:")),
                Line::from(""),
                Line::from(Span::styled(
                    spread(&row.code),
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Center),
                Line::from(""),
                Line::from(
                    "Approve only if the codes match: a different code means a different device.",
                ),
                Line::from(Span::styled(
                    if app.details {
                        format!("request {} · key {}", row.request_id, row.key_name)
                    } else {
                        String::new()
                    },
                    dim(),
                )),
                Line::from(""),
                Line::from(Span::styled("a approve · n deny… · Esc later", bold())),
            ];
            dialog(f, "Approve a device", Text::from(text), width, 15);
        }
        Modal::Deny { row, reason } => {
            let text = vec![
                Line::from(format!("Deny {} (code {})?", row.device, row.code)),
                Line::from(""),
                field("Reason", format!("{}▏", reason.text), true),
                Line::from(""),
                Line::from(Span::styled("Enter deny · Esc cancel", bold())),
            ];
            dialog(f, "Deny a device", Text::from(text), width, 8);
        }
        Modal::Invite(form) => {
            let text = vec![
                Line::from(format!("A new invite to {}.", form.namespace)),
                Line::from(""),
                field(
                    "Role",
                    format!("‹ {} ›", words::role(INVITE_ROLES[form.role])),
                    form.field == 0,
                ),
                field(
                    "Expires",
                    format!("‹ {} ›", EXPIRIES[form.expiry].0),
                    form.field == 1,
                ),
                field(
                    "Device name",
                    format!("{}▏", form.device.text),
                    form.field == 2,
                ),
                Line::from(Span::styled(
                    "  (a suggestion for the new device; optional)",
                    dim(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Tab field · < > change · Enter make · Esc cancel",
                    bold(),
                )),
            ];
            dialog(f, "Invite a device", Text::from(text), width, 11);
        }
        Modal::InviteMade(invite) => draw_invite(f, app, invite),
        Modal::Join(form) => {
            let what = match &form.kind {
                LinkKind::Unknown(None) => {
                    "Paste an anchor link (to follow a prefix) or an invite (to join one)."
                        .to_owned()
                }
                LinkKind::Unknown(Some(why)) => why.clone(),
                LinkKind::Anchor { namespace } => format!(
                    "An anchor link of {}: follow it (f), or ask an admin to let this device join as the role below (Enter).",
                    namespace
                        .clone()
                        .unwrap_or_else(|| "a trusted prefix".into())
                ),
                LinkKind::Invite { scope, .. } => {
                    format!("An invite to join as {scope}/<device name>: press Enter to join.")
                }
            };
            let mut text = vec![
                field(
                    "Link",
                    format!("{}▏", ellipsis(&form.link.text, width as usize - 20)),
                    form.field == 0,
                ),
                Line::from(""),
                Line::from(what),
                Line::from(""),
                field(
                    "Device name",
                    format!("{}▏", form.device.text),
                    form.field == 1,
                ),
            ];
            if matches!(form.kind, LinkKind::Anchor { .. }) {
                text.push(field(
                    "Role",
                    format!("‹ {} ›", words::role(APPROVAL_ROLES[form.role])),
                    form.field == 2,
                ));
            }
            if let Some(identity) = form.identity() {
                text.push(Line::from(Span::styled(
                    format!("Joins as {identity}"),
                    dim(),
                )));
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                "Tab field · on Role: < > change, f follow only · Enter join · Esc cancel",
                bold(),
            )));
            dialog(
                f,
                "Follow or join a trusted prefix",
                Text::from(text),
                width,
                14,
            );
        }
        Modal::Waiting(w) => {
            let text = vec![
                Line::from(format!(
                    "This device asked to join {} as {}.",
                    w.pending.namespace, w.pending.identity
                )),
                Line::from(""),
                Line::from(
                    "Ask an admin to approve it on their device. Their screen shows this code:",
                ),
                Line::from(""),
                Line::from(Span::styled(
                    spread(&w.pending.code),
                    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Center),
                Line::from(""),
                Line::from(if w.pending.expires.is_empty() {
                    "This screen updates by itself when they decide.".to_owned()
                } else {
                    format!(
                        "The request expires {}. This screen updates by itself when they decide.",
                        date(&w.pending.expires)
                    )
                }),
                Line::from(Span::styled(
                    if app.details {
                        format!("request {} · key {}", w.pending.request, w.pending.key)
                    } else {
                        String::new()
                    },
                    dim(),
                )),
                Line::from(Span::styled("Esc hide (keeps waiting)", bold())),
            ];
            dialog(f, "Waiting for approval", Text::from(text), width, 13);
        }
        Modal::Remove { namespace, member } => {
            let name = member
                .device
                .clone()
                .unwrap_or_else(|| member.identity.clone());
            let text = vec![
                Line::from(format!("Remove {name} from {namespace}?")),
                Line::from(""),
                Line::from(format!(
                    "It will no longer be able to publish or be trusted in {namespace}. It can be added again later with a new invite."
                )),
                Line::from("The main key signs this change: you will be asked to unlock it here."),
                Line::from(Span::styled(
                    if app.details {
                        member.identity.clone()
                    } else {
                        String::new()
                    },
                    dim(),
                )),
                Line::from(""),
                Line::from(Span::styled("y remove · Esc cancel", bold())),
            ];
            dialog(f, "Remove a device", Text::from(text), width, 10);
        }
        Modal::Kit {
            namespace,
            action,
            path,
        } => {
            let verb = match action {
                KitAction::Create => "Make a recovery kit for",
                KitAction::Check => "Check a recovery kit of",
            };
            let mut text = vec![
                Line::from(format!("{verb} {namespace}.")),
                Line::from("A recovery kit makes a new main device if this one is lost."),
                Line::from(""),
            ];
            match path {
                Some(p) => {
                    text.push(field("Kit file", format!("{}▏", p.text), true));
                    text.push(Line::from(""));
                    text.push(Line::from(Span::styled("Enter go · Esc cancel", bold())));
                }
                None => {
                    text.push(Line::from("w  24 recovery words (write them down)"));
                    text.push(Line::from("f  a file protected by a passphrase"));
                    text.push(Line::from("h  a key on a second security key (YubiKey)"));
                    text.push(Line::from(""));
                    text.push(Line::from(Span::styled(
                        "w / f / h choose · Esc cancel",
                        bold(),
                    )));
                }
            }
            dialog(f, "Recovery kit", Text::from(text), width, 10);
        }
        Modal::RevokeKit { namespace, key } => {
            let text = vec![
                Line::from(format!("Revoke this recovery kit of {namespace}?")),
                Line::from("It will no longer be able to recover the prefix."),
                Line::from(Span::styled(
                    if app.details {
                        key.clone()
                    } else {
                        String::new()
                    },
                    dim(),
                )),
                Line::from(""),
                Line::from(Span::styled("y revoke · Esc cancel", bold())),
            ];
            dialog(f, "Revoke a recovery kit", Text::from(text), width, 8);
        }
        Modal::KitWords { namespace, words } => {
            let mut text = vec![
                Line::from(format!(
                    "The recovery words of {namespace}. Write them down now:"
                )),
                Line::from(
                    "they are shown this once, and they are all it takes to take over the prefix.",
                ),
                Line::from(""),
            ];
            let list: Vec<&str> = words.split_whitespace().collect();
            for chunk in list.chunks(6).enumerate() {
                let (row, group) = chunk;
                text.push(Line::from(
                    group
                        .iter()
                        .enumerate()
                        .map(|(i, w)| format!("{:>2}. {w:<10}", row * 6 + i + 1))
                        .collect::<String>(),
                ));
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                "Enter done (the words are erased from this screen)",
                bold(),
            )));
            dialog(f, "Recovery words", Text::from(text), width, 12);
        }
        Modal::MoveRoot { namespace } => {
            let current = app
                .model
                .root_of(namespace)
                .map(|r| words::root_store(&r.store))
                .unwrap_or_default();
            let text = vec![
                Line::from(format!("The main key of {namespace} is kept in {current}.")),
                Line::from("Move it to:"),
                Line::from(""),
                Line::from("k  the system keychain"),
                Line::from("p  a file protected by a passphrase"),
                Line::from(""),
                Line::from(Span::styled("k / p choose · Esc cancel", bold())),
            ];
            dialog(f, "Move the main key", Text::from(text), width, 10);
        }
        Modal::Schema {
            namespace,
            lines,
            scroll,
        } => {
            let h = f.area().height.saturating_sub(4);
            let mut text: Vec<Line> = lines
                .iter()
                .skip(*scroll)
                .map(|l| Line::from(l.clone()))
                .collect();
            text.truncate(h.saturating_sub(4) as usize);
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                if app.model.powers(namespace).root {
                    "↑↓ scroll · u update to this build's schema · Esc close"
                } else {
                    "↑↓ scroll · Esc close"
                },
                bold(),
            )));
            dialog(
                f,
                format!("Schema of {namespace}"),
                Text::from(text),
                width,
                h,
            );
        }
        Modal::SchemaPreview(p) => {
            let next = p.held + 1;
            let warn = Style::new().fg(WARN);
            let mut text = vec![Line::from(format!(
                "Updating {} signs version {next} with the main key (you unlock it next). Nothing is signed yet.",
                p.namespace
            ))];
            text.push(Line::from(Span::styled(
                if p.stated {
                    format!(
                        "Policy: as the configuration given states it for {}.",
                        p.namespace
                    )
                } else {
                    format!(
                        "Policy: version {}'s is kept (the configuration given states none for {}).",
                        p.held, p.namespace
                    )
                },
                dim(),
            )));
            text.push(Line::from(""));
            if p.narrows() {
                text.push(Line::from(Span::styled(
                    format!(
                        "⚠ This update NARROWS what devices may do. A device relying on what it removes is refused once it holds version {next}:"
                    ),
                    warn.add_modifier(Modifier::BOLD),
                )));
                for rule in &p.removed {
                    text.push(Line::from(Span::styled(format!("  − rule {rule}"), warn)));
                }
                for lost in &p.links_narrowed {
                    text.push(Line::from(Span::styled(format!("  − links: {lost}"), warn)));
                }
                for relay in &p.relays_dropped {
                    text.push(Line::from(Span::styled(format!("  − relay {relay}"), warn)));
                }
                text.push(Line::from(""));
            }
            if !p.added.is_empty() {
                text.push(Line::from(format!(
                    "Devices gain {} rule{}:",
                    p.added.len(),
                    if p.added.len() == 1 { "" } else { "s" }
                )));
                for rule in &p.added {
                    text.push(Line::from(Span::styled(format!("  + {rule}"), dim())));
                }
            }
            if p.becomes_authoritative {
                text.push(Line::from(
                    "Data is then checked by these rules alone, on every certificate.",
                ));
            }
            if let Some(enrollment) = &p.enrollment {
                text.push(Line::from(format!("How devices join: {enrollment}")));
            }
            if let Some((before, after)) = &p.links {
                text.push(Line::from(format!("Links: {before} → {after}")));
            }
            if let Some((before, after)) = &p.relays {
                let list = |l: &[String]| {
                    if l.is_empty() {
                        "none".to_owned()
                    } else {
                        l.join("; ")
                    }
                };
                text.push(Line::from(format!(
                    "Relays: {} → {}",
                    list(before),
                    list(after)
                )));
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                if p.narrows() {
                    "a accept the narrowing and sign · Esc cancel (nothing changes)"
                } else {
                    "y sign · Esc cancel"
                },
                bold(),
            )));
            let h = (text.len() as u16 + 4).min(f.area().height);
            dialog(
                f,
                format!("Update the schema of {}", p.namespace),
                Text::from(text),
                width,
                h,
            );
        }
        Modal::NewPrefix(form) => {
            let mut text = vec![
                Line::from(
                    "This device becomes the main device of the new trusted prefix: it keeps the main key, which decides which devices belong.",
                ),
                Line::from(""),
                field("Prefix", format!("{}▏", form.prefix.text), form.field == 0),
                Line::from(Span::styled(
                    "  a name that starts with /, e.g. /home",
                    dim(),
                )),
                field(
                    "Device name",
                    format!("{}▏", form.device.text),
                    form.field == 1,
                ),
                field(
                    "Main key in",
                    format!(
                        "‹ {} ›",
                        words::root_store(NEW_ROOT_STORES[form.store].as_str())
                    ),
                    form.field == 2,
                ),
            ];
            if let (Ok(ns), device) = (form.prefix(), form.device.text.trim())
                && !device.is_empty()
            {
                text.push(Line::from(Span::styled(
                    format!("This device will be {ns}/admin/{device}."),
                    dim(),
                )));
            }
            if let Some(problem) = &form.problem {
                text.push(Line::from(Span::styled(
                    problem.clone(),
                    Style::new().fg(BAD),
                )));
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                "Tab field · on Main key: < > change · Enter start · Esc cancel",
                bold(),
            )));
            dialog(f, "Start a new trusted prefix", Text::from(text), width, 14);
        }
        Modal::Recover(form) => {
            let kit = match KIT_KINDS[form.kit] {
                KitFormat::Words => "24 recovery words",
                KitFormat::File => "a file protected by a passphrase",
                KitFormat::Yubikey => "a key on a security key (YubiKey)",
            };
            let mut text = vec![
                Line::from(
                    "For a trusted prefix whose main device is lost: this device becomes its main device, with a new main key. The recovery kit signs the change.",
                ),
                Line::from(""),
                field("Kit", format!("‹ {kit} ›"), form.field == 0),
            ];
            if KIT_KINDS[form.kit] == KitFormat::File {
                text.push(field(
                    "Kit file",
                    format!("{}▏", form.file.text),
                    form.field == 1,
                ));
            }
            text.push(field(
                "Prefix",
                format!("{}▏", form.prefix.text),
                form.field == 2,
            ));
            text.push(Line::from(Span::styled(
                "  empty: the one a kit file names, else the only one this device follows",
                dim(),
            )));
            text.push(field(
                "Device name",
                format!("{}▏", form.device.text),
                form.field == 3,
            ));
            text.push(field(
                "Old device",
                format!(
                    "‹ {} ›",
                    if form.compromised {
                        "may be in someone else's hands: its keys are revoked"
                    } else {
                        "lost or destroyed: what it certified stays valid"
                    }
                ),
                form.field == 4,
            ));
            text.push(field(
                "New main key",
                format!(
                    "‹ {} ›",
                    words::root_store(NEW_ROOT_STORES[form.store].as_str())
                ),
                form.field == 5,
            ));
            text.push(Line::from(""));
            text.push(Line::from(
                "This device must follow the prefix and reach a device that holds it: it recovers from the newest version.",
            ));
            if let Some(problem) = &form.problem {
                text.push(Line::from(Span::styled(
                    problem.clone(),
                    Style::new().fg(BAD),
                )));
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(
                "Tab field · on ‹ ›: < > change · Enter recover · Esc cancel",
                bold(),
            )));
            let h = (text.len() as u16 + 5).min(f.area().height);
            dialog(f, "I lost my main device", Text::from(text), width, h);
        }
        Modal::RecoverUnconfirmed { failure, .. } => {
            let text = vec![
                Line::from(failure.words()),
                Line::from(""),
                Line::from(
                    "Recovering from an older version than the newest would split the trusted prefix in two.",
                ),
                Line::from(
                    "If no device that holds it can be reached, and you are sure no newer version was made than the one this device holds, recover from it.",
                ),
                Line::from(
                    "Otherwise connect this device to one that holds the prefix, then try again.",
                ),
                Line::from(""),
                Line::from(Span::styled(
                    "h recover from the version held here · Esc cancel",
                    bold(),
                )),
            ];
            dialog(
                f,
                "Is the version held here the newest?",
                Text::from(text),
                width,
                14,
            );
        }
        Modal::Started(started) => draw_started(f, app, started),
        Modal::Secret(s) => {
            let mut text = vec![
                Line::from(s.prompt.clone()),
                Line::from(if s.first.is_some() {
                    "Type it again to confirm."
                } else {
                    ""
                }),
                Line::from(""),
                field(
                    "Secret",
                    format!("{}▏", "•".repeat(s.input.chars().count())),
                    true,
                ),
                Line::from(""),
                Line::from(Span::styled(
                    "It stays in this program: only what it signs goes to the daemon.",
                    dim(),
                )),
            ];
            if s.mismatch {
                text.push(Line::from(Span::styled(
                    "The two entries differ: type it again.",
                    Style::new().fg(BAD),
                )));
            }
            text.push(Line::from(Span::styled("Enter go · Esc cancel", bold())));
            dialog(f, "Unlock", Text::from(text), width, 11);
        }
        Modal::Ask { name } => {
            let text = vec![
                field("Name", format!("{}▏", name.text), true),
                Line::from(""),
                Line::from(Span::styled("Enter fetch and check · Esc cancel", bold())),
            ];
            dialog(f, "Fetch a name", Text::from(text), width, 6);
        }
        Modal::Inspected(i) => {
            let verdict = match i.verdict {
                DataVerdict::Valid => Span::styled(
                    "trusted",
                    Style::new().fg(GOOD).add_modifier(Modifier::BOLD),
                ),
                DataVerdict::Invalid => Span::styled(
                    "NOT trusted",
                    Style::new().fg(BAD).add_modifier(Modifier::BOLD),
                ),
                DataVerdict::Pending => {
                    Span::styled("not checked to the end", Style::new().fg(WARN))
                }
                DataVerdict::Unchecked => Span::styled("not checked here", Style::new().fg(WARN)),
                DataVerdict::Unknown => Span::styled("unknown", dim()),
            };
            let mut text = vec![
                Line::from(Span::styled(i.name.clone(), bold())),
                Line::from(""),
                Line::from(vec![Span::raw("Verdict: "), verdict]),
                Line::from(words::detail(&i.detail)),
                Line::from(format!(
                    "Vouched for by: {}",
                    i.namespace
                        .clone()
                        .unwrap_or_else(|| "no trusted prefix this device holds".into())
                )),
                Line::from(format!(
                    "Signed by: {}",
                    i.signer
                        .clone()
                        .unwrap_or_else(|| "nobody (no key named)".into())
                )),
            ];
            if let Some(at) = &i.signed_at {
                text.push(Line::from(format!("Signed at: {at}")));
            }
            if let (Some(from), Some(until)) = (&i.valid_from, &i.valid_until) {
                text.push(Line::from(format!(
                    "Valid: {} – {}",
                    date(from),
                    date(until)
                )));
            }
            text.push(Line::from(format!(
                "{} bytes of {}{}",
                i.content_bytes,
                i.content_type,
                i.freshness_ms
                    .map(|ms| format!(", fresh for {} s", ms / 1000))
                    .unwrap_or_default()
            )));
            if app.details {
                text.push(Line::from(Span::styled(
                    format!(
                        "signature {} · detail [{}]",
                        i.signature_type, i.detail.code
                    ),
                    dim(),
                )));
                for c in &i.chain {
                    text.push(Line::from(Span::styled(format!("  ← {c}"), dim())));
                }
            }
            text.push(Line::from(""));
            text.push(Line::from(Span::styled("Enter close", bold())));
            let h = text.len() as u16 + 4;
            dialog(f, "Data", Text::from(text), width, h);
        }
    }
}

fn ellipsis(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_owned();
    }
    let tail: String = text.chars().skip(count - max.saturating_sub(1)).collect();
    format!("…{tail}")
}

/// The QR code of `text` as half-block lines (two modules per line),
/// with a quiet zone; `None` when it does not encode.
pub fn qr_lines(text: &str) -> Option<Vec<String>> {
    let code = ndn_trust_envelope::qr::encode(text).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 2;
    let size = width + 2 * quiet;
    let dark = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet || x >= width + quiet || y >= width + quiet {
            return false;
        }
        colors[(y - quiet) * width + (x - quiet)].select(true, false)
    };
    let mut lines = Vec::with_capacity(size.div_ceil(2));
    for y in (0..size).step_by(2) {
        let mut line = String::with_capacity(size * 3);
        for x in 0..size {
            line.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
    }
    Some(lines)
}

fn draw_invite(f: &mut Frame, app: &App, invite: &ndn_cert::CreatedInvite) {
    let area = f.area();
    let qr = qr_lines(&invite.link);
    let qr_fits = qr.as_ref().is_some_and(|q| {
        q.len() as u16 + 12 <= area.height && q[0].chars().count() as u16 + 4 <= area.width
    });
    let mut text: Vec<Line> = vec![
        Line::from(format!(
            "An invite to {} as {}{}.",
            invite.namespace,
            invite.info.role.as_deref().map(words::role).unwrap_or_default(),
            invite
                .info
                .device
                .as_ref()
                .map(|d| format!(", for {d}"))
                .unwrap_or_default()
        )),
        Line::from(match invite.info.expires_secs {
            Some(e) => format!("Scan it, open the link or type the code on the new device. It expires {}.", relative(e)),
            None => "Scan it, open the link or type the code on the new device. It works until used or withdrawn.".to_owned(),
        }),
        Line::from(""),
    ];
    match (&qr, qr_fits) {
        (Some(lines), true) => {
            let qr_style = Style::new().fg(Color::Black).bg(Color::White);
            for l in lines {
                text.push(
                    Line::from(Span::styled(l.clone(), qr_style)).alignment(Alignment::Center),
                );
            }
        }
        _ => text.push(Line::from(Span::styled(
            "(Enlarge the window to show the QR code.)",
            dim(),
        ))),
    }
    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::styled("Code ", dim()),
        Span::styled(invite.token.clone(), bold()),
    ]));
    text.push(Line::from(vec![
        Span::styled("Link ", dim()),
        Span::raw(invite.link.clone()),
    ]));
    if app.details {
        text.push(Line::from(Span::styled(
            format!(
                "invite {} · CA {} · scope {}",
                invite.id,
                invite.ca,
                invite.info.scope.clone().unwrap_or_default()
            ),
            dim(),
        )));
    }
    text.push(Line::from(Span::styled(
        "Shown this once. Enter close",
        bold(),
    )));
    let h = area.height;
    let w = area.width;
    let rect = Rect {
        x: 0,
        y: 0,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(Text::from(text))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(ACCENT))
                    .title(Span::styled(" Invite made ", bold())),
            )
            .wrap(Wrap { trim: false }),
        rect,
    );
}

/// A trusted prefix started or recovered here: what happened, its anchor
/// link as a QR code, and in details the daemon's configuration lines.
fn draw_started(f: &mut Frame, app: &App, started: &Started) {
    let area = f.area();
    let mut text: Vec<Line> = Vec::new();
    for line in &started.lines {
        text.push(Line::from(line.clone()));
    }
    text.push(Line::from(""));
    if let Some(link) = &started.link {
        let qr = qr_lines(link);
        let shown = text.len() as u16
            + if app.details {
                started.settings.len() as u16
            } else {
                0
            };
        match qr {
            Some(lines)
                if lines.len() as u16 + shown + 8 <= area.height
                    && lines[0].chars().count() as u16 + 4 <= area.width =>
            {
                let qr_style = Style::new().fg(Color::Black).bg(Color::White);
                for l in lines {
                    text.push(Line::from(Span::styled(l, qr_style)).alignment(Alignment::Center));
                }
            }
            _ => text.push(Line::from(Span::styled(
                "(Enlarge the window to show the QR code.)",
                dim(),
            ))),
        }
        text.push(Line::from(vec![
            Span::styled("Anchor link ", dim()),
            Span::raw(link.clone()),
        ]));
    }
    if app.details {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            format!("expected fingerprint {}", started.fingerprint),
            dim(),
        )));
        text.push(Line::from(Span::styled(
            "The daemon's configuration, for its certificate authority (then restart it):",
            dim(),
        )));
        for line in &started.settings {
            text.push(Line::from(Span::styled(format!("  {line}"), bold())));
        }
    }
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        if app.details {
            "d hide details · Enter close"
        } else {
            "d details · Enter close"
        },
        bold(),
    )));
    let rect = Rect {
        x: 0,
        y: 0,
        width: area.width,
        height: area.height,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(Text::from(text))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(ACCENT))
                    .title(Span::styled(format!(" {} ", started.title), bold())),
            )
            .wrap(Wrap { trim: false }),
        rect,
    );
}
