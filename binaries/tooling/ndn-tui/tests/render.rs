//! Layout invariants of the screens, drawn on ratatui's test backend from
//! a model filled with fixed facts: the elements each screen must show are
//! there, verification codes and invite codes are never cut, actions are
//! offered only where the device's role allows them, and fingerprints show
//! only in details. No wording is pinned (words come from `words`).

use ndn_cert::report::{IdentityStatus, MembershipInfo, MembershipRelation, RootStoreStatus};
use ndn_cert::{
    CaInviteListing, CaIssuedListing, CreatedInvite, InviteEntry, InviteInfo, InviteState,
    IssuedEntry,
};
use ndn_mgmt_wire::{
    ApprovalListing, LinkEntry, LinkListing, LinkPathEntry, LinkRelayEntry, PendingApproval,
};
use ndn_tui::app::{App, Key, Modal, Msg, Screen, Section};
use ndn_tui::model::{Anchor, RootFacts, Update};
use ndn_tui::{ui, words};

const CODE: &str = "482 913";
const ROOT_FP: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn membership(ns: &str, relation: MembershipRelation, role: &str) -> MembershipInfo {
    let identity = if role.is_empty() {
        String::new()
    } else {
        format!("{ns}/{role}/desk")
    };
    MembershipInfo {
        namespace: ns.into(),
        version: 7,
        relation,
        role: role.into(),
        key: if identity.is_empty() {
            String::new()
        } else {
            format!("{identity}/KEY/%01")
        },
        identity,
        valid_until: "2027-01-16T00:00:00Z".into(),
        node_identity: false,
        root_fingerprint: ROOT_FP.into(),
    }
}

fn pending() -> PendingApproval {
    PendingApproval {
        request_id: "req-1".into(),
        key_name: "/home/bob/member/laptop/KEY/%02".into(),
        namespace: "/home/bob".into(),
        role: "member".into(),
        device: "laptop".into(),
        code: CODE.into(),
        state: "pending".into(),
        created_secs: 1_700_000_000,
        expires_secs: 4_000_000_000,
        approver: String::new(),
        reason: String::new(),
    }
}

fn invite_entry(id: &str, state: InviteState) -> InviteEntry {
    InviteEntry {
        id: id.into(),
        info: InviteInfo {
            role: Some("member".into()),
            scope: Some("/home/bob/member".into()),
            created_secs: 1_700_000_000,
            expires_secs: Some(4_000_000_000),
            device: Some("phone".into()),
            created_by: "uid 1000 (bob)".into(),
            state,
            ended_secs: None,
            redeemed_for: None,
        },
    }
}

fn issued(device: &str, revoked: bool) -> IssuedEntry {
    IssuedEntry {
        certificate: format!("/home/bob/member/{device}/KEY/%01/NDNCERT/v=1"),
        key: format!("/home/bob/member/{device}/KEY/%01"),
        identity: format!("/home/bob/member/{device}"),
        role: Some("member".into()),
        device: Some(device.into()),
        valid_from: "20261001T000000Z".into(),
        valid_until: "20270101T000000Z".into(),
        revoked,
    }
}

/// A main device of /home/bob (no recovery kit, a plain-file root key),
/// a member of /work, following /news; one request waiting.
fn app() -> App {
    let mut app = App::new("/run/ndn/mgmt.sock");
    let updates = vec![
        Update::Identity(Ok(IdentityStatus {
            identity: Some("/home/bob/admin/desk".into()),
            is_ephemeral: false,
            pib_path: "/var/lib/ndn/pib".into(),
            key: Some("/home/bob/admin/desk/KEY/%01".into()),
            valid_until: Some("20270101T000000Z".into()),
            days_left: Some(74.5),
            node_identity_source: None,
            signing_identities: Vec::new(),
            root_stores: vec![RootStoreStatus {
                namespace: "/home/bob".into(),
                kind: "file".into(),
                key: "/home/bob/KEY/root".into(),
            }],
        })),
        Update::Memberships(Ok(vec![
            membership("/home/bob", MembershipRelation::Owner, "admin"),
            membership("/work", MembershipRelation::Member, "member"),
            membership("/news", MembershipRelation::Following, ""),
        ])),
        Update::Roots(Ok(vec![RootFacts {
            namespace: "/home/bob".into(),
            key: "/home/bob/KEY/root".into(),
            store: "file".into(),
            location: "/var/lib/ndn/pib/root".into(),
            version: Some(7),
            anchors: vec![Anchor {
                key: "/home/bob/KEY/root".into(),
                recovery_kit: false,
                fingerprint: ROOT_FP.into(),
            }],
        }])),
        Update::Approvals(Ok(ApprovalListing {
            rows: vec![pending()],
            notes: Vec::new(),
        })),
        Update::Invites(Ok(vec![CaInviteListing {
            ca: "/home/bob".into(),
            namespace: "/home/bob".into(),
            invites: vec![
                invite_entry("inv-open", InviteState::Outstanding),
                invite_entry("inv-used", InviteState::Redeemed),
            ],
        }])),
        Update::Issued(Ok(vec![CaIssuedListing {
            ca: "/home/bob".into(),
            namespace: "/home/bob".into(),
            certificates: vec![issued("phone", false), issued("tv", true)],
        }])),
        Update::Links(Ok(LinkListing {
            links: vec![
                LinkEntry {
                    label: "phone".into(),
                    device: "/home/bob/member/phone".parse().ok(),
                    paths: vec![LinkPathEntry {
                        kind: "direct".into(),
                        face_id: 300,
                        remote: Some("192.168.1.23:6367".into()),
                        rtt_micros: Some(4_000),
                        age_secs: 60,
                        via: None,
                    }],
                    direct_state: "up".into(),
                    mode: Some("on-demand".into()),
                    ..Default::default()
                },
                LinkEntry {
                    label: "home-vps".into(),
                    paths: vec![LinkPathEntry {
                        kind: "link".into(),
                        face_id: 301,
                        ..Default::default()
                    }],
                    direct_state: "none".into(),
                    mode: Some("always".into()),
                    relay: Some(LinkRelayEntry {
                        source: "namespace:/home/bob".into(),
                        preference: 0,
                        state: "linked".into(),
                        detail: None,
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })),
    ];
    for u in updates {
        app.handle(Msg::Update(u));
    }
    app
}

fn render(app: &App, w: u16, h: u16) -> String {
    ui::render_text(app, w, h)
}

#[test]
fn home_lists_every_prefix_with_relation_trust_and_the_waiting_request() {
    let app = app();
    let screen = render(&app, 100, 24);
    for ns in ["/home/bob", "/work", "/news"] {
        assert!(screen.contains(ns), "{ns} missing:\n{screen}");
    }
    for label in [
        words::relation(MembershipRelation::Owner, "admin"),
        words::relation(MembershipRelation::Member, "member"),
        words::relation(MembershipRelation::Following, ""),
    ] {
        assert!(
            screen.contains(label),
            "relation {label:?} missing:\n{screen}"
        );
    }
    assert!(
        screen.contains("version 7"),
        "trust version missing:\n{screen}"
    );
    assert!(
        screen.contains(CODE),
        "the request's code is cut:\n{screen}"
    );
    // Both safety warnings: no recovery kit, plain-file main key.
    assert_eq!(screen.matches('⚠').count(), 2, "warnings:\n{screen}");
}

#[test]
fn verification_codes_are_never_cut() {
    let mut app = app();
    for (w, h) in [(60, 20), (80, 24), (120, 40)] {
        app.modal = Some(Modal::Approve(pending()));
        let screen = render(&app, w, h);
        assert!(
            screen.contains(&ui::spread(CODE)),
            "the code is cut at {w}x{h}:\n{screen}"
        );
        app.modal = None;
        app.screen = Screen::Prefix("/home/bob".into());
        app.section = Section::Requests;
        let screen = render(&app, w, h);
        assert!(
            screen.contains(CODE),
            "the code is cut in the list at {w}x{h}:\n{screen}"
        );
        app.screen = Screen::Prefixes;
    }
}

#[test]
fn a_prefix_shows_what_the_role_allows_and_no_more() {
    let mut app = app();
    app.screen = Screen::Prefix("/home/bob".into());
    let owner = render(&app, 120, 40);
    for title in [
        "Waiting for approval",
        "Members",
        "Invites",
        "Recovery kits",
    ] {
        assert!(
            owner.contains(title),
            "owner screen lacks {title}:\n{owner}"
        );
    }
    assert!(
        owner.contains("phone") && owner.contains("tv"),
        "members:\n{owner}"
    );
    assert!(
        owner.contains("i invite") && owner.contains("k new kit"),
        "owner keys:\n{owner}"
    );

    app.screen = Screen::Prefix("/news".into());
    let follower = render(&app, 120, 40);
    for title in ["Waiting for approval", "Invites", "Recovery kits"] {
        assert!(
            !follower.contains(title),
            "a follower is offered {title}:\n{follower}"
        );
    }
    for key in [
        "i invite",
        "k new kit",
        "x remove device",
        "m move main key",
    ] {
        assert!(
            !follower.contains(key),
            "a follower is offered {key}:\n{follower}"
        );
    }
}

#[test]
fn an_invite_shows_its_code_link_and_qr_when_it_fits() {
    let mut app = app();
    let link = "ndn-trust://invite/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
    let invite = CreatedInvite {
        id: "inv-new".into(),
        ca: "/home/bob".into(),
        namespace: "/home/bob".into(),
        info: invite_entry("inv-new", InviteState::Outstanding).info,
        token: "Zx9q-T4kLm2P8vRw5yAa1Q".into(),
        link: link.into(),
    };
    app.modal = Some(Modal::InviteMade(invite));
    let big = render(&app, 120, 60);
    assert!(
        big.contains("Zx9q-T4kLm2P8vRw5yAa1Q"),
        "the code is cut:\n{big}"
    );
    assert!(big.contains('█'), "no QR code on a large screen:\n{big}");
    let small = render(&app, 80, 24);
    assert!(
        small.contains("Zx9q-T4kLm2P8vRw5yAa1Q"),
        "the code is cut:\n{small}"
    );
}

#[test]
fn connections_show_peer_carried_prefix_path_and_relays() {
    let mut app = app();
    app.screen = Screen::Connections;
    let screen = render(&app, 120, 30);
    assert!(
        screen.contains("phone") && screen.contains("home-vps"),
        "{screen}"
    );
    assert!(
        screen.contains("/home/bob"),
        "the carried prefix is missing:\n{screen}"
    );
    assert!(screen.contains("4 ms"), "rtt missing:\n{screen}");
    assert!(screen.contains("Relays"), "relays missing:\n{screen}");
}

#[test]
fn fingerprints_and_the_event_log_show_only_in_details() {
    let mut app = app();
    app.screen = Screen::Prefix("/home/bob".into());
    let plain = render(&app, 160, 50);
    assert!(
        !plain.contains(&ROOT_FP[..16]),
        "a fingerprint outside details:\n{plain}"
    );
    app.handle(Msg::Key(Key::Char('d')));
    let details = render(&app, 160, 50);
    assert!(
        details.contains(&ROOT_FP[..16]),
        "no fingerprint in details:\n{details}"
    );
    assert!(
        details.contains("Events"),
        "no event log in details:\n{details}"
    );
}
