//! tui: the admin TUI's state layer (`ndn_tui::driver::Driver`, the model
//! and the commands behind its keys) against running daemons — no
//! terminal; keystrokes for the forms and the secrets typed into its
//! prompts. Each TUI follows its daemon's trust and links streams and must
//! see every change by itself, without being told to reload.
//!
//! Topology: root (.1, main device + CA of /tu, listening for QUIC links)
//! linked to laptop (.2, also dials root over QUIC), phone (.3) and spare
//! (.4, a device with no trusted prefix: it starts /tu2, then recovers /tu
//! with a recovery kit made on the main device).
//!
//! The screens each step leaves are drawn on a test backend and written to
//! `<run dir>/tui/*.txt` (kept with `--keep`); nothing asserts their words.

use std::path::PathBuf;

use ndn_cert::report::{DataVerdict, MembershipRelation};
use ndn_cert::{InviteRequest, InviteState, KitFormat};
use ndn_namespace::root::SecretKind;
use ndn_packet::Name;
use ndn_tui::app::{Command, Effect, Key, Modal, Msg, Screen, Section};
use ndn_tui::driver::Driver;
use ndn_tui::model::Warning;
use ndn_tui::root::RootOp;
use ndn_tui::ui;

use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/tu";
/// The trusted prefix spare starts in its TUI.
const NS2: &str = "/tu2";

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn name(s: &str) -> Name {
    s.parse().expect("a name")
}

/// Write what `driver`'s app shows on a `w` × `h` screen to
/// `<run dir>/tui/<file>.txt`.
fn capture(cx: &mut Cx<'_>, driver: &Driver, file: &str, w: u16, h: u16) -> StepResult<()> {
    let dir: PathBuf = cx.w.dir.join("tui");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{file}.txt"));
    std::fs::write(&path, ui::render_text(&driver.app, w, h))
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    cx.note(&format!("screen: {}", path.display()));
    Ok(())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let base = NodeCfg {
        refresh_secs: 1,
        ..Default::default()
    };
    sc.world.add(
        "root",
        1,
        NodeCfg {
            links: vec![link("laptop", 2), link("phone", 3), link("spare", 4)],
            routes: vec![
                route(n("/admin/laptop"), "laptop"),
                route(n("/member/phone"), "phone"),
            ],
            quic_listen: true,
            ..base.clone()
        },
    );
    sc.world.add(
        "laptop",
        2,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            peers: vec![PeerCfg {
                device: Some(n("/admin/desk")),
                endpoint: Some(addr(1)),
                ..Default::default()
            }],
            ..base.clone()
        },
    );
    sc.world.add(
        "phone",
        3,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            ..base.clone()
        },
    );
    sc.world.add(
        "spare",
        4,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            ..base.clone()
        },
    );

    let root = sc.step("init the main device", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    sc.step(
        "start the main device's daemon with its CA, and laptop, phone and spare",
        |cx| {
            cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
            cx.w.node_mut("root").cfg.ca = Some(CaCfg {
                prefix: NS.into(),
                identity: n("/CA"),
                member_days: None,
            });
            cx.start("root")?;
            cx.start("laptop")?;
            cx.start("phone")?;
            cx.start("spare")
        },
    )?;

    let rt = runtime();
    let sock = |cx: &Cx<'_>, node: &str| cx.w.node(node).sock().display().to_string();
    let wait = SHORT;

    let mut desk = sc.step(
        "the TUI on the main device lists /tu as owned, with the no-recovery-kit warning",
        |cx| {
            let socket = sock(cx, "root");
            let driver =
                rt.block_on(async {
                    let mut d = Driver::connect(&socket, None)
                        .await
                        .map_err(|f| f.words())?;
                    let ok = d
                        .settle(wait, |app| {
                            app.model.prefixes().iter().any(|p| {
                                p.namespace == NS && p.relation == MembershipRelation::Owner
                            }) && app.model.warnings().contains(&Warning::NoRecoveryKit {
                                namespace: NS.into(),
                            })
                        })
                        .await;
                    if ok {
                        Ok(d)
                    } else {
                        Err(format!(
                            "the TUI does not list {NS} as owned with its warning: {:?} {:?}",
                            d.app.model.prefixes(),
                            d.app.model.warnings()
                        ))
                    }
                })?;
            capture(cx, &driver, "home", 100, 24)?;
            Ok(driver)
        },
    )?;

    let invite_link = sc.step(
        "the TUI makes an invite (member, 1 day, for phone): link, code and QR shown once, listed as open",
        |cx| {
            let link = rt.block_on(async {
                let ca = desk
                    .app
                    .model
                    .invite_ca(NS)
                    .map(|c| name(&c.ca))
                    .ok_or("the TUI offers no invite: no CA of /tu listed")?;
                desk.execute(vec![Effect::Run(Command::CreateInvite {
                    ca,
                    request: InviteRequest {
                        role: "member".into(),
                        ttl_secs: Some(86_400),
                        device: Some("phone".into()),
                    },
                })]);
                let made = desk
                    .settle(wait, |app| matches!(app.modal, Some(Modal::InviteMade(_))))
                    .await;
                let Some(Modal::InviteMade(invite)) = &desk.app.modal else {
                    return Err(format!("no invite made: {:?}", desk.app.status));
                };
                if !made {
                    return Err("the invite dialog did not settle".into());
                }
                let (id, link) = (invite.id.clone(), invite.link.clone());
                let listed = desk
                    .settle(wait, |app| {
                        app.model
                            .invites_in(NS)
                            .iter()
                            .any(|i| i.id == id && i.info.state == InviteState::Outstanding)
                    })
                    .await;
                if !listed {
                    return Err(format!("invite {id} is not listed as open"));
                }
                Ok::<_, String>(link)
            })?;
            capture(cx, &desk, "invite", 110, 60)?;
            desk.app.modal = None;
            Ok(link)
        },
    )?;

    let mut phone = sc.step(
        "phone's TUI joins with the invite: a member of /tu, told by its own trust stream",
        |cx| {
            let socket = sock(cx, "phone");
            let link = invite_link.clone();
            rt.block_on(async {
                let mut d = Driver::connect(&socket, None)
                    .await
                    .map_err(|f| f.words())?;
                d.execute(vec![Effect::Run(Command::Join {
                    link,
                    identity: name(&n("/member/phone")),
                })]);
                let ok = d
                    .settle(wait, |app| {
                        app.model
                            .membership(NS)
                            .is_some_and(|m| m.relation == MembershipRelation::Member)
                    })
                    .await;
                if ok {
                    Ok(d)
                } else {
                    Err(format!("phone is no member of {NS}: {:?}", d.app.status))
                }
            })
        },
    )?;

    sc.step(
        "the main device's TUI hears the invite used and lists phone as a member",
        |cx| {
            let ok = rt.block_on(desk.settle(wait, |app| {
                app.model
                    .members_in(NS)
                    .iter()
                    .any(|m| m.identity == n("/member/phone") && !m.revoked)
                    && app
                        .model
                        .invites_in(NS)
                        .iter()
                        .any(|i| i.info.state == InviteState::Redeemed)
            }));
            if !ok {
                return Err(format!("members {:?}", desk.app.model.members_in(NS)));
            }
            cx.evidence("phone listed as a member and the invite as used, from events alone");
            Ok(())
        },
    )?;

    let (mut laptop, code) = sc.step(
        "laptop's TUI asks to join as an admin: waiting, with a code",
        |cx| {
            let socket = sock(cx, "laptop");
            let link = root.link_fp.clone();
            rt.block_on(async {
                let mut d = Driver::connect(&socket, None)
                    .await
                    .map_err(|f| f.words())?;
                d.execute(vec![Effect::Run(Command::Join {
                    link,
                    identity: name(&n("/admin/laptop")),
                })]);
                let ok = d.settle(wait, |app| app.waiting.is_some()).await;
                let Some(w) = d.app.waiting.clone().filter(|_| ok) else {
                    return Err(format!("laptop is not waiting: {:?}", d.app.status));
                };
                Ok((d, w.pending.code))
            })
        },
    )?;
    capture_step(sc, &laptop, "waiting", 100, 24)?;

    let request = sc.step(
        "the main device's TUI shows the request with the same code",
        |cx| {
            let ok = rt.block_on(desk.settle(wait, |app| {
                app.model.pending_in(NS).iter().any(|r| r.code == code)
            }));
            let row = desk
                .app
                .model
                .pending_in(NS)
                .into_iter()
                .find(|r| r.code == code)
                .cloned()
                .filter(|_| ok)
                .ok_or_else(|| {
                    format!(
                        "no request with code {code}: {:?}",
                        desk.app.model.pending()
                    )
                })?;
            cx.evidence(&format!("both screens show {code}"));
            desk.app.screen = Screen::Prefix(NS.into());
            desk.app.section = Section::Requests;
            capture(cx, &desk, "prefix", 120, 40)?;
            desk.app.modal = Some(Modal::Approve(row.clone()));
            capture(cx, &desk, "approve", 100, 24)?;
            desk.app.modal = None;
            Ok(row.request_id)
        },
    )?;

    sc.step(
        "approve on the main device: laptop's TUI sees its wait end, an admin of /tu; the main device's TUI lists it as a member",
        |_cx| {
            rt.block_on(async {
                desk.execute(vec![Effect::Run(Command::Approve {
                    request: request.clone(),
                })]);
                if !desk
                    .settle(wait, |app| app.model.pending_in(NS).is_empty())
                    .await
                {
                    return Err(format!(
                        "still pending on the main device: {:?}",
                        desk.app.status
                    ));
                }
                let ok = laptop
                    .settle(wait + ndn_cert::approval::STATUS_LIFETIME, |app| {
                        app.waiting.is_none()
                            && app.model.membership(NS).is_some_and(|m| m.role == "admin")
                    })
                    .await;
                if !ok {
                    return Err(format!(
                        "laptop: waiting {:?}, membership {:?}",
                        laptop.app.waiting,
                        laptop.app.model.membership(NS)
                    ));
                }
                // The certificate is issued when laptop asks after the
                // decision; the main device's TUI hears of it by itself.
                let listed = desk
                    .settle(wait, |app| {
                        app.model
                            .members_in(NS)
                            .iter()
                            .any(|m| m.identity == n("/admin/laptop") && !m.revoked)
                    })
                    .await;
                if listed {
                    Ok(())
                } else {
                    Err(format!(
                        "the main device does not list laptop: {:?}",
                        desk.app.model.members_in(NS)
                    ))
                }
            })
        },
    )?;

    let doc = content(4_000, 41);
    sc.step(
        "phone publishes; the main device's TUI fetches and checks it: trusted, vouched for by /tu",
        |cx| {
            cx.publish("phone", &n("/member/phone/doc"), &doc, None, None)?;
            rt.block_on(async {
                desk.execute(vec![
                    Effect::Load(ndn_tui::model::Listing::Routes),
                    Effect::Load(ndn_tui::model::Listing::Cached),
                    Effect::Run(Command::Inspect {
                        name: name(&n("/member/phone/doc")),
                    }),
                ]);
                desk.settle(wait, |app| matches!(app.modal, Some(Modal::Inspected(_))))
                    .await;
            });
            let Some(Modal::Inspected(i)) = &desk.app.modal else {
                return Err(format!("no inspection: {:?}", desk.app.status));
            };
            if i.verdict != DataVerdict::Valid || i.namespace.as_deref() != Some(NS) {
                return Err(format!(
                    "inspection: verdict {:?}, vouched by {:?}",
                    i.verdict, i.namespace
                ));
            }
            capture(cx, &desk, "inspect", 100, 30)?;
            desk.app.modal = None;
            desk.app.screen = Screen::Data;
            capture(cx, &desk, "data", 120, 30)
        },
    )?;

    sc.step(
        "connections: laptop's TUI connects its link to the main device now; both TUIs list it up, carrying /tu",
        |cx| {
            let up = |app: &ndn_tui::app::App, device: &str| {
                app.model.links.get().is_some_and(|l| {
                    l.links.iter().any(|e| {
                        e.device.as_ref().is_some_and(|d| d.to_string() == device)
                            && !e.paths.is_empty()
                            && app.model.carried_by(e).iter().any(|ns| ns == NS)
                    })
                })
            };
            let links = |app: &ndn_tui::app::App| {
                format!(
                    "{:?} ({:?})",
                    app.model.links.get().map(|l| l
                        .links
                        .iter()
                        .map(|e| (&e.label, &e.device, e.paths.len()))
                        .collect::<Vec<_>>()),
                    app.model.links.failure
                )
            };
            let (laptop_up, desk_up) = rt.block_on(async {
                let label = laptop.app.model.links.get().and_then(|l| {
                    l.links
                        .iter()
                        .find(|e| e.device.as_ref().is_some_and(|d| d.to_string() == n("/admin/desk")))
                        .map(|e| e.label.clone())
                });
                let Some(label) = label else {
                    return (false, false);
                };
                laptop.execute(vec![Effect::Run(Command::LinkConnect { label })]);
                let laptop_up = laptop.settle(wait, |app| up(app, &n("/admin/desk"))).await;
                desk.execute(vec![Effect::Load(ndn_tui::model::Listing::Links)]);
                let desk_up = desk.settle(wait, |app| up(app, &n("/admin/laptop"))).await;
                (laptop_up, desk_up)
            });
            laptop.app.screen = Screen::Connections;
            capture(cx, &laptop, "connections-laptop", 120, 24)?;
            desk.app.screen = Screen::Connections;
            capture(cx, &desk, "connections", 120, 24)?;
            if !laptop_up {
                return Err(format!("laptop's links: {}", links(&laptop.app)));
            }
            if !desk_up {
                return Err(format!("the main device's links: {}", links(&desk.app)));
            }
            Ok(())
        },
    )?;

    let v0 = sc.world.held_version("root", NS).unwrap_or(0);
    sc.step(
        "remove phone from the TUI: the main key is unlocked in the TUI, a new version revokes it, everyone sees it",
        |cx| {
            rt.block_on(async {
                desk.app.screen = Screen::Prefix(NS.into());
                desk.execute(vec![Effect::Run(Command::Root(RootOp::Revoke {
                    namespace: name(NS),
                    name: name(&n("/member/phone")),
                }))]);
                if !desk
                    .settle(wait, |app| matches!(app.modal, Some(Modal::Secret(_))))
                    .await
                {
                    return Err(format!("no passphrase prompt: {:?}", desk.app.status));
                }
                for c in ROOT_PASS.chars() {
                    desk.handle(Msg::Key(Key::Char(c)));
                }
                desk.handle(Msg::Key(Key::Enter));
                let removed = desk
                    .settle(wait, |app| {
                        app.model
                            .members_in(NS)
                            .iter()
                            .any(|m| m.identity == n("/member/phone") && m.revoked)
                            && app.model.membership(NS).is_some_and(|m| m.version == v0 + 1)
                    })
                    .await;
                if !removed {
                    return Err(format!(
                        "phone is not listed as removed: {:?} {:?}",
                        desk.app.status,
                        desk.app.model.members_in(NS)
                    ));
                }
                Ok(())
            })?;
            cx.expect_version("root", NS, v0 + 1)?;
            capture(cx, &desk, "removed", 120, 40)?;
            desk.app.modal = None;
            let seen = rt.block_on(phone.settle(wait, |app| {
                app.model.membership(NS).is_some_and(|m| m.version == v0 + 1)
            }));
            if !seen {
                return Err("phone's TUI does not hold the new version".into());
            }
            Ok(())
        },
    )?;

    sc.step(
        "details: the event log of the main device's TUI tells each change",
        |cx| {
            let kinds: Vec<String> = desk.app.model.log.iter().map(|l| l.kind.clone()).collect();
            for want in [
                "invite-created",
                "invite-redeemed",
                "certificate-issued",
                "approval-requested",
                "approval-decided",
                "context-updated",
            ] {
                if !kinds.iter().any(|k| k == want) {
                    return Err(format!("no {want} event in the log: {kinds:?}"));
                }
            }
            desk.handle(Msg::Key(Key::Char('d')));
            capture(cx, &desk, "details", 140, 45)?;
            desk.app.screen = Screen::Node;
            capture(cx, &desk, "node", 120, 30)?;
            desk.app.screen = Screen::Prefixes;
            capture(cx, &desk, "home-details", 140, 30)
        },
    )?;
    desk.handle(Msg::Key(Key::Char('d')));

    let v1 = sc.world.held_version("root", NS).unwrap_or(0);
    sc.step(
        "a schema update from a TUI given a config whose [ca] entry narrows the link policy: shown before signing, signed only once the narrowing is accepted",
        |cx| {
            let socket = sock(cx, "root");
            let config = ndn_config::ForwarderConfig {
                ca: vec![ndn_config::CaTomlConfig {
                    prefix: NS.into(),
                    identity: n("/CA"),
                    link_roles: Some(vec!["admin".into(), "node".into()]),
                    ..Default::default()
                }],
                ..Default::default()
            };
            let d = rt.block_on(async {
                let mut d = Driver::connect(&socket, Some(config))
                    .await
                    .map_err(|f| f.words())?;
                if !d.settle(wait, |app| app.model.powers(NS).root).await {
                    return Err(format!("the TUI is not the main device of {NS}"));
                }
                d.app.screen = Screen::Prefix(NS.into());
                d.handle(Msg::Key(Key::Char('s')));
                if !d
                    .settle(wait, |app| matches!(app.modal, Some(Modal::Schema { .. })))
                    .await
                {
                    return Err(format!("no schema shown: {:?}", d.app.status));
                }
                d.handle(Msg::Key(Key::Char('u')));
                let previewed = d
                    .settle(wait, |app| {
                        matches!(&app.modal, Some(Modal::SchemaPreview(p)) if p.narrows() && !p.links_narrowed.is_empty())
                    })
                    .await;
                if !previewed {
                    return Err(format!(
                        "no narrowing shown before signing: {:?} {:?}",
                        d.app.modal, d.app.status
                    ));
                }
                Ok(d)
            })?;
            capture(cx, &d, "schema-narrowing", 110, 30)?;
            let mut d = d;
            rt.block_on(async {
                // A narrowing is signed only with its own key.
                d.handle(Msg::Key(Key::Char('y')));
                if !matches!(d.app.modal, Some(Modal::SchemaPreview(_))) {
                    return Err("y signed a narrowing".into());
                }
                d.handle(Msg::Key(Key::Char('a')));
                let signed = answer_secrets(&mut d, |_| ROOT_PASS.into(), |app| {
                    matches!(&app.modal, Some(Modal::Message { title, .. }) if title == "Schema updated")
                        && app.model.membership(NS).is_some_and(|m| m.version == v1 + 1)
                })
                .await;
                if !signed {
                    return Err(format!(
                        "the update was not signed and taken: {:?} {:?}",
                        d.app.modal, d.app.status
                    ));
                }
                Ok(())
            })?;
            capture(cx, &d, "schema-updated", 110, 24)?;
            cx.expect_version("root", NS, v1 + 1)
        },
    )?;

    let kit_words = sc.step(
        "make a words recovery kit in the main device's TUI: the words shown once",
        |cx| {
            let words = rt.block_on(async {
                desk.execute(vec![Effect::Run(Command::Root(RootOp::KitCreate {
                    namespace: name(NS),
                    format: KitFormat::Words,
                    out: None,
                }))]);
                let made = answer_secrets(
                    &mut desk,
                    |_| ROOT_PASS.into(),
                    |app| matches!(app.modal, Some(Modal::KitWords { .. })),
                )
                .await;
                match &desk.app.modal {
                    Some(Modal::KitWords { words, .. }) if made => Ok(words.to_string()),
                    _ => Err(format!("no recovery words shown: {:?}", desk.app.status)),
                }
            })?;
            capture(cx, &desk, "kit-words", 100, 24)?;
            desk.handle(Msg::Key(Key::Enter));
            cx.expect_version("root", NS, v1 + 2)?;
            Ok(words)
        },
    )?;

    let mut spare = sc.step(
        "spare's TUI, on a device that holds no trusted prefix, opens on the first-run screen",
        |cx| {
            let socket = sock(cx, "spare");
            let d = rt.block_on(async {
                let mut d = Driver::connect(&socket, None)
                    .await
                    .map_err(|f| f.words())?;
                let empty = d
                    .settle(wait, |app| {
                        app.pib.is_some() && app.model.memberships.get().is_some_and(Vec::is_empty)
                    })
                    .await;
                if !empty {
                    return Err(format!(
                        "spare's TUI lists prefixes: {:?}",
                        d.app.model.prefixes()
                    ));
                }
                Ok(d)
            })?;
            capture(cx, &d, "first-run", 100, 30)?;
            Ok(d)
        },
    )?;

    sc.step(
        "start /tu2 in spare's TUI (n): its passphrase typed twice; spare's daemon lists /tu2 as owned",
        |cx| {
            spare.handle(Msg::Key(Key::Char('n')));
            typ(&mut spare, "/tu2");
            spare.handle(Msg::Key(Key::Tab));
            retype(&mut spare, "spare");
            capture(cx, &spare, "new-prefix", 100, 24)?;
            rt.block_on(async {
                spare.handle(Msg::Key(Key::Enter));
                let started = answer_secrets(&mut spare, |_| ROOT_PASS.into(), |app| {
                    matches!(app.modal, Some(Modal::Started(_)))
                        && app.model.prefixes().iter().any(|p| {
                            p.namespace == NS2 && p.relation == MembershipRelation::Owner
                        })
                })
                .await;
                if !started {
                    return Err(format!(
                        "/tu2 is not listed as owned: {:?} {:?}",
                        spare.app.status,
                        spare.app.model.prefixes()
                    ));
                }
                Ok(())
            })?;
            capture(cx, &spare, "started", 100, 50)?;
            spare.handle(Msg::Key(Key::Char('d')));
            capture(cx, &spare, "started-details", 120, 60)?;
            spare.handle(Msg::Key(Key::Char('d')));
            spare.handle(Msg::Key(Key::Enter));
            cx.expect_version("spare", NS2, 1)
        },
    )?;

    sc.step(
        "spare follows /tu with its anchor link, at the version the main device holds",
        |_cx| {
            let link = root.link_fp.clone();
            rt.block_on(async {
                spare.execute(vec![Effect::Run(Command::Follow { link })]);
                let following = spare
                    .settle(wait, |app| {
                        app.model.membership(NS).is_some_and(|m| {
                            m.relation == MembershipRelation::Following && m.version == v1 + 2
                        })
                    })
                    .await;
                if !following {
                    return Err(format!(
                        "spare does not follow {NS} at v{}: {:?} {:?}",
                        v1 + 2,
                        spare.app.status,
                        spare.app.model.membership(NS)
                    ));
                }
                Ok(())
            })
        },
    )?;

    sc.step(
        "I lost my main device (r): spare recovers /tu with the words typed into its TUI; it becomes the main device, and the old one takes the new versions",
        |cx| {
            spare.handle(Msg::Key(Key::Char('r')));
            // Kit: 24 words (the first choice); the file field is skipped.
            spare.handle(Msg::Key(Key::Tab));
            typ(&mut spare, NS);
            spare.handle(Msg::Key(Key::Tab));
            retype(&mut spare, "spare");
            capture(cx, &spare, "recover", 100, 30)?;
            let words = kit_words.clone();
            rt.block_on(async {
                spare.handle(Msg::Key(Key::Enter));
                let recovered = answer_secrets(
                    &mut spare,
                    |kind| match kind {
                        SecretKind::KitWords => words.clone(),
                        _ => NEW_ROOT_PASS.into(),
                    },
                    |app| {
                        matches!(app.modal, Some(Modal::Started(_)))
                            && app.model.membership(NS).is_some_and(|m| {
                                m.relation == MembershipRelation::Owner && m.version == v1 + 4
                            })
                    },
                )
                .await;
                if !recovered {
                    return Err(format!(
                        "spare is not the main device of {NS}: {:?} {:?} {:?}",
                        spare.app.modal,
                        spare.app.status,
                        spare.app.model.membership(NS)
                    ));
                }
                Ok(())
            })?;
            capture(cx, &spare, "recovered", 110, 50)?;
            cx.expect_version("spare", NS, v1 + 4)?;
            cx.wait_version("root", NS, v1 + 4, SHORT).map(|_| ())
        },
    )?;
    drop(rt);
    Ok(())
}

/// Type `text` into the field that has the focus.
fn typ(d: &mut Driver, text: &str) {
    for c in text.chars() {
        d.handle(Msg::Key(Key::Char(c)));
    }
}

/// Replace what the focused field holds with `text`.
fn retype(d: &mut Driver, text: &str) {
    for _ in 0..64 {
        d.handle(Msg::Key(Key::Backspace));
    }
    typ(d, text);
}

/// Type `answer(kind)` into every secret prompt `d` shows (twice for a new
/// secret) until `done` holds of its app: whether it did within [`SHORT`].
async fn answer_secrets(
    d: &mut Driver,
    answer: impl Fn(SecretKind) -> String,
    done: impl Fn(&ndn_tui::app::App) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + SHORT;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        d.settle(left, |app| {
            done(app) || matches!(app.modal, Some(Modal::Secret(_)))
        })
        .await;
        let kind = match &d.app.modal {
            Some(Modal::Secret(s)) => s.ask.request.kind,
            _ => return done(&d.app),
        };
        typ(d, &answer(kind));
        d.handle(Msg::Key(Key::Enter));
    }
}

/// A capture as a step of its own (for a driver borrowed elsewhere).
fn capture_step(sc: &mut Scenario, d: &Driver, file: &str, w: u16, h: u16) -> Result<(), Abort> {
    sc.step(&format!("capture the {file} screen"), |cx| {
        capture(cx, d, file, w, h)
    })
}
