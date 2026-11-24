//! The names local apps asked this daemon to carry in transit
//! (`security/transit`, `ndn-rs/docs/specs/mgmt-trust.md` "Transit"): either
//! a person's self-certifying namespace an app adopted for one scope of its
//! own alone (a data host's spaces), or the two prefixes of an introduction,
//! `<device>/32=intro` and `<device>/32=hint`, which the joiner's host carries
//! for the length of one join (the offer and the hint record are signed by a
//! namespace this daemon does not hold yet; `invite.md` §12.1). Data under
//! one, which this forwarder, not holding its namespace, would refuse,
//! is forwarded unvalidated to the Interests pending for it and never cached.
//! Each mark is one reason in the engine's count of the name's reasons to be
//! in transit (`TransitPrefixes`), beside the links'; the first reason and the
//! last run the links' action for a namespace (its sync group with the
//! `multicast` strategy; an introduction's prefixes have none). A mark is owned
//! by the management face that asked, and released when that face closes: an
//! app that ends, crashes or restarts leaves no mark behind. The keyring is
//! never touched.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use ndn_engine::ForwarderEngine;
use ndn_namespace::{TrustRefusal, code};
use ndn_packet::tlv_type::{IMPLICIT_SHA256, KEYWORD, PARAMETERS_SHA256};
use ndn_packet::{Name, NameComponent};
use ndn_security::self_certifying::self_certifying_digest;
use ndn_transport::FaceId;

/// What a mark may name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Marked {
    /// A person's self-certifying namespace.
    Namespace,
    /// `<device>/32=intro` or `<device>/32=hint`.
    Introduction,
}

impl Marked {
    /// What `name` is, if a mark may name it: a self-certifying namespace, or
    /// exactly one device name (plain components: no keyword, no digest) then
    /// the one keyword `intro` or `hint`, nothing else of a device.
    fn of(name: &Name) -> Option<Marked> {
        if matches!(self_certifying_digest(name), Ok(Some(_))) {
            return Some(Marked::Namespace);
        }
        let (last, device) = name.components().split_last()?;
        let plain =
            |c: &NameComponent| ![KEYWORD, IMPLICIT_SHA256, PARAMETERS_SHA256].contains(&c.typ);
        let intro = last.typ == KEYWORD && matches!(last.value.as_ref(), b"intro" | b"hint");
        (intro && !device.is_empty() && device.iter().all(plain)).then_some(Marked::Introduction)
    }
}

pub(crate) struct TransitMarks {
    inner: Arc<Inner>,
}

struct Inner {
    engine: ForwarderEngine,
    /// The marks each face holds (`None`: this node's own), per namespace
    /// (never zero): apart from the links' reasons, so a release takes back
    /// only a mark its face made. A face's entry, once made, stays until
    /// the face closes: its watch for the close runs meanwhile.
    marks: Mutex<HashMap<Option<FaceId>, HashMap<Name, u64>>>,
}

impl TransitMarks {
    pub(crate) fn new(engine: ForwarderEngine) -> Self {
        Self {
            inner: Arc::new(Inner {
                engine,
                marks: Mutex::default(),
            }),
        }
    }

    /// One mark more on `namespace` (`carry`), or one taken back, for
    /// `face` (the management face that asked; `None`: this node).
    pub(crate) fn mark(
        &self,
        face: Option<FaceId>,
        namespace: Name,
        carry: bool,
    ) -> Result<ndn_mgmt::TransitInfo, TrustRefusal> {
        let Some(marked) = Marked::of(&namespace) else {
            return Err(TrustRefusal::new(
                code::TRANSIT_NOT_PERSONAL,
                format!(
                    "{namespace} is neither a self-certifying namespace (/user/<0xA1: 32 bytes>) \
                     nor an introduction's prefix (<device>/32=intro or <device>/32=hint): only a \
                     person's namespace, adopted by an app for one scope of its own, or an \
                     introduction's prefixes, carried for the length of a join, are carried in \
                     transit for an app; adopt any other namespace on this node from its anchor \
                     link, or let the link serving its devices carry it"
                ),
            )
            .with("namespace", namespace.to_string()));
        };
        let inner = &self.inner;
        let engine = &inner.engine;
        let transit = engine.transit();
        // Held across the engine's count, so marks and reasons move together.
        let mut marks = inner.marks.lock().unwrap_or_else(PoisonError::into_inner);
        if carry {
            if let Some(id) = face
                && !marks.contains_key(&face)
            {
                // The face's first mark: watch for its close. A face that
                // closed before its command was handled gets no answer,
                // and keeps no mark nobody would release.
                let Some(closed) = engine.face_token(id) else {
                    tracing::debug!(
                        face = %id,
                        %namespace,
                        "a transit mark asked by a face that closed meanwhile: not kept"
                    );
                    return Ok(inner.info(&marks, &namespace));
                };
                let watch = Arc::downgrade(inner);
                tokio::spawn(async move {
                    closed.cancelled().await;
                    Inner::face_closed(&watch, id);
                });
            }
            transit.add(&namespace, || {
                if marked == Marked::Namespace {
                    ndn_namespace::sync_group::carry(engine, &namespace);
                }
            });
            *marks
                .entry(face)
                .or_default()
                .entry(namespace.clone())
                .or_default() += 1;
        } else if let Some(own) = marks.get_mut(&face)
            && let Some(held) = own.get_mut(&namespace)
        {
            transit.remove(&namespace, || {
                if marked == Marked::Namespace {
                    ndn_namespace::sync_group::release(engine, &namespace);
                }
            });
            *held -= 1;
            if *held == 0 {
                own.remove(&namespace);
            }
        }
        // A release with no mark of the face held takes nothing: another
        // face's mark is that face's, a link's reason the link's.
        Ok(inner.info(&marks, &namespace))
    }
}

impl Inner {
    /// `face` closed: every mark it held is released.
    fn face_closed(watch: &Weak<Inner>, face: FaceId) {
        let Some(inner) = watch.upgrade() else {
            return;
        };
        let engine = &inner.engine;
        let transit = engine.transit();
        let mut marks = inner.marks.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = marks.remove(&Some(face)) else {
            return;
        };
        for (namespace, count) in &held {
            for _ in 0..*count {
                transit.remove(namespace, || {
                    if Marked::of(namespace) == Some(Marked::Namespace) {
                        ndn_namespace::sync_group::release(engine, namespace);
                    }
                });
            }
        }
        if !held.is_empty() {
            tracing::info!(
                face = %face,
                namespaces = ?held.keys().map(ToString::to_string).collect::<Vec<_>>(),
                "the face that marked these namespaces in transit closed: its marks are released"
            );
        }
    }

    /// The answer: the marks every face holds on `namespace` now.
    fn info(
        &self,
        marks: &HashMap<Option<FaceId>, HashMap<Name, u64>>,
        namespace: &Name,
    ) -> ndn_mgmt::TransitInfo {
        ndn_mgmt::TransitInfo {
            namespace: namespace.to_string(),
            marks: marks.values().filter_map(|own| own.get(namespace)).sum(),
            held: self
                .engine
                .keyring()
                .is_some_and(|k| !k.context_for(namespace).namespace().is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_security::self_certifying::self_certifying_name;

    use super::*;

    /// Marks are counted: two scopes marking one namespace and one
    /// releasing keep it in transit, the last release takes it out, and a
    /// release with no mark held never takes a link's reason.
    #[tokio::test]
    async fn marks_are_counted_and_never_take_a_links_reason() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .expect("engine build");
        let marks = TransitMarks::new(engine.clone());
        let carol = self_certifying_name(&[7; 32]);
        let page = carol.clone().append("page");
        let marked = |carry| {
            marks
                .mark(None, carol.clone(), carry)
                .expect("a person's namespace")
        };

        assert_eq!(marked(true).marks, 1);
        assert_eq!(marked(true).marks, 2);
        assert_eq!(marked(false).marks, 1);
        assert!(engine.transit().covers(&page), "one scope still marks it");
        assert_eq!(marked(false).marks, 0);
        assert!(!engine.transit().covers(&page), "the last mark is released");

        // A link serving carol's devices holds a reason of its own.
        engine.transit().add(&carol, || {});
        assert_eq!(marked(false).marks, 0, "no mark is held");
        assert!(
            engine.transit().covers(&page),
            "a release with no mark held keeps the link's reason"
        );
        assert_eq!(marked(true).marks, 1);
        engine.transit().remove(&carol, || {});
        assert!(
            engine.transit().covers(&page),
            "the link leaving keeps the app's mark"
        );
        assert_eq!(marked(false).marks, 0);
        assert!(!engine.transit().covers(&page));

        let refused = marks
            .mark(None, "/alice".parse().unwrap(), true)
            .expect_err("not a person's namespace");
        assert!(refused.is(code::TRANSIT_NOT_PERSONAL), "{refused:?}");
        assert!(!engine.transit().covers(&"/alice/x".parse().unwrap()));
        shutdown.shutdown().await;
    }

    /// A mark is owned by the face that asked: another face's release never
    /// takes it, and the face closing — its app ended, crashed or restarted
    /// — releases every mark it held, leaving the others'.
    #[tokio::test]
    async fn a_closed_face_leaves_no_mark_behind() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .expect("engine build");
        let app = engine.faces().alloc_id();
        let (face, _handle) = ndn_face::local::InProcFace::new(app, 8);
        engine.add_face(face, tokio_util::sync::CancellationToken::new());
        let marks = TransitMarks::new(engine.clone());
        let carol = self_certifying_name(&[7; 32]);
        let page = carol.clone().append("page");
        let mark = |face, carry| marks.mark(face, carol.clone(), carry).expect("a person's");

        assert_eq!(mark(Some(app), true).marks, 1);
        assert_eq!(mark(Some(app), true).marks, 2);
        assert_eq!(mark(None, true).marks, 3, "this node's own mark");
        let stranger = engine.faces().alloc_id();
        assert_eq!(
            mark(Some(stranger), false).marks,
            3,
            "a face takes back only marks of its own"
        );

        engine.remove_face(app);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while mark(Some(stranger), false).marks != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the closed face's two marks are still held: {:?}",
                mark(Some(stranger), false)
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(engine.transit().covers(&page), "the node's own mark stays");
        assert_eq!(
            mark(Some(app), true).marks,
            1,
            "a mark asked by a face already closed is not kept"
        );
        assert_eq!(mark(None, false).marks, 0);
        assert!(!engine.transit().covers(&page));
        shutdown.shutdown().await;
    }

    /// An introduction's two prefixes `<device>/32=intro` and `<device>/32=hint`
    /// (the joiner's host carries them for the length of a join, whose offer
    /// and hint record are signed by a namespace the daemon does not hold yet)
    /// are marked like a person's namespace — and nothing else of a device is:
    /// not its other prefixes, not a longer name under the keyword, not a
    /// keyword with no device before it. Their release works the same, and
    /// neither takes the sync-group action a namespace takes.
    #[tokio::test]
    async fn an_introductions_prefixes_and_no_other_name_of_a_device_are_marked() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .expect("engine build");
        let marks = TransitMarks::new(engine.clone());
        let name = |s: &str| s.parse::<Name>().expect("a name");
        let intro = name("/alice/member/laptop/32=intro");
        let hint = name("/alice/member/laptop/32=hint");
        let offer = name("/alice/member/laptop/32=intro/32=offer/abc");
        let record = name("/alice/member/laptop/32=hint/abc");

        let held = marks.mark(None, intro.clone(), true);
        assert_eq!(held.expect("the intro prefix").marks, 1);
        assert_eq!(
            marks
                .mark(None, hint.clone(), true)
                .expect("the hint prefix")
                .marks,
            1
        );
        assert!(engine.transit().covers(&offer));
        assert!(engine.transit().covers(&record));
        assert!(
            !engine
                .transit()
                .covers(&name("/alice/member/laptop/32=log/x")),
            "another prefix of the device is not carried"
        );
        assert!(!engine.transit().covers(&name("/alice/member/laptop")));

        for refused in [
            name("/alice/member/laptop"),
            name("/alice/member/laptop/32=log"),
            name("/alice/member/laptop/32=intro/32=offer"),
            name("/alice/member/laptop/32=hint/abc"),
            name("/32=intro"),
        ] {
            let why = marks
                .mark(None, refused.clone(), true)
                .expect_err("not an introduction prefix");
            assert!(why.is(code::TRANSIT_NOT_PERSONAL), "{refused}: {why:?}");
        }

        assert_eq!(marks.mark(None, hint, false).expect("released").marks, 0);
        assert!(
            !engine.transit().covers(&record),
            "the release takes it out"
        );
        shutdown.shutdown().await;
    }
}
