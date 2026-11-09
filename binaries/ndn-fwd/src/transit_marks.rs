//! The namespaces local apps asked this daemon to carry in transit
//! (`security/transit`, `ndn-rs/docs/specs/mgmt-trust.md` "Transit"): a
//! person's self-certifying namespace an app adopted for one scope of its
//! own alone (a data host's folders), whose Data this forwarder, not
//! holding it, forwards unvalidated to the Interests pending for it and
//! never caches. Each mark is one reason in the engine's count of the
//! namespace's reasons to be in transit (`TransitPrefixes`), beside the
//! links'; the first reason and the last run the links' action (the
//! namespace's sync group with the multicast strategy). A mark is owned by
//! the management face that asked, and released when that face closes: an
//! app that ends, crashes or restarts leaves no mark behind. The keyring is
//! never touched.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use ndn_engine::ForwarderEngine;
use ndn_namespace::{TrustRefusal, code};
use ndn_packet::Name;
use ndn_security::self_certifying::self_certifying_digest;
use ndn_transport::FaceId;

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
        if !matches!(self_certifying_digest(&namespace), Ok(Some(_))) {
            return Err(TrustRefusal::new(
                code::TRANSIT_NOT_PERSONAL,
                format!(
                    "{namespace} is not a self-certifying namespace (/user/<0xA1: 32 bytes>): \
                     only a person's namespace, adopted by an app for one scope of its own, is \
                     carried in transit for it; adopt any other namespace on this node from its \
                     anchor link, or let the link serving its devices carry it"
                ),
            )
            .with("namespace", namespace.to_string()));
        }
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
                ndn_namespace::sync_group::carry(engine, &namespace)
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
                ndn_namespace::sync_group::release(engine, &namespace)
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
                    ndn_namespace::sync_group::release(engine, namespace)
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
                .is_some_and(|k| k.version_of(namespace).is_some()),
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
}
