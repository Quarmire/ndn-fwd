//! The namespaces local apps asked this daemon to carry in transit
//! (`security/transit`, `ndn-rs/docs/specs/mgmt-trust.md` "Transit"): a
//! person's self-certifying namespace an app adopted for one scope of its
//! own alone (a data host's folders), whose Data this forwarder, not
//! holding it, forwards unvalidated to the Interests pending for it and
//! never caches. Each mark is one reason in the engine's count of the
//! namespace's reasons to be in transit (`TransitPrefixes`), beside the
//! links'; the first reason and the last run the links' action (the
//! namespace's sync group with the multicast strategy). The keyring is
//! never touched.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use ndn_engine::ForwarderEngine;
use ndn_namespace::{TrustRefusal, code};
use ndn_packet::Name;
use ndn_security::self_certifying::self_certifying_digest;

pub(crate) struct TransitMarks {
    engine: ForwarderEngine,
    /// The marks apps hold, per namespace (never zero): apart from the
    /// links' reasons, so a release takes back only a mark an app made.
    marks: Mutex<HashMap<Name, u64>>,
}

impl TransitMarks {
    pub(crate) fn new(engine: ForwarderEngine) -> Self {
        Self {
            engine,
            marks: Mutex::default(),
        }
    }

    /// One mark more on `namespace` (`carry`), or one taken back.
    pub(crate) fn mark(
        &self,
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
        let engine = &self.engine;
        let transit = engine.transit();
        // Held across the engine's count, so marks and reasons move together.
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
        let held = if carry {
            transit.add(&namespace, || {
                ndn_namespace::sync_group::carry(engine, &namespace)
            });
            let held = marks.entry(namespace.clone()).or_default();
            *held += 1;
            *held
        } else {
            // No mark of an app's held: nothing to take back (a link's
            // reason is the link's).
            let Some(held) = marks.get_mut(&namespace) else {
                return Ok(self.info(&namespace, 0));
            };
            transit.remove(&namespace, || {
                ndn_namespace::sync_group::release(engine, &namespace)
            });
            *held -= 1;
            let left = *held;
            if left == 0 {
                marks.remove(&namespace);
            }
            left
        };
        Ok(self.info(&namespace, held))
    }

    /// The answer: `marks` apps hold on `namespace` now.
    fn info(&self, namespace: &Name, marks: u64) -> ndn_mgmt::TransitInfo {
        ndn_mgmt::TransitInfo {
            namespace: namespace.to_string(),
            marks,
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
                .mark(carol.clone(), carry)
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
            .mark("/alice".parse().unwrap(), true)
            .expect_err("not a person's namespace");
        assert!(refused.is(code::TRANSIT_NOT_PERSONAL), "{refused:?}");
        assert!(!engine.transit().covers(&"/alice/x".parse().unwrap()));
        shutdown.shutdown().await;
    }
}
