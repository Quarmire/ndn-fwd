//! Publication of the node's stored trust contexts by name, following the RDR
//! convention, so a device holding only an anchor fingerprint can fetch a
//! context (`ndn_cert::fetch_context`) and pin it (`ndn_cert::adopt_with_tofu`).
//!
//! For every context in `<pib>/contexts/` (`ndn-fwd init` stores the hub's
//! own there, `ndn-fwd adopt` the adopted ones), re-verified on read — a file
//! that fails is not published:
//!
//! - `/<ns>/32=trust-context/v=<N>` (exact) → the stored signed Data,
//!   byte-identical; it is never re-signed, so its root signature is what the
//!   fetcher pins.
//! - `/<ns>/32=trust-context/32=metadata` → RDR metadata Data
//!   `/<ns>/32=trust-context/32=metadata/v=<N>/seg=0` whose Content is the
//!   versioned Name alone, FreshnessPeriod [`METADATA_FRESHNESS`],
//!   DigestSha256 (see [`metadata_data`] for why it is not signed).
//! - anything else under the prefix → Nack(NoRoute), so a fetch of a version
//!   this node does not hold fails at once instead of timing out.
//!
//! One in-process face carries all of it, with one FIB entry
//! `/<ns>/32=trust-context` per context — more specific than a `[demo_ca]`
//! entry `/<ns>`, so longest-prefix match routes here. The store holds one file
//! (the newest adopted version) per namespace, so "newest stored version" is
//! that file's. The store is read once at startup; a context adopted later is
//! served after the daemon restarts.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::Producer;
use ndn_app::rdr::MetaData;
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{NackReason, Name};
use ndn_transport::FaceId;

pub(crate) const CONTEXT_FACE_ID: u64 = 0xFFFF_0005;

/// RDR metadata names "the newest version now"; a short freshness makes a
/// MustBeFresh discovery Interest reach the publisher again soon after an
/// update instead of being answered from caches. Matches
/// `ndn_app::rdr` (the same 1 s for objects it publishes).
const METADATA_FRESHNESS: Duration = Duration::from_secs(1);

/// One published context: the names it answers and the wires it answers with.
#[derive(Debug)]
struct Published {
    prefix: Name,
    metadata_name: Name,
    versioned: Name,
    /// The stored signed Data, verbatim.
    context: Bytes,
    /// The RDR metadata Data pointing at `versioned`.
    metadata: Bytes,
}

/// The publisher between engine build (its face is attached) and spawn (its
/// FIB entries are installed and the serve loop starts).
pub(crate) struct ContextPublisher {
    face_id: FaceId,
    handle: InProcHandle,
    contexts: Vec<Published>,
}

/// Read the context store under `pib_root` and build the replies. Returns the
/// face to attach before build, or `None` when there is nothing to publish
/// (an unreadable store is logged, like the keyring load beside it).
pub(crate) fn prepare(pib_root: &Path) -> Option<(InProcFace, ContextPublisher)> {
    let stored = match ndn_cert::read_stored_contexts(pib_root) {
        Ok(stored) => stored,
        Err(e) => {
            tracing::warn!(target: "security", error = %e, "cannot read trust contexts to publish");
            return None;
        }
    };
    let mut contexts = Vec::with_capacity(stored.len());
    for (path, result) in stored {
        match result {
            Ok((ctx, data)) => {
                let versioned = ctx.rdr_name();
                contexts.push(Published {
                    prefix: ndn_cert::rdr_prefix(ctx.namespace()),
                    metadata_name: ndn_cert::rdr_metadata_name(ctx.namespace()),
                    metadata: metadata_data(ctx.namespace(), &versioned, ctx.version()),
                    versioned,
                    context: data.raw().clone(),
                });
            }
            Err(e) => tracing::warn!(
                target: "security",
                path = %path.display(),
                error = %e,
                "not publishing stored trust context"
            ),
        }
    }
    if contexts.is_empty() {
        tracing::info!(
            target: "security",
            store = %pib_root.join(ndn_cert::context_store::CONTEXTS_DIR).display(),
            "no stored trust context to publish"
        );
        return None;
    }
    let face_id = FaceId(CONTEXT_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);
    Some((
        face,
        ContextPublisher {
            face_id,
            handle,
            contexts,
        },
    ))
}

/// The RDR metadata Data for the context `versioned` of `namespace`:
/// `<ns>/32=trust-context/32=metadata/v=<version>/seg=0`, Content = the
/// versioned Name only (no segment fields: the context is one Data).
///
/// Signed with DigestSha256, not the node key. The metadata is an
/// unauthenticated pointer by design: a joiner holds only the anchor
/// fingerprint and cannot check a node signature, and `fetch_context` confines
/// the pointer to `<ns>/32=trust-context/v=<N>` before the pinned context
/// signature decides trust. A node-key signature would also be *rejected*:
/// every forwarder that holds this namespace's context validates Data arriving
/// on a non-local face against the generated schema, which has no rule for the
/// metadata name (`ndn-fwd schema explain` → deny), so a key-signed metadata
/// Data is dropped one hop away; DigestSha256 is accepted as integrity-only.
fn metadata_data(namespace: &Name, versioned: &Name, version: u64) -> Bytes {
    let content = MetaData {
        versioned_name: versioned.clone(),
        ..MetaData::default()
    }
    .encode();
    let name = ndn_cert::rdr_metadata_name(namespace)
        .append_version(version)
        .append_segment(0);
    DataBuilder::new(name, &content)
        .freshness(METADATA_FRESHNESS)
        .build()
}

/// What to answer an Interest named `name` with: a stored wire, or `None`
/// for a Nack.
fn answer<'a>(contexts: &'a [Published], name: &Name) -> Option<&'a Bytes> {
    contexts.iter().find_map(|c| {
        if *name == c.versioned {
            Some(&c.context)
        } else if *name == c.metadata_name {
            Some(&c.metadata)
        } else {
            None
        }
    })
}

impl ContextPublisher {
    /// Install one FIB entry per published context and start serving.
    pub(crate) fn spawn(self, engine: &ForwarderEngine) {
        for c in &self.contexts {
            engine.fib().add_nexthop(&c.prefix, self.face_id, 0);
            tracing::info!(
                target: "security",
                prefix = %c.prefix,
                context = %c.versioned,
                face = self.face_id.0,
                "publishing trust context (RDR)"
            );
        }
        let contexts = Arc::new(self.contexts);
        let producer = Producer::from_handle(self.handle, Name::root());
        tokio::spawn(async move {
            let served = producer
                .serve(|interest, responder| {
                    let contexts = Arc::clone(&contexts);
                    async move {
                        let sent = match answer(&contexts, &interest.name) {
                            Some(wire) => responder.respond_bytes(wire.clone()).await,
                            None => responder.nack(NackReason::NoRoute).await,
                        };
                        if let Err(e) = sent {
                            tracing::debug!(
                                target: "security",
                                name = %interest.name,
                                error = %e,
                                "trust-context reply not sent"
                            );
                        }
                    }
                })
                .await;
            if let Err(e) = served {
                tracing::error!(target: "security", error = %e, "trust-context publisher exited");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Data;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn stored(dir: &Path, ns: &str) -> ndn_cert::HubInit {
        let hub = ndn_cert::init_hub(&ndn_security::SecurityManager::new(), &n(ns)).unwrap();
        ndn_cert::persist_context(dir, &hub.context, &hub.context_data).unwrap();
        hub
    }

    #[test]
    fn serves_stored_context_verbatim_and_metadata_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let bob = stored(dir.path(), "/home/bob");
        let alice = stored(dir.path(), "/home/alice");
        let (_face, publisher) = prepare(dir.path()).expect("two contexts stored");

        for hub in [&bob, &alice] {
            let ns = hub.context.namespace();
            let versioned = hub.context.rdr_name();
            // Exact versioned name → the stored signed Data, byte-identical.
            assert_eq!(
                answer(&publisher.contexts, &versioned),
                Some(hub.context_data.raw())
            );
            // Metadata → RDR Name-only content pointing at exactly that name,
            // under this namespace (what `fetch_context` accepts).
            let wire = answer(&publisher.contexts, &ndn_cert::rdr_metadata_name(ns))
                .expect("metadata served");
            let meta = Data::decode(wire.clone()).unwrap();
            assert!(meta.name.has_prefix(&ndn_cert::rdr_metadata_name(ns)));
            let content = meta.content().unwrap();
            assert_eq!(*content, versioned.encode_to_tlv());
            assert_eq!(ndn_cert::context_pointer(ns, content).unwrap(), versioned);
            assert_eq!(
                meta.meta_info().and_then(|m| m.freshness_period),
                Some(METADATA_FRESHNESS)
            );
        }
        // Another version, the bare prefix, or anything else → Nack.
        for other in [
            "/home/bob/32=trust-context/v=2",
            "/home/bob/32=trust-context",
            "/home/bob/32=trust-context/32=metadata/v=1/seg=0",
            "/home/eve/32=trust-context/32=metadata",
        ] {
            assert_eq!(answer(&publisher.contexts, &n(other)), None, "{other}");
        }
    }

    #[test]
    fn damaged_store_file_is_not_published() {
        let dir = tempfile::tempdir().unwrap();
        stored(dir.path(), "/home/bob");
        let path = ndn_cert::context_file_path(dir.path(), &n("/home/bob"));
        std::fs::write(&path, b"not a Data packet").unwrap();
        assert!(prepare(dir.path()).is_none());
    }

    #[test]
    fn empty_store_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(prepare(dir.path()).is_none());
    }
}
