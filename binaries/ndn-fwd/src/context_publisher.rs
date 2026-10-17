//! Publication of the node's stored trust contexts by name, following the RDR
//! convention, so a device holding only an anchor fingerprint can fetch a
//! context (`ndn_cert::fetch_context`) and pin it (`ndn_cert::adopt_with_tofu`).
//!
//! For every context in `<pib>/contexts/` (`ndn-fwd init` stores the root device's
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
//! `/<ns>/32=trust-context` per context — more specific than a `[ca]`
//! entry `/<ns>`, so longest-prefix match routes here. The store holds one file
//! (the newest adopted version) per namespace, so "newest stored version" is
//! that file's. The store is read at startup; a context the running daemon
//! adopts (`security/context-adopt`) is added with
//! [`PublishedContexts::publish`], replacing any older version of the same
//! namespace, and served at once.

use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::Producer;
use ndn_app::rdr::MetaData;
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, NackReason, Name};
use ndn_security::SignedTrustContext;
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

impl Published {
    fn new(ctx: &SignedTrustContext, data: &Data) -> Self {
        let versioned = ctx.rdr_name();
        Self {
            prefix: ndn_cert::rdr_prefix(ctx.namespace()),
            metadata_name: ndn_cert::rdr_metadata_name(ctx.namespace()),
            metadata: metadata_data(ctx.namespace(), &versioned, ctx.version()),
            versioned,
            context: data.raw().clone(),
        }
    }
}

/// The published set: swapped whole on change, so the serve loop reads a
/// consistent snapshot without holding a lock across a reply.
type Snapshot = Arc<Vec<Published>>;

/// The publisher between engine build (its face is attached) and spawn (its
/// FIB entries are installed and the serve loop starts).
pub(crate) struct ContextPublisher {
    face_id: FaceId,
    handle: InProcHandle,
    contexts: Vec<Published>,
}

/// Read the context store under `pib_root` and build the replies. Returns the
/// face to attach before build. The face exists even when nothing is stored
/// yet, so a context adopted at runtime can be published (an unreadable
/// store is logged, like the keyring load beside it).
pub(crate) fn prepare(pib_root: &Path) -> (InProcFace, ContextPublisher) {
    let stored = match ndn_cert::read_stored_contexts(pib_root) {
        Ok(stored) => stored,
        Err(e) => {
            tracing::warn!(target: "security", error = %e, "cannot read trust contexts to publish");
            Vec::new()
        }
    };
    let mut contexts = Vec::with_capacity(stored.len());
    for (path, result) in stored {
        match result {
            Ok((ctx, data)) => contexts.push(Published::new(&ctx, &data)),
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
            "no stored trust context to publish yet"
        );
    }
    let face_id = FaceId(CONTEXT_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);
    (
        face,
        ContextPublisher {
            face_id,
            handle,
            contexts,
        },
    )
}

/// The RDR metadata Data for the context `versioned` of `namespace`:
/// `<ns>/32=trust-context/32=metadata/v=<version>/seg=0`, Content = the
/// versioned Name only (no segment fields: the context is one Data).
///
/// Signed with DigestSha256, not the node key. The metadata is an
/// unauthenticated pointer by design: an adopter holds only the anchor
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

/// `current` with `added` in place of any entry for the same namespace.
fn with_context(current: &[Published], added: Published) -> Vec<Published> {
    let mut next: Vec<Published> = current
        .iter()
        .filter(|c| c.prefix != added.prefix)
        .map(|c| Published {
            prefix: c.prefix.clone(),
            metadata_name: c.metadata_name.clone(),
            versioned: c.versioned.clone(),
            context: c.context.clone(),
            metadata: c.metadata.clone(),
        })
        .collect();
    next.push(added);
    next
}

impl ContextPublisher {
    /// Install one FIB entry per published context and start serving.
    /// Returns the handle that publishes contexts adopted later.
    pub(crate) fn spawn(self, engine: &ForwarderEngine) -> PublishedContexts {
        for c in &self.contexts {
            log_published(engine, c, self.face_id);
        }
        let published = PublishedContexts {
            engine: engine.clone(),
            face_id: self.face_id,
            list: Arc::new(RwLock::new(Arc::new(self.contexts))),
            bypassed: Arc::new(Mutex::new(HashMap::new())),
        };
        let list = Arc::clone(&published.list);
        let producer = Producer::from_handle(self.handle, Name::root());
        tokio::spawn(async move {
            let served = producer
                .serve(|interest, responder| {
                    let snapshot: Snapshot = Arc::clone(
                        &list.read().unwrap_or_else(|poisoned| poisoned.into_inner()),
                    );
                    async move {
                        let sent = match answer(&snapshot, &interest.name) {
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
        published
    }
}

fn log_published(engine: &ForwarderEngine, c: &Published, face_id: FaceId) {
    engine.fib().add_nexthop(&c.prefix, face_id, 0);
    tracing::info!(
        target: "security",
        prefix = %c.prefix,
        context = %c.versioned,
        face = face_id.0,
        "publishing trust context (RDR)"
    );
}

/// The running publisher's set of contexts, shared with the adoption backend.
#[derive(Clone)]
pub(crate) struct PublishedContexts {
    engine: ForwarderEngine,
    face_id: FaceId,
    list: Arc<RwLock<Snapshot>>,
    /// `/<ns>/32=trust-context` prefixes whose FIB entry toward this
    /// publisher is withdrawn, with how many adoption fetches need it so.
    bypassed: Arc<Mutex<HashMap<Name, usize>>>,
}

impl PublishedContexts {
    /// Serve `ctx` (signed Data `data`) from now on, replacing an earlier
    /// version of the same namespace.
    pub(crate) fn publish(&self, ctx: &SignedTrustContext, data: &Data) {
        let added = Published::new(ctx, data);
        let bypassed = self.lock_bypassed();
        if bypassed.contains_key(&added.prefix) {
            // Routed toward the publisher again when the fetch ends.
            tracing::info!(target: "security", context = %added.versioned, "publishing trust context (RDR)");
        } else {
            log_published(&self.engine, &added, self.face_id);
        }
        let mut list = self.list.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        *list = Arc::new(with_context(&list, added));
    }

    /// While the returned guard lives, Interests under `namespace`'s
    /// trust-context prefix are not routed to this publisher, so an adoption
    /// fetch reaches the forwarders that serve the namespace instead of
    /// being answered with the version this node already holds (which would
    /// make a newer version impossible to fetch).
    pub(crate) fn bypass(&self, namespace: &Name) -> PublisherBypass {
        let prefix = ndn_cert::rdr_prefix(namespace);
        let mut bypassed = self.lock_bypassed();
        let count = bypassed.entry(prefix.clone()).or_insert(0);
        if *count == 0 {
            self.engine.fib().remove_nexthop(&prefix, self.face_id);
        }
        *count += 1;
        PublisherBypass {
            published: self.clone(),
            prefix,
        }
    }

    fn lock_bypassed(&self) -> std::sync::MutexGuard<'_, HashMap<Name, usize>> {
        self.bypassed.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// See [`PublishedContexts::bypass`]; routes the prefix back to the
/// publisher on drop (if it still publishes it and no other fetch runs).
pub(crate) struct PublisherBypass {
    published: PublishedContexts,
    prefix: Name,
}

impl Drop for PublisherBypass {
    fn drop(&mut self) {
        let p = &self.published;
        let mut bypassed = p.lock_bypassed();
        let Some(count) = bypassed.get_mut(&self.prefix) else {
            return;
        };
        *count -= 1;
        if *count > 0 {
            return;
        }
        bypassed.remove(&self.prefix);
        let list = p.list.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if list.iter().any(|c| c.prefix == self.prefix) {
            p.engine.fib().add_nexthop(&self.prefix, p.face_id, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Data;

    fn published(dir: &Path) -> Vec<Published> {
        prepare(dir).1.contexts
    }

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn stored(dir: &Path, ns: &str) -> ndn_cert::NamespaceInit {
        let root_dev = ndn_cert::init_namespace(&ndn_security::SecurityManager::new(), &n(ns)).unwrap();
        ndn_cert::persist_context(dir, &root_dev.context, &root_dev.context_data).unwrap();
        root_dev
    }

    #[test]
    fn serves_stored_context_verbatim_and_metadata_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let bob = stored(dir.path(), "/home/bob");
        let alice = stored(dir.path(), "/home/alice");
        let contexts = published(dir.path());

        for root_dev in [&bob, &alice] {
            let ns = root_dev.context.namespace();
            let versioned = root_dev.context.rdr_name();
            // Exact versioned name → the stored signed Data, byte-identical.
            assert_eq!(
                answer(&contexts, &versioned),
                Some(root_dev.context_data.raw())
            );
            // Metadata → RDR Name-only content pointing at exactly that name,
            // under this namespace (what `fetch_context` accepts).
            let wire = answer(&contexts, &ndn_cert::rdr_metadata_name(ns))
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
            assert_eq!(answer(&contexts, &n(other)), None, "{other}");
        }
    }

    #[test]
    fn damaged_store_file_is_not_published() {
        let dir = tempfile::tempdir().unwrap();
        stored(dir.path(), "/home/bob");
        let path = ndn_cert::context_file_path(dir.path(), &n("/home/bob"));
        std::fs::write(&path, b"not a Data packet").unwrap();
        assert!(published(dir.path()).is_empty());
    }

    #[test]
    fn empty_store_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(published(dir.path()).is_empty());
    }

    /// A context adopted at runtime is served at once and replaces the entry
    /// of its namespace (one per namespace), leaving others alone.
    #[test]
    fn adopted_context_replaces_its_namespace_entry() {
        let dir = tempfile::tempdir().unwrap();
        let bob = stored(dir.path(), "/home/bob");
        let alice = ndn_cert::init_namespace(&ndn_security::SecurityManager::new(), &n("/home/alice"))
            .unwrap();
        let other_bob =
            ndn_cert::init_namespace(&ndn_security::SecurityManager::new(), &n("/home/bob")).unwrap();
        let start = published(dir.path());
        let added = with_context(&start, Published::new(&alice.context, &alice.context_data));
        assert_eq!(added.len(), 2);
        assert_eq!(
            answer(&added, &alice.context.rdr_name()),
            Some(alice.context_data.raw())
        );
        assert_eq!(
            answer(&added, &bob.context.rdr_name()),
            Some(bob.context_data.raw())
        );
        let replaced = with_context(
            &added,
            Published::new(&other_bob.context, &other_bob.context_data),
        );
        assert_eq!(replaced.len(), 2);
        assert_eq!(
            answer(&replaced, &other_bob.context.rdr_name()),
            Some(other_bob.context_data.raw())
        );
    }

    /// While the node adopts a namespace by fetching, Interests for its
    /// trust context go where the namespace is served (here: the `/home/bob`
    /// route), not to this node's own publisher holding an older version;
    /// afterwards the publisher serves again.
    #[tokio::test]
    async fn adoption_fetches_bypass_the_local_publisher() {
        let dir = tempfile::tempdir().unwrap();
        stored(dir.path(), "/home/bob");
        let (face, publisher) = prepare(dir.path());
        let publisher_face = publisher.face_id;
        let (engine, shutdown) = ndn_engine::EngineBuilder::new(ndn_engine::EngineConfig::default())
            .face(face)
            .build()
            .await
            .unwrap();
        let published = publisher.spawn(&engine);
        let upstream = FaceId(4242);
        engine.fib().add_nexthop(&n("/home/bob"), upstream, 0);
        let metadata = ndn_cert::rdr_metadata_name(&n("/home/bob"));
        let next_face = |e: &ForwarderEngine| e.fib().lpm(&metadata).unwrap().nexthops[0].face_id;
        assert_eq!(next_face(&engine), publisher_face);

        let first = published.bypass(&n("/home/bob"));
        let second = published.bypass(&n("/home/bob"));
        assert_eq!(next_face(&engine), upstream);
        drop(first);
        assert_eq!(next_face(&engine), upstream, "another fetch still runs");
        drop(second);
        assert_eq!(next_face(&engine), publisher_face);
        shutdown.shutdown().await;
    }
}
