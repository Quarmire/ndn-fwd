//! Trust-context updates pushed over each namespace's sync group
//! (`[security] context_sync = true`), beside the periodic refresh
//! ([`crate::context_refresh`]).
//!
//! The daemon joins the SVS group of every namespace it holds
//! ([`ndn_identity::context_sync::group_prefix`]:
//! `/<ns>/32=trust-context/32=sync`) at start, and of every namespace it
//! adopts later, as `<group>/<member>` (a name stable across restarts of the
//! node, see [`member_id`]). Each version announced in a group is fetched and
//! adopted by [`ndn_identity::context_sync::run`] under the continuity rule
//! of the refresh — signed by an anchor of the held version, strictly newer,
//! following the versions in between when needed — and kept by
//! [`crate::context_refresh::keep_update`], the code a refresh keeps with:
//! stored, published, and the versions walked through too. A refused version
//! is logged with its reason; the held version stays in force.
//!
//! **The root device publishes.** Every version this node keeps
//! ([`crate::context_adopt::TrustAdmin::keep`], whichever way it came: a
//! revocation, a version handed over with `security/context-update`, a
//! refresh, a recovery) is handed to [`ContextSync::kept`]. When this node's
//! root store holds an anchor key of that version, it serves the version's
//! signed Data at `<group>/<member>/seg=<version>`
//! ([`ndn_identity::context_sync::group_data`]) and advances its sequence
//! number to the version, announcing it to the group at once. Other members
//! only subscribe.
//!
//! **Routes.** SVS floods Sync Interests to every member, so the group needs
//! a route both ways. Up: the group is routed over the non-local faces the
//! namespace itself is routed over (the route a device has toward the root
//! device or a relay), taken when the group is joined and again for each
//! Sync Interest this node sends or receives (SVS may suppress this node's
//! own for as long as its neighbours' keep arriving).
//! Down: each face a Sync Interest of the group arrives on is added to the
//! group's route, so the root device reaches the devices that joined
//! without a route configured toward them. Each such face routes both the
//! Sync Interests (`<group>/v=<SVS dialect>`) and the group Data
//! (`<group>`); this node's own sync face routes the Sync Interests only.
//! Were it a nexthop of `<group>`, a neighbour's fetch of `<group>/<member>/
//! seg=N` would be multicast to it alone (the face it came from excluded),
//! go no further, and hold the PIT entry this node's own fetch of the same
//! version is aggregated onto until both time out. The group runs the
//! multicast strategy. A relay between them carries the group only if it
//! runs `context_sync` too; otherwise the devices behind it get updates by
//! refresh. A version whose fetch failed is fetched again while it is newer
//! than the held one ([`ndn_identity::context_sync::Retry`]).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, Producer};
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_identity::context_sync::{self as group, ContextFetcher};
use ndn_packet::{Data, Interest, NackReason, Name, NameComponent};
use ndn_security::SignedTrustContext;
use ndn_strategy::{ErasedStrategy, MulticastStrategy};
use ndn_sync::{SvsConfig, join_svs_group};
use ndn_transport::{FaceId, FacePersistency, FaceScope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::context_adopt::TrustAdmin;
use crate::context_refresh::{Adopted, holds_root_key, keep_update};

const FACE_BUFFER: usize = 256;

/// The cost of a group route toward a member or upstream (multicast sends
/// on every one of them, so it orders nothing).
const MEMBER_COST: u32 = 10;

/// A version this node kept, for the groups task.
struct KeptVersion {
    namespace: Name,
    version: u64,
    /// The signed context Data's wire.
    data: Bytes,
    /// This node's root store holds an anchor key of the version.
    root: bool,
}

/// The handle [`TrustAdmin`] hands each kept version to.
pub(crate) struct ContextSync {
    pib_root: PathBuf,
    kept: mpsc::UnboundedSender<KeptVersion>,
}

impl ContextSync {
    /// `ctx` (signed Data `data`) was stored and published: join its
    /// namespace's group if this node has not, and on the root device put
    /// the version into the group.
    pub(crate) fn kept(&self, ctx: &SignedTrustContext, data: &Data) {
        let kept = KeptVersion {
            namespace: ctx.namespace().clone(),
            version: ctx.version(),
            data: data.raw().clone(),
            root: holds_root_key(&self.pib_root, ctx),
        };
        if self.kept.send(kept).is_err() {
            tracing::debug!(
                target: "security",
                namespace = %ctx.namespace(),
                "trust-context sync is stopped; the version is not put into its group"
            );
        }
    }
}

/// The groups task between start-up (its [`ContextSync`] goes into the
/// [`TrustAdmin`]) and [`Groups::spawn`].
pub(crate) struct Groups {
    kept: mpsc::UnboundedReceiver<KeptVersion>,
    member: NameComponent,
    pub(crate) svs: SvsConfig,
    pub(crate) retry: group::Retry,
}

/// With `[security] context_sync`, the handle for the [`TrustAdmin`] and the
/// task to spawn once it exists.
pub(crate) fn prepare(enabled: bool, pib_root: &Path) -> Option<(ContextSync, Groups)> {
    if !enabled {
        return None;
    }
    let (tx, rx) = mpsc::unbounded_channel();
    Some((
        ContextSync {
            pib_root: pib_root.to_path_buf(),
            kept: tx,
        },
        Groups {
            kept: rx,
            member: member_id(pib_root),
            // Routed links, not one LAN: a Sync Interest every ~15 s per
            // group. A new version is announced at once; the period bounds
            // how soon the root device learns the face of a member that
            // (re)joined, and how soon a lost announcement is repeated.
            svs: SvsConfig::wan(),
            retry: group::Retry::default(),
        },
    ))
}

/// This node's member name component: stable across restarts (SVS keeps one
/// entry per member name) and distinct per node — a hash of the machine's
/// id (else its host name) and the PIB's path.
fn member_id(pib_root: &Path) -> NameComponent {
    let machine = ["/etc/machine-id", "/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let pib = std::fs::canonicalize(pib_root).unwrap_or_else(|_| pib_root.to_path_buf());
    // FNV-1a, 64 bits.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let bytes = machine.trim().as_bytes().iter().chain(&[0]).chain(pib.as_os_str().as_encoded_bytes());
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    NameComponent::generic(Bytes::from(format!("{hash:016x}")))
}

impl Groups {
    /// Join the group of every namespace held, then follow the versions
    /// kept, until `cancel`.
    pub(crate) fn spawn(self, admin: Arc<TrustAdmin>, cancel: CancellationToken) {
        tokio::spawn(self.run(admin, cancel));
    }

    async fn run(mut self, admin: Arc<TrustAdmin>, cancel: CancellationToken) {
        let mut joined: HashMap<Name, Group> = HashMap::new();
        for held in admin.keyring.contexts() {
            let namespace = held.namespace().clone();
            let root = holds_root_key(&admin.pib_root, &held);
            // The root device announces the version it holds as its
            // sequence number; the versions it stores are served by it.
            let seq = if root { held.version() } else { 0 };
            let group =
                Group::join(&admin, &self.member, &namespace, seq, &self.svs, self.retry, &cancel);
            if root {
                group.serve_stored(&admin.pib_root, &namespace);
            }
            joined.insert(namespace, group);
        }
        loop {
            let kept = tokio::select! {
                _ = cancel.cancelled() => return,
                kept = self.kept.recv() => match kept {
                    Some(kept) => kept,
                    None => return,
                },
            };
            let group = joined.entry(kept.namespace.clone()).or_insert_with(|| {
                Group::join(&admin, &self.member, &kept.namespace, 0, &self.svs, self.retry, &cancel)
            });
            if kept.root {
                group.put(&kept).await;
            }
        }
    }
}

/// This node's membership in one namespace's group.
struct Group {
    namespace: Name,
    /// `<group>/<member>`.
    node: Name,
    /// The SVS publication channel: each message advances the sequence
    /// number by one and announces it.
    publish: mpsc::Sender<(Name, Option<Bytes>)>,
    /// The sequence number announced: the newest version this node put into
    /// the group.
    seq: u64,
    /// The group Data this node serves, by sequence number (= version).
    served: Arc<RwLock<BTreeMap<u64, Bytes>>>,
}

impl Group {
    /// Join `namespace`'s group as `<group>/<member>` announcing `seq`,
    /// and subscribe: each version announced by another member is adopted
    /// under the continuity rule and kept as a refreshed one is.
    fn join(
        admin: &Arc<TrustAdmin>,
        member: &NameComponent,
        namespace: &Name,
        seq: u64,
        svs: &SvsConfig,
        retry: group::Retry,
        cancel: &CancellationToken,
    ) -> Self {
        let engine = &admin.engine;
        let prefix = group::group_prefix(namespace);
        let node = prefix.clone().append_component(member.clone());
        engine.strategy_table().insert(
            &prefix,
            Arc::new(MulticastStrategy::new()) as Arc<dyn ErasedStrategy>,
        );

        // Sync Interests in and out; nothing else (see the module docs).
        let sync = prefix.clone().append_version(svs.dialect.sync_version());
        let (sync_id, sync_face) = local_face(engine, cancel);
        engine.fib().add_nexthop(&sync, sync_id, 0);
        let (serve_id, serve_face) = local_face(engine, cancel);
        engine.fib().add_nexthop(&node, serve_id, 0);
        let served = Arc::new(RwLock::new(BTreeMap::new()));
        serve(serve_face, node.clone(), Arc::clone(&served));

        let routes = Routes {
            engine: engine.clone(),
            namespace: namespace.clone(),
            group: prefix.clone(),
            sync,
            own: sync_id,
        };
        let (out_tx, out_rx) = mpsc::channel(FACE_BUFFER);
        let (in_tx, in_rx) = mpsc::channel(FACE_BUFFER);
        let handle = join_svs_group(
            prefix.clone(),
            node.clone(),
            out_tx,
            in_rx,
            SvsConfig {
                local_seq: seq,
                ..svs.clone()
            },
        );
        let publish = handle.tx.clone();
        pump(routes, Arc::new(sync_face), out_rx, in_tx, cancel.child_token());

        let fetcher: Arc<dyn ContextFetcher> = Arc::new(EngineFetcher(tokio::sync::Mutex::new(
            engine.app_consumer(cancel.child_token()),
        )));
        let keeper = Arc::clone(admin);
        tokio::spawn(group::run(
            handle,
            namespace.clone(),
            fetcher,
            Arc::clone(&admin.keyring),
            move |update| {
                // `keep_update` logs what became of it.
                let _ = keep_update(&keeper, update, Adopted::OverSync);
            },
            retry,
            cancel.child_token(),
        ));
        tracing::info!(
            target: "security",
            namespace = %namespace,
            group = %prefix,
            member = %node,
            seq,
            "joined the namespace's trust-context sync group"
        );
        Self {
            namespace: namespace.clone(),
            node,
            publish,
            seq,
            served,
        }
    }

    /// Serve every version of `namespace` stored under `pib_root`.
    fn serve_stored(&self, pib_root: &Path, namespace: &Name) {
        let stored = ndn_cert::read_stored_versions(pib_root, namespace)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, read)| read.ok())
            .chain(ndn_cert::read_stored_context(pib_root, namespace).ok().flatten());
        for (ctx, data) in stored {
            self.serve(ctx.version(), &data);
        }
    }

    fn serve(&self, version: u64, data: &Data) {
        let Some(wire) = group::group_data(&self.node, data) else {
            return;
        };
        self.served
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(version, wire);
    }

    /// Serve `kept` (a version whose anchor key this node holds) and, when
    /// newer than the sequence number announced, advance the sequence
    /// number to it — one publication per step, since SVS advances by one —
    /// so every member fetches it now.
    async fn put(&mut self, kept: &KeptVersion) {
        let data = match Data::decode(kept.data.clone()) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    namespace = %self.namespace,
                    version = kept.version,
                    error = %e,
                    "a kept trust-context version is not a Data packet; not put into the sync group"
                );
                return;
            }
        };
        self.serve(kept.version, &data);
        if kept.version <= self.seq {
            return;
        }
        while self.seq < kept.version {
            let name = self.node.clone().append_segment(self.seq + 1);
            if self.publish.send((name, None)).await.is_err() {
                tracing::warn!(
                    target: "security",
                    namespace = %self.namespace,
                    version = kept.version,
                    "the sync group stopped; the version reaches the members by refresh"
                );
                return;
            }
            self.seq += 1;
        }
        tracing::info!(
            target: "security",
            namespace = %self.namespace,
            version = kept.version,
            member = %self.node,
            "put the trust-context version into the namespace's sync group"
        );
    }
}

/// A local in-process face on `engine`, kept until `cancel`.
fn local_face(engine: &ForwarderEngine, cancel: &CancellationToken) -> (FaceId, InProcHandle) {
    let id = engine.faces().alloc_id();
    let (face, handle) = InProcFace::new(id, FACE_BUFFER);
    engine.add_face_with_persistency(face, cancel.child_token(), FacePersistency::Persistent);
    (id, handle)
}

/// Answer `<node>/seg=<version>` with the group Data served for that
/// version; Nack anything else, so a member walking past a version this
/// node does not hold moves on at once.
fn serve(handle: InProcHandle, node: Name, served: Arc<RwLock<BTreeMap<u64, Bytes>>>) {
    let producer = Producer::from_handle(handle, node.clone());
    tokio::spawn(async move {
        let result = producer
            .serve(|interest, responder| {
                let wire = (interest.name.len() == node.len() + 1)
                    .then(|| interest.name.components().last()?.as_segment())
                    .flatten()
                    .and_then(|seq| {
                        served
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get(&seq)
                            .cloned()
                    });
                async move {
                    let sent = match wire {
                        Some(wire) => responder.respond_bytes(wire).await,
                        None => responder.nack(NackReason::NoRoute).await,
                    };
                    if let Err(e) = sent {
                        tracing::debug!(
                            target: "security",
                            name = %interest.name,
                            error = %e,
                            "trust-context sync reply not sent"
                        );
                    }
                }
            })
            .await;
        if let Err(e) = result {
            tracing::warn!(target: "security", error = %e, "trust-context sync group Data is no longer served");
        }
    });
}

/// The group's route on this node (see the module docs).
struct Routes {
    engine: ForwarderEngine,
    namespace: Name,
    /// `<group>`: the group Data of every member.
    group: Name,
    /// `<group>/v=<dialect>`: the Sync Interests.
    sync: Name,
    /// The group's own sync face, a nexthop of `sync` only.
    own: FaceId,
}

impl Routes {
    /// Route the group's Sync Interests and group Data over `face` too,
    /// where they are not already.
    fn add(&self, face: FaceId) {
        if face == self.own {
            return;
        }
        let fib = self.engine.fib();
        for prefix in [&self.group, &self.sync] {
            let routed = fib
                .lpm_with_depth(prefix)
                .filter(|(depth, _)| *depth == prefix.len())
                .is_some_and(|(_, entry)| entry.nexthops.iter().any(|hop| hop.face_id == face));
            if !routed {
                fib.add_nexthop(prefix, face, MEMBER_COST);
                tracing::debug!(target: "security", prefix = %prefix, face = face.0, "trust-context sync group routed over a face");
            }
        }
    }

    /// Up: the non-local faces the namespace is routed over.
    fn upstream(&self) {
        let Some(entry) = self.engine.fib().lpm(&self.namespace) else {
            return;
        };
        for hop in &entry.nexthops {
            let non_local = self
                .engine
                .faces()
                .get(hop.face_id)
                .is_some_and(|face| face.scope() == FaceScope::NonLocal);
            if non_local {
                self.add(hop.face_id);
            }
        }
    }

    /// Whether `name` is one of the group's Sync Interests
    /// (`<group>/v=<dialect>`, then its parameters digest).
    fn is_sync_interest(&self, name: &Name) -> bool {
        name.has_prefix(&self.sync)
    }
}

/// Carry SVS's packets between it and the sync face: the group's Sync
/// Interests out and in, after routing the group upstream (at once, and again
/// for each Sync Interest either way: SVS suppresses this node's own while its
/// neighbours' keep arriving, so a relay may send none for minutes, and its
/// members' Sync Interests must still reach the root device through it); and
/// in, after routing the group toward the face each arrived on. Nothing
/// else is routed to the face (see the module docs).
fn pump(
    routes: Routes,
    face: Arc<InProcHandle>,
    mut out: mpsc::Receiver<Bytes>,
    into_svs: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
) {
    routes.upstream();
    let routes = Arc::new(routes);
    let (out_face, out_routes) = (Arc::clone(&face), Arc::clone(&routes));
    tokio::spawn(async move {
        while let Some(pkt) = out.recv().await {
            out_routes.upstream();
            if out_face.send(pkt).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        loop {
            let pkt = tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = face.recv() => match pkt {
                    Some(pkt) => pkt,
                    None => break,
                },
            };
            let Ok(interest) = Interest::decode(pkt.clone()) else {
                continue;
            };
            if !routes.is_sync_interest(&interest.name) {
                continue;
            }
            if let Some(from) = routes.engine.source_face_id(&interest) {
                routes.add(from);
            }
            routes.upstream();
            if into_svs.send(pkt).await.is_err() {
                break;
            }
        }
    });
}

/// Fetches group Data through this node's forwarder, like any app.
struct EngineFetcher(tokio::sync::Mutex<Consumer>);

#[async_trait::async_trait]
impl ContextFetcher for EngineFetcher {
    async fn fetch_content(&self, name: Name) -> Result<Bytes, String> {
        let data = self.0.lock().await.fetch(name).await.map_err(|e| e.to_string())?;
        data.content().cloned().ok_or_else(|| "the Data carries no Content".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_cert::RootStore;
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_security::{Ed25519Signer, FilePib, Keyring, SecurityManager, Signer};
    use ndn_transport::FaceKind;

    use super::*;

    /// A non-local face on each engine, pumped to the other.
    fn link(a: &ForwarderEngine, b: &ForwarderEngine, cancel: &CancellationToken) -> FaceId {
        let face = |e: &ForwarderEngine| {
            let id = e.faces().alloc_id();
            let (face, handle) = InProcFace::new_kind(id, FACE_BUFFER, FaceKind::Udp);
            e.add_face(face, cancel.child_token());
            (id, Arc::new(handle))
        };
        let ((_, a), (b_id, b)) = (face(a), face(b));
        let pump = |from: Arc<InProcHandle>, to: Arc<InProcHandle>| {
            tokio::spawn(async move {
                while let Some(pkt) = from.recv().await {
                    if to.send(pkt).await.is_err() {
                        break;
                    }
                }
            })
        };
        pump(Arc::clone(&a), Arc::clone(&b));
        pump(b, a);
        b_id
    }

    async fn engine() -> (ForwarderEngine, ShutdownHandle) {
        EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .build()
            .await
            .unwrap()
    }

    /// A node with PIB `pib_root`, holding `keyring`, in its namespaces'
    /// sync groups (no refresh runs).
    fn node(
        engine: &ForwarderEngine,
        keyring: Keyring,
        pib_root: &Path,
        cancel: &CancellationToken,
    ) -> Arc<TrustAdmin> {
        node_with(engine, keyring, pib_root, cancel, quick())
    }

    fn node_with(
        engine: &ForwarderEngine,
        keyring: Keyring,
        pib_root: &Path,
        cancel: &CancellationToken,
        svs: SvsConfig,
    ) -> Arc<TrustAdmin> {
        let (sync, mut groups) = prepare(true, pib_root).unwrap();
        groups.svs = svs;
        let admin = Arc::new(TrustAdmin {
            engine: engine.clone(),
            keyring: Arc::new(keyring),
            pib_root: pib_root.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            ca: None,
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
            context_sync: Some(sync),
        });
        groups.spawn(Arc::clone(&admin), cancel.child_token());
        admin
    }

    /// Sync Interests every few hundred ms, so the group forms quickly.
    fn quick() -> SvsConfig {
        SvsConfig {
            sync_interval: Duration::from_millis(300),
            jitter_ms: 50,
            suppression_period: Duration::from_millis(50),
            ..SvsConfig::wan()
        }
    }

    async fn holds(keyring: &Keyring, ns: &Name, version: u64) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while keyring.version_of(ns) != Some(version) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("v{version} did not arrive over sync; holds {:?}", keyring.version_of(ns))
        });
    }

    /// A device that never refreshes adopts the root device's revocation
    /// pushed over the namespace's sync group, and stores it byte for byte;
    /// a version a stranger signed, announced in the same group, is refused:
    /// the root's next version is still adopted over it.
    #[tokio::test]
    async fn a_revocation_pushed_over_sync_is_adopted_and_a_forged_version_refused() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev.path()).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let root_signer = RootStore::open(&pib).unwrap().unwrap().signer(None).await.unwrap();
        let v1 = &init.init.context_data;
        // The version after `base` revoking `revoked`, signed by the root key.
        let next = |base: &Data, revoked: &str| {
            let n = base.name.components().last().unwrap().as_version().unwrap() + 1;
            let ctx = SignedTrustContext::decode_content(base.content().unwrap(), n)
                .unwrap()
                .with_revocation(revoked.parse().unwrap());
            let signer = Arc::clone(&root_signer);
            async move { ctx.sign_into_data_async(signer.as_ref()).await.unwrap() }
        };

        let cancel = CancellationToken::new();
        let ((root_engine, root_down), (dev_engine, dev_down)) = (engine().await, engine().await);
        let up = link(&root_engine, &dev_engine, &cancel);
        // The device's route toward the root device; none the other way.
        dev_engine.fib().add_nexthop(&ns, up, 10);

        let root_keyring = Keyring::new();
        ndn_cert::load_persisted_contexts(root_dev.path(), &root_keyring).unwrap();
        let root = node(&root_engine, root_keyring, root_dev.path(), &cancel);
        let dev_keyring = Keyring::new();
        ndn_cert::adopt_with_tofu(&dev_keyring, v1, &ns, &ndn_cert::anchor_fingerprint(&init.init.anchor))
            .unwrap();
        let dev = node(&dev_engine, dev_keyring, device.path(), &cancel);

        // The root device revokes a key (the version `ndn-fwd revoke` hands
        // its daemon).
        let v2 = next(v1, "/home/bob/member/phone/KEY/k1").await;
        crate::context_refresh::apply_update(&root, v2.raw().clone()).await.unwrap();
        holds(&dev.keyring, &ns, 2).await;
        let (_, stored) = ndn_cert::read_stored_context(device.path(), &ns).unwrap().unwrap();
        assert_eq!(stored.raw(), v2.raw());

        // Another member announces v3, signed by a stranger listing itself
        // as an anchor.
        let stranger: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[5; 32],
            "/home/bob/KEY/stranger".parse().unwrap(),
        ));
        let forged = SignedTrustContext::decode_content(v1.content().unwrap(), 3).unwrap();
        forged.add_anchor(ndn_cert::recovery_anchor(Arc::clone(&stranger)).await.unwrap());
        let forged = forged.sign_into_data_async(stranger.as_ref()).await.unwrap();
        let prefix = group::group_prefix(&ns);
        let rogue = prefix.clone().append_component(NameComponent::generic(Bytes::from_static(b"rogue")));
        let (serve_id, serve_face) = local_face(&root_engine, &cancel);
        root_engine.fib().add_nexthop(&rogue, serve_id, 0);
        let fetched = Arc::new(tokio::sync::Notify::new());
        let wire = group::group_data(&rogue, &forged).unwrap();
        let producer = Producer::from_handle(serve_face, rogue.clone());
        let served = Arc::clone(&fetched);
        tokio::spawn(async move {
            let _ = producer
                .serve(|_, responder| {
                    let (wire, served) = (wire.clone(), Arc::clone(&served));
                    async move {
                        let _ = responder.respond_bytes(wire).await;
                        served.notify_one();
                    }
                })
                .await;
        });
        let (sync_id, sync_face) = local_face(&root_engine, &cancel);
        root_engine.fib().add_nexthop(&prefix, sync_id, 0);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(16);
        let (_in_tx, in_rx) = mpsc::channel(16);
        let rogue_handle = join_svs_group(
            prefix.clone(),
            rogue.clone(),
            out_tx,
            in_rx,
            SvsConfig {
                local_seq: 2,
                ..quick()
            },
        );
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                let _ = sync_face.send(pkt).await;
            }
        });
        rogue_handle.tx.send((rogue.clone().append_segment(3), None)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), fetched.notified())
            .await
            .expect("the device never fetched the forged version");

        // Fetched and checked before the root device's v3 is announced: had
        // it been adopted, the root's v3 would be refused as not newer.
        let v3 = next(&v2, "/home/bob/member/tablet/KEY/k2").await;
        crate::context_refresh::apply_update(&root, v3.raw().clone()).await.unwrap();
        holds(&dev.keyring, &ns, 3).await;
        let (_, stored) = ndn_cert::read_stored_context(device.path(), &ns).unwrap().unwrap();
        assert_eq!(stored.raw(), v3.raw());

        cancel.cancel();
        drop(rogue_handle);
        root_down.shutdown().await;
        dev_down.shutdown().await;
    }

    /// The group is routed upstream from the moment it is joined, and again
    /// for each Sync Interest received, not only before one of this node's
    /// own: SVS resets that timer whenever a neighbour's Sync Interest covers
    /// the local state, so a relay between the root device and its devices
    /// may send none for minutes. Seen in the end-to-end harness
    /// (ndn-fwd/testbed/e2e, `lifecycle-push`): such a relay never routed the
    /// group toward the root device, the root device's announcement of a
    /// revocation went nowhere, and the devices behind the relay never got it.
    #[tokio::test]
    async fn the_group_is_routed_upstream_without_a_sync_interest_of_its_own() {
        let (root_dev, relay) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev.path()).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();

        let cancel = CancellationToken::new();
        let (engine, down) = engine().await;
        let non_local_face = |engine: &ForwarderEngine| {
            let id = engine.faces().alloc_id();
            let (face, handle) = InProcFace::new_kind(id, FACE_BUFFER, FaceKind::Udp);
            engine.add_face(face, cancel.child_token());
            (id, handle)
        };
        // The relay's route toward the root device.
        let (up, _up) = non_local_face(&engine);
        engine.fib().add_nexthop(&ns, up, 10);

        let keyring = Keyring::new();
        ndn_cert::adopt_with_tofu(
            &keyring,
            &init.init.context_data,
            &ns,
            &ndn_cert::anchor_fingerprint(&init.init.anchor),
        )
        .unwrap();
        // Its own Sync Interests would go out once an hour at the earliest.
        let quiet = SvsConfig {
            sync_interval: Duration::from_secs(3600),
            ..quick()
        };
        let _relay = node_with(&engine, keyring, relay.path(), &cancel, quiet);

        let prefix = group::group_prefix(&ns);
        let routed_over = |face: FaceId| {
            let (engine, prefix) = (engine.clone(), prefix.clone());
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !engine
                        .fib()
                        .lpm_with_depth(&prefix)
                        .filter(|(depth, _)| *depth == prefix.len())
                        .is_some_and(|(_, e)| e.nexthops.iter().any(|hop| hop.face_id == face))
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .is_ok()
            }
        };
        assert!(
            routed_over(up).await,
            "the group must be routed toward the root device once joined"
        );

        // A route toward the namespace added later is taken when a member's
        // Sync Interest arrives.
        let (up2, _up2) = non_local_face(&engine);
        engine.fib().add_nexthop(&ns, up2, 10);
        let (_, member) = non_local_face(&engine);
        let sync = ndn_packet::encode::InterestBuilder::new(
            prefix.clone().append_version(quick().dialect.sync_version()),
        )
        .build();
        member.send(sync).await.unwrap();
        assert!(
            routed_over(up2).await,
            "a member's Sync Interest must take the namespace's routes up again"
        );

        cancel.cancel();
        down.shutdown().await;
    }

    /// A neighbour's fetch of a member's group Data, arriving here, must not
    /// be routed to this node's own sync face, which passes only Sync
    /// Interests to SVS: multicast there alone (the face it came from
    /// excluded), it went nowhere, and this node's own fetch of the same
    /// version, aggregated onto that PIT entry, timed out. Seen in the
    /// end-to-end harness (ndn-fwd/testbed/e2e, `lifecycle-push`): a relay
    /// multicast its fetch of the root device's revocation to a device just
    /// before the device fetched it, and the device never adopted it. Here
    /// the device's own fetch must reach the upstream that leads to the
    /// publisher, and be answered.
    #[tokio::test]
    async fn a_neighbours_fetch_of_group_data_does_not_hold_up_this_nodes_own() {
        let (root_dev, tab) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev.path()).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();

        let cancel = CancellationToken::new();
        let (engine, down) = engine().await;
        // The device's only link: toward the relay, which leads to the root
        // device.
        let up = engine.faces().alloc_id();
        let (face, relay) = InProcFace::new_kind(up, FACE_BUFFER, FaceKind::Udp);
        engine.add_face(face, cancel.child_token());
        engine.fib().add_nexthop(&ns, up, 10);
        let keyring = Keyring::new();
        ndn_cert::adopt_with_tofu(
            &keyring,
            &init.init.context_data,
            &ns,
            &ndn_cert::anchor_fingerprint(&init.init.anchor),
        )
        .unwrap();
        // Its own Sync Interests would go out once an hour at the earliest.
        let quiet = SvsConfig {
            sync_interval: Duration::from_secs(3600),
            ..quick()
        };
        let _tab = node_with(&engine, keyring, tab.path(), &cancel, quiet);

        let publisher = group::group_prefix(&ns)
            .append_component(NameComponent::generic(Bytes::from_static(b"desk")));
        // The group Data of the version the root device holds, v1.
        let wanted = publisher.clone().append_segment(1);
        let prefix = group::group_prefix(&ns);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !engine
                .fib()
                .lpm_with_depth(&prefix)
                .filter(|(depth, _)| *depth == prefix.len())
                .is_some_and(|(_, e)| e.nexthops.iter().any(|hop| hop.face_id == up))
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the device never joined the group");

        // The relay's own fetch, multicast to the device, and the device's
        // own right after it (within the PIT's 10 ms retransmission window,
        // as in the harness: aggregated onto the relay's, not sent again).
        let from_relay = ndn_packet::encode::InterestBuilder::new(wanted.clone())
            .lifetime(Duration::from_secs(4))
            .build();
        let fetcher = EngineFetcher(tokio::sync::Mutex::new(engine.app_consumer(cancel.child_token())));
        relay.send(from_relay).await.unwrap();
        let fetch = {
            let wanted = wanted.clone();
            tokio::spawn(async move { fetcher.fetch_content(wanted).await })
        };
        let reached = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pkt = relay.recv().await.expect("the device's link closed");
                // An Interest sent on, not the Nack of the relay's own.
                let interest = match ndn_packet::lp::LpPacket::decode(pkt.clone()) {
                    Ok(lp) if lp.nack.is_none() => lp.fragment.map(Interest::decode),
                    Ok(_) => None,
                    Err(_) => Some(Interest::decode(pkt)),
                };
                if interest.is_some_and(|i| i.is_ok_and(|i| *i.name == wanted)) {
                    break;
                }
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "the device's fetch of the group Data never went toward the publisher"
        );
        let data = group::group_data(&publisher, &init.init.context_data).unwrap();
        relay.send(data).await.unwrap();
        let content = fetch.await.unwrap().expect("the device's fetch was not answered");
        assert_eq!(&content, init.init.context_data.raw());

        cancel.cancel();
        down.shutdown().await;
    }
}
