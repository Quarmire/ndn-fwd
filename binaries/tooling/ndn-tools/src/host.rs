//! What the host does on a daemon for the data layer: follow the trust
//! contexts the daemon adopts, adopt another person's anchor through it
//! ([`DaemonHost`], the `ndn_invite::Host` of the introductions and the
//! `ndn_heap::Adopter` of the data layer) and carry names in transit on it
//! ([`Marks`]).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;

use ndn_app::{Connection, Consumer};
use ndn_cert::report::TrustEvent;
use ndn_heap::{Adopter, Scoping};
use ndn_invite::{Adopting, Host};
use ndn_ipc::MgmtClient;
use ndn_ipc::events::{EventSubscription, Notice};
use ndn_packet::Name;
use ndn_security::{Keyring, ScopedContext};
use ndn_trust_envelope::TrustEnvelope;

/// How long one long-poll of the daemon's trust stream waits for an event.
const TRUST_POLL: Duration = Duration::from_secs(30);
/// How long before subscribing to the trust stream again after it failed
/// (a reconnect backoff: while subscribed, the host only waits for events).
const TRUST_RETRY: Duration = Duration::from_secs(3);

/// Follow the trust-context versions the daemon at `face_socket` adopts —
/// pulled, pushed, or signed there by `ndn-fwd revoke`/`readmit` — from its
/// trust stream (`/localhost/nfd/security/notifications`): each
/// `context-updated` event makes the host adopt the version the daemon
/// stored in the PIB at `pib_root` into `keyring`, and the data layer
/// re-checks what it holds on each adoption. A resync (the first notice,
/// and whenever the host fell behind the stream or the daemon restarted)
/// adopts every stored version newer than the held one, so a version told
/// of meanwhile is not missed. Re-adopting a held version changes nothing;
/// an older one is refused by the keyring (no rollback).
pub async fn follow_contexts(face_socket: String, pib_root: PathBuf, keyring: Arc<Keyring>) {
    loop {
        let mut trust = match EventSubscription::<TrustEvent>::connect(&face_socket).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    socket = %face_socket,
                    "the daemon's trust stream is not reachable: {e}; trust-context versions it \
                     adopts are not followed until it is (subscribing again)"
                );
                tokio::time::sleep(TRUST_RETRY).await;
                continue;
            }
        };
        loop {
            match trust.next(TRUST_POLL).await {
                Ok(None) => {}
                Ok(Some(Notice::Resync { .. })) => adopt_stored(&pib_root, &keyring),
                Ok(Some(Notice::Event {
                    event:
                        TrustEvent::ContextUpdated {
                            namespace, version, ..
                        },
                    ..
                })) => adopt_told(&pib_root, &keyring, &namespace, version),
                Ok(Some(Notice::Event { .. })) => {}
                Err(e) => {
                    tracing::warn!(
                        socket = %face_socket,
                        "the daemon's trust stream failed: {e}; subscribing again (a resync \
                         adopts what was stored meanwhile)"
                    );
                    tokio::time::sleep(TRUST_RETRY).await;
                    break;
                }
            }
        }
    }
}

/// Adopt every trust context stored in the PIB at `pib_root` that is newer
/// than the one `keyring` holds of its namespace — a held namespace only by
/// the continuity rule ([`ndn_cert::adopt_stored_context`]).
pub fn adopt_stored(pib_root: &Path, keyring: &Keyring) {
    match ndn_cert::load_persisted_contexts(pib_root, keyring) {
        Ok(read) => {
            for (path, result) in read {
                if let Err(e) = result {
                    tracing::debug!(path = %path.display(), "stored trust context not adopted: {e}");
                }
            }
        }
        Err(e) => tracing::warn!(
            pib = %pib_root.display(),
            "trust contexts not read: {e}; newer versions the daemon stores are adopted at the \
             next one it tells of once the PIB is readable again"
        ),
    }
}

/// Adopt version `version` of `namespace`, which the daemon told of: the
/// daemon stores a version in the PIB at `pib_root` before it tells of it,
/// so the stored file holds it (or a newer one). When it does not — the
/// daemon could not store it — nothing is adopted now: the next version the
/// daemon stores and tells of, or the next resync, brings the host up to
/// date.
pub fn adopt_told(pib_root: &Path, keyring: &Keyring, namespace: &str, version: u64) {
    let ns: Name = match namespace.parse() {
        Ok(ns) => ns,
        Err(e) => {
            tracing::warn!(
                namespace,
                "the daemon told of a namespace that is no name: {e}"
            );
            return;
        }
    };
    if keyring.version_of(&ns).is_some_and(|held| held >= version) {
        return;
    }
    match ndn_cert::read_stored_context(pib_root, &ns) {
        Ok(Some((ctx, data))) if ctx.version() >= version => {
            let stored = ctx.version();
            if let Err(e) = ndn_cert::adopt_stored_context(pib_root, keyring, ctx, &data) {
                tracing::warn!(
                    %ns,
                    stored,
                    held = ?keyring.version_of(&ns),
                    "stored trust context not adopted: {e}; this host keeps the version it holds"
                );
            }
        }
        Ok(stored) => tracing::warn!(
            %ns,
            version,
            stored = ?stored.map(|(ctx, _)| ctx.version()),
            pib = %pib_root.display(),
            "the daemon told of this version but the PIB does not hold it (the daemon could \
             not store it: see its log); not adopted now — the next version it stores, or the \
             next resync, brings this host up to date"
        ),
        Err(e) => tracing::warn!(
            %ns,
            version,
            pib = %pib_root.display(),
            "the stored trust context is not readable: {e}; not adopted now — the next \
             version the daemon stores, or the next resync, brings this host up to date"
        ),
    }
}

/// How long the daemon may take to adopt an anchor link: an inline context
/// of another kind of namespace needs no fetch, but a self-certifying
/// namespace not held is adopted by name — version 1, the newest's name and
/// the newest, then a walk of at most `ndn_cert::MAX_CATCH_UP_TIME` (40 s)
/// when versions lie in between; the link's inline context is never taken
/// alone.
const ADOPT_LIMIT: Duration = Duration::from_secs(60);

/// The daemon's transit marks, as the host asks for them
/// (`security/transit`, owned by the connection that asks).
#[async_trait::async_trait]
pub trait Marks: Send + Sync {
    /// Ask the daemon to carry `name` in transit (`carry`: one mark more,
    /// owned by this connection) or to take one mark back.
    async fn mark(&self, name: &Name, carry: bool) -> Result<(), String>;
}

/// [`Marks`] over one management connection the host holds for its whole
/// run: when the host ends — crashed or not — the daemon releases whatever
/// it still holds.
pub struct DaemonMarks(pub MgmtClient);

#[async_trait::async_trait]
impl Marks for DaemonMarks {
    async fn mark(&self, namespace: &Name, carry: bool) -> Result<(), String> {
        let what = if carry { "carry" } else { "stop carrying" };
        self.0
            .security_transit(namespace, carry)
            .await
            .map(|_| ())
            .map_err(|e| match ndn_ipc::trust_refusal_in(&e) {
                Some(refusal) if refusal.is(ndn_cert::report::code::TRANSIT_NOT_PERMITTED) => {
                    format!(
                        "the daemon refused to {what} {namespace} in transit: {refusal} (run \
                         this host as a member of a group in the daemon's `[security] \
                         transit_groups`, which may carry namespaces in transit and change \
                         nothing else of its trust, then start it again)"
                    )
                }
                Some(refusal) => {
                    format!("the daemon refused to {what} {namespace} in transit: {refusal}")
                }
                None => format!(
                    "asking the daemon to {what} {namespace} in transit: {e}; if the daemon \
                     restarted, start this host again (the daemon released this host's marks \
                     with its connection)"
                ),
            })
    }
}

/// An introduction's two prefixes, `introduction_prefixes(inviter)`
/// (`<D>/32=intro`, `<D>/32=hint`), carried in transit on the daemon for the
/// length of one join (invite.md §12.1): the offer and the hint record are
/// signed by a namespace the joiner's daemon does not hold until the join
/// ends, so it forwards Data under them unvalidated, to the pending Interests
/// only and uncached; the layer verifies every packet itself.
///
/// [`end`](Self::end) takes the marks back and waits for the daemon's answer;
/// a join that is dropped before it (its future cancelled) takes them back
/// from the runtime in the background, so a mark is never left behind but by
/// a host that ends — and the daemon releases those with its connection.
pub struct IntroTransit {
    marks: Arc<dyn Marks>,
    held: Vec<Name>,
}

impl IntroTransit {
    /// Take every mark back, whichever way the join went.
    pub async fn end(mut self) {
        for prefix in std::mem::take(&mut self.held) {
            if let Err(why) = self.marks.mark(&prefix, false).await {
                tracing::warn!(
                    %prefix,
                    "{why}; the daemon keeps carrying it in transit until this host ends"
                );
            }
        }
    }
}

impl Drop for IntroTransit {
    fn drop(&mut self) {
        if self.held.is_empty() {
            return;
        }
        let (marks, held) = (Arc::clone(&self.marks), std::mem::take(&mut self.held));
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                prefixes = ?held.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "released with no runtime to tell the daemon on: its marks stay until this host \
                 ends"
            );
            return;
        };
        runtime.spawn(async move {
            for prefix in held {
                if let Err(why) = marks.mark(&prefix, false).await {
                    tracing::warn!(
                        %prefix,
                        "{why}; the daemon keeps carrying it in transit until this host ends"
                    );
                }
            }
        });
    }
}

/// Carry `ndn_invite::introduction_prefixes(inviter)` in transit over
/// `marks`: both prefixes, or none (one that is refused takes the other back
/// and says why).
pub async fn carry_introduction(
    marks: &Arc<dyn Marks>,
    inviter: &Name,
) -> Result<IntroTransit, String> {
    let mut transit = IntroTransit {
        marks: Arc::clone(marks),
        held: Vec::new(),
    };
    for prefix in ndn_invite::introduction_prefixes(inviter) {
        if let Err(why) = marks.mark(&prefix, true).await {
            transit.end().await;
            return Err(why);
        }
        transit.held.push(prefix);
    }
    Ok(transit)
}

/// Run `join`, a join of the inviter's code, with the inviter's introduction
/// prefixes carried in transit meanwhile ([`carry_introduction`]) and taken
/// back whatever way it ends: it returns, or it is dropped (cancelled)
/// before it does.
pub async fn carrying_introduction<T>(
    marks: &Arc<dyn Marks>,
    inviter: &Name,
    join: impl Future<Output = T>,
) -> Result<T, String> {
    let transit = carry_introduction(marks, inviter).await?;
    let joined = join.await;
    transit.end().await;
    Ok(joined)
}

/// The data layer's and the introductions' host on a daemon: this device's
/// anchor is its namespace's trust context as the daemon stored it in the
/// PIB; another person's anchor link is adopted by the daemon
/// (`security/context-adopt`, as `ndn-ctl adopt` asks), which validates and
/// stores it and routes the namespace over its relay links — a
/// self-certifying namespace not held by name over the network, the link's
/// version 1 only compared with the fetched one (a different one refused as
/// a fork), never offline — and then by this host's keyring from the PIB, so
/// the layer's validator trusts it before `adopt` answers.
///
/// A host with no link layer of its own: it dials nothing, holds no grants
/// and no departure marks (the defaults of [`Host`]: a join reaches the
/// inviter by the relays its code names, else by name; an offer admits a
/// person by the space's members alone). The introduction's own transit is
/// the host's `join` verb's ([`carry_introduction`]).
///
/// A writer's self-certifying namespace that a space's members list, which
/// the daemon does not hold, is adopted for the layer alone
/// (`adopt_scoped`, heap.md §6): the daemon is asked to carry it in transit
/// first (`security/transit`, one mark) unless this host has it carried
/// already — whether the layer adopts it anew or refreshes from a version it
/// held, one it kept across a restart included — since the daemon refuses
/// that namespace's Data as one not held, the adoption's own fetches of its
/// trust-context versions included; then the versions are fetched over this
/// host's own connection and checked here (`ndn_cert::adopt_scoped`), into no
/// keyring. A mark this adoption took is taken back if it fails, and the one
/// mark of a namespace when the layer releases it (`release_scoped`);
/// releasing one not carried does nothing. Every mark is asked over
/// [`marks`](Self::marks), the connection that owns it.
pub struct DaemonHost {
    pub face_socket: String,
    pub pib_root: PathBuf,
    /// This device's namespace (empty: none governs its name).
    pub namespace: Name,
    pub keyring: Arc<Keyring>,
    /// This host's own connection to the daemon, which a namespace adopted
    /// for a space is fetched over.
    pub connection: Arc<dyn Connection>,
    /// The transit marks, asked over the connection that owns them, open
    /// for the host's whole run.
    pub marks: Arc<dyn Marks>,
    /// The namespaces this host has the daemon carry in transit for the
    /// layer: one mark each.
    pub carried: Mutex<HashSet<Name>>,
}

impl DaemonHost {
    /// Whether the keyring holds `namespace` at `version` or newer, rooted
    /// in the anchor of `fingerprint`.
    fn holds(&self, namespace: &Name, fingerprint: &[u8; 32], version: u64) -> bool {
        let ctx = self.keyring.context_for(namespace);
        ctx.namespace() == namespace
            && ctx.version() >= version
            && ctx
                .anchors()
                .iter()
                .any(|a| ndn_security::anchor_fingerprint(a.value()) == *fingerprint)
    }

    async fn adopt_link(&self, link: &TrustEnvelope) -> Result<(), String> {
        let TrustEnvelope::Anchor {
            namespace: Some(namespace),
            fingerprint: Some(fingerprint),
            version,
            ..
        } = link
        else {
            return Err("not an anchor link naming its namespace and fingerprint".into());
        };
        let ns: Name = namespace
            .parse()
            .map_err(|e| format!("the anchor link's namespace {namespace:?} is no name: {e}"))?;
        let version = version.unwrap_or(0);
        // Asked again (the same key asks again after a lost answer): held.
        if self.holds(&ns, fingerprint, version) {
            return Ok(());
        }
        let client = MgmtClient::connect(&self.face_socket).await.map_err(|e| {
            format!(
                "the daemon at {} is not reachable to adopt {ns}: {e}",
                self.face_socket
            )
        })?;
        let resp = client
            .security_context_adopt(&link.to_uri(), ADOPT_LIMIT)
            .await
            .map_err(|e| format!("asking the daemon to adopt {ns}: {e}"))?;
        if !resp.is_ok() {
            return Err(match ndn_ipc::trust_refusal(&resp) {
                Some(refusal) => format!("the daemon refused to adopt {ns}: {refusal}"),
                None => format!(
                    "the daemon refused to adopt {ns} ({}): {}",
                    resp.status_code, resp.status_text
                ),
            });
        }
        let info: ndn_cert::report::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
            .map_err(|e| {
                format!(
                    "unreadable answer from the daemon ({e}): {}",
                    resp.status_text
                )
            })?;
        adopt_told(&self.pib_root, &self.keyring, &info.namespace, info.version);
        if self.holds(&ns, fingerprint, version) {
            Ok(())
        } else {
            Err(format!(
                "the daemon adopted {ns} v{}, but the PIB at {} gives this host no such version to \
                 adopt: check the PIB is the daemon's",
                info.version,
                self.pib_root.display()
            ))
        }
    }

    /// Adopt `namespace` for the layer alone, refreshed from `held` when the
    /// layer holds a version already; carried in transit once, whichever.
    async fn adopt_for_spaces(
        &self,
        namespace: &Name,
        held: Option<&ScopedContext>,
    ) -> Result<ScopedContext, String> {
        let newly = self
            .carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(namespace.clone());
        if newly && let Err(why) = self.marks.mark(namespace, true).await {
            self.carried
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(namespace);
            return Err(why);
        }
        let mut exchange = HostExchange(Consumer::new(Arc::clone(&self.connection)));
        match ndn_cert::adopt_scoped(None, &mut exchange, namespace, held).await {
            Ok(scoped) => Ok(scoped),
            Err(e) => {
                if newly {
                    self.carried
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(namespace);
                    if let Err(why) = self.marks.mark(namespace, false).await {
                        tracing::warn!(%namespace, "{why}");
                    }
                }
                Err(format!(
                    "adopting {namespace} by name for the spaces that list it as a writer \
                     failed: {e}; its entries there wait, and it is asked again (reach its \
                     devices, through a route to {namespace} on this device's daemon, for it to \
                     succeed)"
                ))
            }
        }
    }
}

/// Fetches over this host's own connection to the daemon, for an adoption
/// by name: each Interest asked once (the layer asks the adoption again).
struct HostExchange(Consumer);

impl ndn_cert::CaExchange for HostExchange {
    async fn express(&mut self, interest: Bytes) -> Result<ndn_packet::Data, ndn_cert::CertError> {
        self.0
            .fetch_wire(interest, ndn_app::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| ndn_cert::CertError::Transport(e.to_string()))
    }
}

impl Host for DaemonHost {
    fn anchor(&self) -> Option<Bytes> {
        if self.namespace.is_empty() {
            return None;
        }
        match ndn_cert::read_stored_context(&self.pib_root, &self.namespace) {
            Ok(Some((_, data))) => Some(data.raw().clone()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    namespace = %self.namespace,
                    "this device's trust context is not readable from the PIB: {e}"
                );
                None
            }
        }
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(self.adopt_link(link))
    }
}

impl Adopter for DaemonHost {
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        Box::pin(self.adopt_for_spaces(namespace, held))
    }

    fn release_scoped(&self, namespace: &Name) {
        if !self
            .carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(namespace)
        {
            return;
        }
        let (marks, namespace) = (Arc::clone(&self.marks), namespace.clone());
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                %namespace,
                "released with no runtime to tell the daemon on: its mark stays until this host \
                 ends"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(why) = marks.mark(&namespace, false).await {
                tracing::warn!(
                    %namespace,
                    "{why}; the daemon keeps carrying it in transit until this host ends"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The daemon's marks, recorded; `refuse` names the one it refuses to
    /// carry.
    #[derive(Default)]
    struct FakeMarks {
        asked: Mutex<Vec<(Name, bool)>>,
        refuse: Option<Name>,
    }

    impl FakeMarks {
        fn asked(&self) -> Vec<(Name, bool)> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Marks for FakeMarks {
        async fn mark(&self, name: &Name, carry: bool) -> Result<(), String> {
            if carry && self.refuse.as_ref() == Some(name) {
                return Err(format!("the daemon refused to carry {name}"));
            }
            self.asked.lock().unwrap().push((name.clone(), carry));
            Ok(())
        }
    }

    fn n(s: &str) -> Name {
        s.parse().expect("a name")
    }

    /// The inviter's introduction prefixes, exactly, are carried from the
    /// start of a join and taken back when it ends: the offer and the hint
    /// record are signed by a namespace the joiner's daemon does not hold
    /// (invite.md §12.1), and a host that carries nothing fails the join at
    /// the offer fetch.
    #[tokio::test]
    async fn the_inviters_introduction_prefixes_are_carried_until_the_join_ends() {
        let inviter = n("/alice/member/laptop");
        let fake = Arc::new(FakeMarks::default());
        let marks: Arc<dyn Marks> = fake.clone();

        let transit = carry_introduction(&marks, &inviter).await.expect("carried");
        let prefixes = ndn_invite::introduction_prefixes(&inviter);
        assert_eq!(transit.held, prefixes);
        assert_eq!(
            fake.asked(),
            prefixes
                .iter()
                .map(|p| (p.clone(), true))
                .collect::<Vec<_>>(),
            "exactly the two introduction prefixes of the inviter are marked, and nothing else \
             of it"
        );

        transit.end().await;
        let mut taken_back = fake.asked();
        taken_back.drain(..2);
        assert_eq!(
            taken_back,
            prefixes
                .iter()
                .map(|p| (p.clone(), false))
                .collect::<Vec<_>>(),
            "every mark is taken back"
        );
    }

    /// A prefix the daemon refuses leaves nothing carried: the one it took
    /// is taken back, and the refusal's words are the error.
    #[tokio::test]
    async fn a_refused_prefix_leaves_no_mark_behind() {
        let inviter = n("/alice/member/laptop");
        let [intro, hint] = ndn_invite::introduction_prefixes(&inviter);
        let fake = Arc::new(FakeMarks {
            refuse: Some(hint.clone()),
            ..FakeMarks::default()
        });
        let marks: Arc<dyn Marks> = fake.clone();

        let why = carry_introduction(&marks, &inviter)
            .await
            .map(|_| ())
            .expect_err("the daemon refused one");
        assert!(why.contains(&hint.to_string()), "{why}");
        assert_eq!(fake.asked(), vec![(intro.clone(), true), (intro, false)]);
    }

    /// The marks are held while the join runs, whatever it answers, and taken
    /// back when it returns: what the daemon sees is exactly the inviter's
    /// two prefixes for the length of the join.
    #[tokio::test]
    async fn the_marks_are_held_for_the_length_of_the_join() {
        let inviter = n("/alice/member/laptop");
        let prefixes = ndn_invite::introduction_prefixes(&inviter);
        let fake = Arc::new(FakeMarks::default());
        let marks: Arc<dyn Marks> = fake.clone();

        let seen = carrying_introduction(&marks, &inviter, async { fake.asked() })
            .await
            .expect("carried");
        assert_eq!(
            seen,
            prefixes
                .iter()
                .map(|p| (p.clone(), true))
                .collect::<Vec<_>>(),
            "the join runs with both prefixes carried"
        );
        assert_eq!(fake.asked().len(), 4, "and they are taken back after it");

        let refused = Arc::new(FakeMarks {
            refuse: Some(prefixes[0].clone()),
            ..FakeMarks::default()
        });
        let marks: Arc<dyn Marks> = refused.clone();
        let joined = carrying_introduction(&marks, &inviter, async { 1 }).await;
        assert!(
            joined.is_err(),
            "a join is not started when the daemon refuses its marks"
        );
        assert!(refused.asked().is_empty());
    }

    /// A join that is dropped (cancelled) before it ended takes its marks
    /// back from the runtime: none outlives it but with a host that ends.
    #[tokio::test]
    async fn a_cancelled_join_takes_its_marks_back() {
        let inviter = n("/alice/member/laptop");
        let fake = Arc::new(FakeMarks::default());
        let marks: Arc<dyn Marks> = fake.clone();
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            carrying_introduction(&marks, &inviter, std::future::pending::<()>()),
        )
        .await;
        assert!(cancelled.is_err(), "the join never ends: it timed out");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while fake.asked().iter().filter(|(_, carry)| !carry).count() != 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the marks were not taken back: {:?}",
                fake.asked()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
