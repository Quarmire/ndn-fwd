//! The identities the running daemon signs as.
//!
//! - **The node identity**: the key of the daemon's own packets —
//!   management responses, discovery records, its QUIC link key — chosen at
//!   startup ([`ndn_cert::choose_node_identity`]) and changed only by an
//!   operator (`[security] identity`, `ndn-fwd node-identity`), or when a
//!   daemon without any persistent identity enrolls its first one. Those
//!   subsystems share one [`ActiveSigner`] and take one snapshot of it per
//!   packet, so a change applies from the next packet on and every packet's
//!   KeyLocator names the key that signed it. (DV routing with
//!   `static`/`lvs` trust takes a fixed copy of the startup key instead: its
//!   neighbours trust only the keys they list.)
//! - **The signing identities**: every identity the engine's
//!   [`SecurityManager`] holds — one per trusted prefix the daemon is a
//!   member of; Data is signed with the key its name chooses
//!   ([`SecurityManager::signer_for`]). An enrollment adds one.
//!
//! [`changes`](ActiveIdentity::changes) bumps whenever a signing identity is
//! added or removed or the node key changes, so a subsystem that presents
//! the daemon's identities (QUIC links' memberships) presents them again.

use std::sync::Arc;

use ndn_cert::NodeIdentitySource;
use ndn_packet::Name;
use ndn_security::{ActiveSigner, SecurityManager, Signer, SigningIdentity};

pub(crate) struct ActiveIdentity {
    /// The node signer.
    signer: Arc<ActiveSigner>,
    /// The engine's key store: the signing identities.
    security: Arc<SecurityManager>,
    /// The startup key when it is an in-memory key minted at startup.
    ephemeral_key: Option<Name>,
    /// Which rule chose the node identity (an enrollment that makes the
    /// first identity the node identity records `PibDefault`).
    source: std::sync::Mutex<NodeIdentitySource>,
    /// Counts the changes, so a subsystem that acts on the daemon's
    /// identities (QUIC links made again) learns of each.
    changed: tokio::sync::watch::Sender<u64>,
}

impl ActiveIdentity {
    /// The node identity signing with `node` (one of `security`'s keys, or
    /// the in-memory startup key when `ephemeral`), chosen by `source`.
    pub(crate) fn new(
        security: Arc<SecurityManager>,
        node: Arc<dyn Signer>,
        source: NodeIdentitySource,
    ) -> Self {
        let ephemeral = source == NodeIdentitySource::Ephemeral;
        Self {
            ephemeral_key: ephemeral.then(|| node.key_name().clone()),
            signer: Arc::new(ActiveSigner::new(node)),
            security,
            source: std::sync::Mutex::new(source),
            changed: tokio::sync::watch::Sender::new(0),
        }
    }

    /// The node signer the signing subsystems hold.
    pub(crate) fn signer(&self) -> &Arc<ActiveSigner> {
        &self.signer
    }

    /// Every identity the daemon signs Data as, sorted by identity.
    pub(crate) fn signing_identities(&self) -> Vec<SigningIdentity> {
        self.security.signing_identities()
    }

    /// A signing identity was added (an enrollment; its key is in the
    /// engine's key store already) or removed.
    pub(crate) fn identities_changed(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    /// Sign the daemon's own packets with `signer` (a persistent PIB key)
    /// from the next packet on: the daemon's first identity, enrolled while
    /// it ran on its startup key. The ephemeral startup key leaves the
    /// signing identities: nothing is signed with it any more.
    pub(crate) fn replace_node(&self, signer: Arc<dyn Signer>, source: NodeIdentitySource) {
        self.signer.replace(signer);
        if let Some(ephemeral) = &self.ephemeral_key {
            self.security.remove_key(ephemeral);
        }
        *self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
        self.identities_changed();
    }

    /// Changes each time a signing identity is added or removed or the node
    /// key changes.
    pub(crate) fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// The node key, and whether it is the ephemeral startup key.
    pub(crate) fn current(&self) -> (Name, bool) {
        let key = self.signer.current().key_name().clone();
        let ephemeral = self.ephemeral_key.as_ref() == Some(&key);
        (key, ephemeral)
    }

    /// Which rule chose the node identity.
    pub(crate) fn source(&self) -> NodeIdentitySource {
        *self
            .source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
