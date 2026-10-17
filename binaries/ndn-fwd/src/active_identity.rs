//! The key the running daemon signs its own packets with — management
//! responses and discovery records — which `security/enroll` replaces while
//! the daemon runs. (DV routing with `static`/`lvs` trust takes a fixed
//! copy of the startup key instead: its neighbours trust only the keys they
//! list.)
//!
//! Those subsystems share one [`ActiveSigner`] and take one snapshot of it
//! per packet, so a switch applies from the next packet on and every packet's
//! KeyLocator names the key that signed it.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::{ActiveSigner, Signer};

pub(crate) struct ActiveIdentity {
    signer: Arc<ActiveSigner>,
    /// The startup key when it is an in-memory key minted at startup.
    ephemeral_key: Option<Name>,
}

impl ActiveIdentity {
    pub(crate) fn new(signer: Arc<dyn Signer>, ephemeral: bool) -> Self {
        Self {
            ephemeral_key: ephemeral.then(|| signer.key_name().clone()),
            signer: Arc::new(ActiveSigner::new(signer)),
        }
    }

    /// The signer the signing subsystems hold.
    pub(crate) fn signer(&self) -> &Arc<ActiveSigner> {
        &self.signer
    }

    /// Sign with `signer` (a persistent PIB key) from the next packet on.
    pub(crate) fn switch_to(&self, signer: Arc<dyn Signer>) {
        self.signer.replace(signer);
    }

    /// The key signing now, and whether it is the ephemeral startup key.
    pub(crate) fn current(&self) -> (Name, bool) {
        let key = self.signer.current().key_name().clone();
        let ephemeral = self.ephemeral_key.as_ref() == Some(&key);
        (key, ephemeral)
    }
}
