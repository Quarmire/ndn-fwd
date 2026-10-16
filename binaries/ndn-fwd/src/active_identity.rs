//! The key the running daemon signs its own packets with — management
//! responses and discovery records — which `security/enroll` can replace
//! while the daemon runs.
//!
//! Those subsystems hold an `Arc<dyn Signer>` taken at startup. Handing them
//! an [`ActiveIdentity`] instead lets one switch reach all of them without
//! changing their APIs. [`Signer::key_name`] returns a reference that lives as
//! long as `&self`, so every signer that was active stays owned by the
//! `ActiveIdentity` (a fixed number of slots, each written once); after
//! [`SLOTS`] − 1 switches in one run, further keys take effect at the next
//! start.
//!
//! A packet being signed exactly while the key changes may carry the new
//! KeyLocator with the old key's signature (key name and signature are two
//! calls); it fails validation once and the next packet is consistent.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};
use ndn_security::{Signer, TrustError};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The startup key plus up to seven runtime switches per run.
pub(crate) const SLOTS: usize = 8;

struct Slot {
    signer: Arc<dyn Signer>,
    ephemeral: bool,
}

pub(crate) struct ActiveIdentity {
    slots: [OnceLock<Slot>; SLOTS],
    /// Index of the slot in use; always a written slot.
    current: AtomicUsize,
    /// Next slot to claim.
    next: AtomicUsize,
}

impl ActiveIdentity {
    pub(crate) fn new(signer: Arc<dyn Signer>, ephemeral: bool) -> Self {
        let slots: [OnceLock<Slot>; SLOTS] = std::array::from_fn(|_| OnceLock::new());
        let _ = slots[0].set(Slot { signer, ephemeral });
        Self {
            slots,
            current: AtomicUsize::new(0),
            next: AtomicUsize::new(1),
        }
    }

    fn get(&self) -> &Slot {
        // `current` only ever names a slot written before it was stored.
        self.slots[self.current.load(Ordering::Acquire)]
            .get()
            .expect("the current slot is written")
    }

    /// Sign with `signer` (a persistent PIB key) from now on. `false` when
    /// this run has used up its switches; the key then applies at the next
    /// start.
    pub(crate) fn switch_to(&self, signer: Arc<dyn Signer>) -> bool {
        let i = self.next.fetch_add(1, Ordering::AcqRel);
        if i >= SLOTS {
            return false;
        }
        let _ = self.slots[i].set(Slot {
            signer,
            ephemeral: false,
        });
        self.current.store(i, Ordering::Release);
        true
    }

    pub(crate) fn key(&self) -> Name {
        self.get().signer.key_name().clone()
    }

    pub(crate) fn is_ephemeral(&self) -> bool {
        self.get().ephemeral
    }
}

impl Signer for ActiveIdentity {
    fn sig_type(&self) -> SignatureType {
        self.get().signer.sig_type()
    }

    fn key_name(&self) -> &Name {
        self.get().signer.key_name()
    }

    fn cert_name(&self) -> Option<&Name> {
        self.get().signer.cert_name()
    }

    fn public_key(&self) -> Option<Bytes> {
        self.get().signer.public_key()
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        self.get().signer.sign(region)
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        self.get().signer.sign_sync(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::Ed25519Signer;

    fn signer(name: &str, seed: u8) -> Arc<dyn Signer> {
        Arc::new(Ed25519Signer::from_seed(&[seed; 32], name.parse().unwrap()))
    }

    /// After a switch, the key name and the signature both come from the new
    /// key, which is persistent; once the slots are used up the active key
    /// stays as it is.
    #[test]
    fn switch_changes_key_and_signature_together() {
        let old = signer("/ndn-fwd/host/KEY/e", 1);
        let new = signer("/home/bob/member/host/KEY/k", 2);
        let active = ActiveIdentity::new(Arc::clone(&old), true);
        assert!(active.is_ephemeral());
        assert_eq!(active.key_name(), old.key_name());
        assert!(active.switch_to(Arc::clone(&new)));
        assert_eq!(active.key_name(), new.key_name());
        assert!(!active.is_ephemeral());
        let region = b"region";
        assert_eq!(
            active.sign_sync(region).unwrap(),
            new.sign_sync(region).unwrap()
        );
        for i in 2..SLOTS {
            assert!(active.switch_to(signer("/home/bob/member/host/KEY/x", i as u8)));
        }
        let last = active.key();
        assert!(!active.switch_to(Arc::clone(&old)));
        assert_eq!(active.key(), last);
    }
}
