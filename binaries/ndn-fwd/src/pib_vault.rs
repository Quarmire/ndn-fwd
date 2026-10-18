//! The daemon's [`KeyVault`]: device keys and certificates in its PIB
//! (`keys/*/certs/`, issuer certificates under `<pib>/issuers`, request
//! records under `<pib>/requests`), and how a newly enrolled key takes
//! over signing: the PIB's default identity changes, and the running
//! daemon switches its signer unless `[security] identity` names another
//! identity or DV routing keeps the key it started with.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::RequestStore;
use ndn_namespace::{Activation, KeyUnavailable, KeyVault};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, PibError, Signer};

use crate::active_identity::ActiveIdentity;

/// Where the outgoing requests live, beside the PIB.
pub(crate) const REQUESTS_DIR: &str = "requests";

pub(crate) struct PibVault {
    pub(crate) pib_root: PathBuf,
    /// The key management responses and discovery records are signed with;
    /// `None` when the node runs unsigned.
    pub(crate) signing: Option<Arc<ActiveIdentity>>,
    /// DV routing runs with `static`/`lvs` trust: it keeps the key the node
    /// started with (see `installs::dv::prepare`), so an enrollment says so.
    pub(crate) dv_keeps_startup_key: bool,
    /// `[security] identity` from the config: it takes precedence over the
    /// PIB's default identity, so an enrollment does not change the signer.
    pub(crate) configured_identity: Option<String>,
}

impl PibVault {
    fn open(&self) -> Result<FilePib, PibError> {
        FilePib::open(&self.pib_root)
    }

    fn unreadable(&self, e: PibError) -> String {
        format!("cannot read the PIB {}: {e}", self.pib_root.display())
    }
}

impl KeyVault for PibVault {
    fn location(&self) -> String {
        self.pib_root.display().to_string()
    }

    fn default_identity(&self) -> Result<Option<Name>, String> {
        let pib = FilePib::new(&self.pib_root)
            .map_err(|e| format!("cannot open the PIB {}: {e}", self.pib_root.display()))?;
        Ok(pib.get_default_identity().ok().flatten())
    }

    fn request_store(&self) -> Result<RequestStore, String> {
        RequestStore::open(self.pib_root.join(REQUESTS_DIR)).map_err(|e| e.to_string())
    }

    fn generate(&self, key: &Name) -> Result<Arc<dyn Signer>, String> {
        let pib = FilePib::new(&self.pib_root).map_err(|e| e.to_string())?;
        let generated = pib.generate_ed25519(key).map_err(|e| e.to_string())?;
        Ok(Arc::new(generated))
    }

    fn keep_pending(&self, _key: &Name) -> Result<(), String> {
        // `generate` keeps the key in the PIB already.
        Ok(())
    }

    fn signer(&self, key: &Name) -> Result<Arc<dyn Signer>, KeyUnavailable> {
        let pib = self.open().map_err(|e| {
            KeyUnavailable::Unreadable(format!(
                "cannot open the PIB {}: {e}",
                self.pib_root.display()
            ))
        })?;
        pib.get_signer(key)
            .map_err(|e| KeyUnavailable::Gone(format!("gone from the PIB ({e})")))
    }

    fn discard(&self, key: &Name) -> Result<(), String> {
        self.open()
            .and_then(|pib| pib.delete_key(key))
            .map_err(|e| e.to_string())
    }

    fn store_certificate(&self, key: &Name, cert: &Data) -> Result<(), String> {
        self.open()
            .and_then(|pib| pib.store_issued_cert(key, cert.raw()).map(drop))
            .map_err(|e| e.to_string())
    }

    fn make_default(&self, identity: &Name) -> Result<(), String> {
        self.open()
            .and_then(|pib| pib.set_default_identity(identity))
            .map_err(|e| e.to_string())
    }

    fn keep_issuers(&self, issuers: &[Data]) -> Result<(), String> {
        ndn_cert::issuers::keep_issuer_certs(&self.pib_root, issuers)
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn issuers(&self) -> Vec<Bytes> {
        ndn_cert::issuers::stored_issuer_certs(&self.pib_root)
    }

    fn keys(&self) -> Result<Vec<Name>, String> {
        let pib = match self.open() {
            Ok(pib) => pib,
            // No PIB yet: no keys.
            Err(PibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(self.unreadable(e)),
        };
        pib.list_keys().map_err(|e| self.unreadable(e))
    }

    fn certificate(&self, key: &Name) -> Option<Certificate> {
        self.open().ok()?.get_cert(key).ok()
    }

    fn issued_certificate(&self, key: &Name) -> Result<Option<Bytes>, String> {
        self.open()
            .and_then(|pib| pib.get_issued_cert(key))
            .map_err(|e| self.unreadable(e))
    }

    fn activate(&self, identity: &Name, key: &Name, signer: Arc<dyn Signer>) -> Activation {
        let mut at_next_start = Vec::new();
        if self.dv_keeps_startup_key {
            at_next_start.push(format!(
                "DV routing: it keeps signing with the key this node started with (DV `static`/`lvs` \
                 trust); it signs with {key} after a restart, so add that key to every DV \
                 neighbour's [routing.dv.trust] trusted_keys before restarting"
            ));
        }
        let signing_now = match (&self.configured_identity, &self.signing) {
            (Some(configured), _) => {
                at_next_start.push(format!(
                    "nothing: [security] identity = \"{configured}\" in this node's config takes \
                     precedence over the PIB's default identity; remove that line to sign as \
                     {identity}"
                ));
                false
            }
            (None, Some(active)) => {
                active.switch_to(signer);
                true
            }
            (None, None) => {
                at_next_start.push(format!(
                    "management responses: this node started without a signing key; it signs as \
                     {identity} after a restart"
                ));
                false
            }
        };
        Activation {
            signing_now,
            at_next_start,
        }
    }
}
