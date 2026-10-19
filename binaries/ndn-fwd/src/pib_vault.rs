//! The daemon's [`KeyVault`]: device keys and certificates in its PIB
//! (`keys/*/certs/`, issuer certificates under `<pib>/issuers`, request
//! records under `<pib>/requests`), and how a newly enrolled key is added:
//! the engine signs the namespace's Data with it at once (beside the
//! daemon's other identities) and the subsystems presenting the daemon's
//! identities are told. The node identity — the key of the daemon's own
//! packets — changes only for the daemon's first identity (it ran on an
//! ephemeral key), and the PIB's default identity is recorded only then.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{NodeIdentitySource, RequestStore};
use ndn_namespace::{Activation, Detail, KeyUnavailable, KeyVault, detail_code};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, PibError, Signer};

use crate::active_identity::ActiveIdentity;

/// Where the outgoing requests live, beside the PIB.
pub(crate) const REQUESTS_DIR: &str = "requests";

pub(crate) struct PibVault {
    pub(crate) pib_root: PathBuf,
    /// The daemon's identities: the node signer and the engine's signing
    /// identities; `None` when the node runs unsigned.
    pub(crate) signing: Option<Arc<ActiveIdentity>>,
    /// DV routing runs with `static`/`lvs` trust: it keeps the key the node
    /// started with (see `installs::dv::prepare`), so a new node identity
    /// says so.
    pub(crate) dv_keeps_startup_key: bool,
    /// `[security] identity` from the config: it takes precedence over the
    /// PIB's default identity, so the first enrollment does not change the
    /// node signer.
    pub(crate) configured_identity: Option<String>,
}

impl PibVault {
    fn open(&self) -> Result<FilePib, PibError> {
        FilePib::open(&self.pib_root)
    }

    fn unreadable(&self, e: PibError) -> String {
        format!("cannot read the PIB {}: {e}", self.pib_root.display())
    }

    /// The identity of the running node key, unless it is the ephemeral
    /// startup key.
    fn running_node_identity(&self) -> Option<Name> {
        let (key, ephemeral) = self.signing.as_ref()?.current();
        if ephemeral {
            return None;
        }
        let comps = key.components();
        let at = comps.iter().position(|c| c.value.as_ref() == b"KEY")?;
        Some(Name::from_components(comps[..at].iter().cloned()))
    }
}

impl KeyVault for PibVault {
    fn location(&self) -> String {
        self.pib_root.display().to_string()
    }

    /// The PIB's default identity, else the persistent node identity the
    /// daemon runs on (configured, or chosen as a root device's or the first
    /// enrolled identity): an enrollment never records a default beside it.
    fn default_identity(&self) -> Result<Option<Name>, String> {
        let pib = FilePib::new(&self.pib_root)
            .map_err(|e| format!("cannot open the PIB {}: {e}", self.pib_root.display()))?;
        Ok(pib
            .get_default_identity()
            .ok()
            .flatten()
            .or_else(|| self.running_node_identity()))
    }

    fn node_identity(&self) -> Option<Name> {
        self.running_node_identity()
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

    /// The engine signs `identity`'s Data with `key` already (the
    /// enrollment registered it); the subsystems presenting the daemon's
    /// identities are told. For the daemon's first identity
    /// (`first_identity`, it ran on its ephemeral startup key) the node
    /// signer switches to it too, unless `[security] identity` names
    /// another one.
    fn activate(
        &self,
        identity: &Name,
        key: &Name,
        signer: Arc<dyn Signer>,
        first_identity: bool,
    ) -> Activation {
        let mut at_next_start = Vec::new();
        let Some(active) = &self.signing else {
            at_next_start.push(
                Detail::new(
                    detail_code::NEXT_START_UNSIGNED,
                    format!(
                        "this node started without a signing key; it signs as {identity} after \
                         a restart"
                    ),
                )
                .with("identity", identity),
            );
            return Activation {
                signing_now: false,
                node_identity: false,
                at_next_start,
            };
        };
        let mut node_identity = false;
        if first_identity {
            match &self.configured_identity {
                Some(configured) => at_next_start.push(
                    Detail::new(
                        detail_code::NEXT_START_CONFIGURED_IDENTITY,
                        format!(
                            "the node identity stays {configured}: this node's configuration \
                             names it; {identity} is recorded as its default identity, the node \
                             identity once the configuration names none"
                        ),
                    )
                    .with("configured", configured)
                    .with("identity", identity),
                ),
                None if active.current().1 => {
                    active.replace_node(Arc::clone(&signer), NodeIdentitySource::PibDefault);
                    node_identity = true;
                    if self.dv_keeps_startup_key {
                        at_next_start.push(
                            Detail::new(
                                detail_code::NEXT_START_ROUTING_KEY,
                                format!(
                                    "routing keeps signing with the key this node started with; \
                                     it signs with {key} after a restart, so have every routing \
                                     neighbour trust that key before restarting"
                                ),
                            )
                            .with("key", key),
                        );
                    }
                }
                None => {}
            }
        }
        // The engine holds the key already; links present the new
        // membership.
        active.identities_changed();
        Activation {
            signing_now: true,
            node_identity,
            at_next_start,
        }
    }
}
