//! NDN transport for the remote signer — the dashboard's side of the pairing
//! channel.
//!
//! A [`ndn_security::custodian::RemoteCustodian`] built on this sends each command's
//! signed region to the paired phone as a [`WireSignRequest`] in an Interest's
//! application parameters, addressed to the phone's `…/signer` responder prefix.
//! The phone signs it — only within the scope and window the operator granted —
//! and returns the signature in the Data content. No key, only individual
//! signatures, ever crosses the wire, and it rides the *same* forwarder the
//! dashboard already manages: NDN-native, no HTTP relay or IP signaling.
//!
//! Pairs with the phone-side responder `NdnEngine::serve_remote_signer`
//! (`crates/ndn-boltffi/src/engine.rs`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_app::Consumer;
use ndn_security::custodian::{
    CustodianError, CustodianRef, RemoteSignRequest, RemoteSignerTransport, WireSignRequest,
    WireSignResponse,
};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Name, NameComponent};
use ndn_trust_envelope::{CapDirection, Capability, TrustEnvelope};
use tokio::sync::Mutex;

/// Derive the operator **identity** name from a certificate name by dropping the
/// `KEY/<id>/…` suffix — `/demo/phone/dev1/KEY/x/self/v=0` → `/demo/phone/dev1`.
fn identity_of_cert_name(cert_name: &Name) -> Option<Name> {
    let comps: &[NameComponent] = cert_name.components();
    let key_idx = comps.iter().position(|c| c.value.as_ref() == b"KEY")?;
    Some(Name::from_components(comps[..key_idx].iter().cloned()))
}

/// Complete pairing from a scanned `Capability{Grant}`: decode the operator
/// certificate it carries, build an NDN transport to the phone's `…/signer`
/// responder, and provision it as this console's active remote signer. From here
/// on, [`crate::operator_keyring::command_signer`] routes every command's
/// signature to the phone. Returns the operator identity name now signing.
pub fn pair_from_grant(grant_uri: &str, socket_path: PathBuf) -> Result<String, String> {
    let cert_wire = match TrustEnvelope::from_uri(grant_uri.trim()).map_err(|e| e.to_string())? {
        TrustEnvelope::Capability(Capability {
            direction: CapDirection::Grant,
            grant: Some(cert),
            ..
        }) => cert,
        TrustEnvelope::Capability(Capability {
            direction: CapDirection::Grant,
            grant: None,
            ..
        }) => return Err("grant carries no operator certificate".into()),
        _ => return Err("not a capability grant".into()),
    };

    // The responder prefix is name-derived: <operator identity>/signer.
    let cert =
        ndn_packet::Data::decode(cert_wire.clone()).map_err(|e| format!("certificate decode: {e:?}"))?;
    let identity = identity_of_cert_name(&cert.name)
        .ok_or("operator certificate name has no /KEY/ component")?;
    let responder_prefix = identity.clone().append("signer");
    let fob_id = identity.to_string();

    let transport: Arc<dyn RemoteSignerTransport> =
        Arc::new(NdnRemoteSignerTransport::new(socket_path, responder_prefix));
    crate::operator_keyring::provision_remote_signer_from_cert(
        cert_wire,
        transport,
        CustodianRef::Fob { fob_id },
    )
}

/// Routes signing requests to a paired phone over the shared forwarder socket.
pub struct NdnRemoteSignerTransport {
    /// The forwarder's app/management socket (the one the dashboard manages).
    socket_path: PathBuf,
    /// The phone's responder prefix (e.g. `/demo/phone/dev1/signer`).
    responder_prefix: Name,
    /// Lazily-opened consumer face to the forwarder (reused across requests).
    consumer: Mutex<Option<Consumer>>,
    /// Monotonic request id for single-flight correlation.
    req_counter: AtomicU64,
    /// How long to wait for the phone to approve + sign.
    timeout: Duration,
}

impl NdnRemoteSignerTransport {
    pub fn new(socket_path: impl Into<PathBuf>, responder_prefix: Name) -> Self {
        Self {
            socket_path: socket_path.into(),
            responder_prefix,
            consumer: Mutex::new(None),
            req_counter: AtomicU64::new(1),
            // Generous: the phone may need to wake, and an out-of-scope request
            // can wait on a biometric prompt.
            timeout: Duration::from_secs(20),
        }
    }
}

#[async_trait]
impl RemoteSignerTransport for NdnRemoteSignerTransport {
    async fn request_signature(&self, req: &RemoteSignRequest) -> Result<Bytes, CustodianError> {
        let req_id = self.req_counter.fetch_add(1, Ordering::Relaxed);
        let wire = WireSignRequest {
            req_id,
            region: req.region.clone(),
        }
        .encode();

        let mut guard = self.consumer.lock().await;
        if guard.is_none() {
            let c = Consumer::connect(&self.socket_path)
                .await
                .map_err(|e| CustodianError::SignFailed(format!("connect signer face: {e}")))?;
            *guard = Some(c);
        }
        let consumer = guard.as_mut().unwrap();

        let builder = InterestBuilder::new(self.responder_prefix.clone())
            .app_parameters(wire.to_vec())
            .must_be_fresh()
            .lifetime(self.timeout);
        let data = consumer
            .fetch_with(builder)
            .await
            .map_err(|e| CustodianError::SignFailed(format!("signer unreachable: {e}")))?;

        let content = data
            .content()
            .ok_or_else(|| CustodianError::SignFailed("empty signer response".into()))?;
        match WireSignResponse::decode(content)
            .map_err(|e| CustodianError::SignFailed(format!("bad signer response: {e:?}")))?
        {
            WireSignResponse::Approved {
                req_id: got,
                signature,
            } => {
                if got != req_id {
                    return Err(CustodianError::SignFailed(
                        "signer response id mismatch".into(),
                    ));
                }
                Ok(signature)
            }
            WireSignResponse::Denied { .. } => Err(CustodianError::SignFailed(
                "the operator denied this signature on the phone".into(),
            )),
        }
    }

    /// Best-effort liveness: can we open a face to the forwarder? (Whether the
    /// phone itself is up surfaces per-request as a `SignFailed` timeout — a
    /// cheap probe here can't prove the remote producer is listening.)
    async fn is_reachable(&self) -> bool {
        let mut guard = self.consumer.lock().await;
        if guard.is_some() {
            return true;
        }
        match Consumer::connect(&self.socket_path).await {
            Ok(c) => {
                *guard = Some(c);
                true
            }
            Err(_) => false,
        }
    }
}
