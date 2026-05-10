//! Browser-side NDNCERT enrollment client.
//!
//! Drives the NEW + CHALLENGE round-trip against the embedded
//! `/demo/CA` served by `ndn-fwd` (see `binaries/spec/ndn-fwd/src/demo_ca.rs`).
//! Returns an [`EnrolledIdentity`] carrying the freshly-generated ECDSA
//! P-256 signer plus the issued certificate name. The caller signs
//! `/localhop/nfd/rib/register` Interests with the signer, with the
//! issued cert as the KeyLocator.
//!
//! The CA's challenge handler is `nop` — every request is approved.
//! Only safe behind a trusted local face.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::EnrollmentSession;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{KeyChain, Signer};

use crate::engine::{Engine, EngineError};

#[derive(Debug)]
pub enum EnrollError {
    Engine(EngineError),
    Cert(ndn_cert::CertError),
    Trust(ndn_security::error::TrustError),
    Decode(String),
    Protocol(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::Engine(e) => write!(f, "engine: {e}"),
            EnrollError::Cert(e) => write!(f, "ndncert: {e}"),
            EnrollError::Trust(e) => write!(f, "trust: {e}"),
            EnrollError::Decode(e) => write!(f, "decode: {e}"),
            EnrollError::Protocol(e) => write!(f, "protocol: {e}"),
        }
    }
}

impl From<EngineError> for EnrollError {
    fn from(e: EngineError) -> Self {
        EnrollError::Engine(e)
    }
}
impl From<ndn_cert::CertError> for EnrollError {
    fn from(e: ndn_cert::CertError) -> Self {
        EnrollError::Cert(e)
    }
}
impl From<ndn_security::error::TrustError> for EnrollError {
    fn from(e: ndn_security::error::TrustError) -> Self {
        EnrollError::Trust(e)
    }
}

/// A successfully-enrolled browser identity.
pub struct EnrolledIdentity {
    /// Signing key that produced the cert request. Use this to sign
    /// `/localhop/nfd/rib/register` Interests.
    pub signer: Arc<dyn Signer>,
    /// Name of the issued certificate, used as the KeyLocator name on
    /// signed Interests.
    pub cert_name: Name,
    /// Wire bytes of the issued certificate Data packet (so the caller
    /// can serve it back to the forwarder if asked for it).
    pub cert_wire: Bytes,
}

const ENROLL_LIFETIME: Duration = Duration::from_millis(4000);

#[cfg(all(target_arch = "wasm32", feature = "web"))]
fn log(msg: &str) {
    web_sys::console::log_1(&format!("[enroll] {msg}").into());
}
#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
fn log(_msg: &str) {}

/// Run the full NDNCERT NEW + CHALLENGE flow against `ca_prefix` with
/// the auto-approve `nop` challenge. Equivalent to
/// [`enroll_with_challenge`] with `Challenge::Nop`. Kept as a
/// thin wrapper for callers that don't need the token-claim path.
pub async fn enroll(
    engine: &Engine,
    ca_prefix: &Name,
    identity_name: &Name,
) -> Result<EnrolledIdentity, EnrollError> {
    enroll_with_challenge(engine, ca_prefix, identity_name, Challenge::Nop).await
}

/// Challenge selector for [`enroll_with_challenge`].
///
/// `Nop` matches a CA running `NopChallenge` (every request
/// auto-approved — demo / trusted-face only). `Token { value }`
/// matches a CA running `TokenChallenge` populated with the
/// pre-provisioned token; this is the onboarding-link path
/// (`#join=<token>` in the URL fragment).
pub enum Challenge {
    Nop,
    Token { value: String },
}

impl Challenge {
    fn name(&self) -> &'static str {
        match self {
            Challenge::Nop => "nop",
            Challenge::Token { .. } => "token",
        }
    }

    fn parameters(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut params = serde_json::Map::new();
        if let Challenge::Token { value } = self {
            params.insert(
                "token".to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
        params
    }
}

/// Run the full NDNCERT NEW + CHALLENGE flow against `ca_prefix`,
/// returning a fresh signing identity bound to a CA-issued cert.
///
/// `identity_name` is the requester's NDN identity (e.g. `/demo/browser/<random>`);
/// the signing key is auto-generated under it. `challenge` selects
/// which challenge type to negotiate — must match what the CA was
/// configured to serve.
pub async fn enroll_with_challenge(
    engine: &Engine,
    ca_prefix: &Name,
    identity_name: &Name,
    challenge: Challenge,
) -> Result<EnrolledIdentity, EnrollError> {
    // Build a fresh KeyChain so the caller doesn't have to manage a
    // signer themselves. Callers that *do* want to manage the seed
    // (e.g. JoinClient persisting to IdbPib) should call
    // [`enroll_with_signer`] directly.
    let keychain = KeyChain::ephemeral(identity_name.to_string()).map_err(EnrollError::Trust)?;
    let signer = keychain.signer().map_err(EnrollError::Trust)?;
    enroll_with_signer(engine, ca_prefix, signer, challenge).await
}

/// Variant that takes a pre-built signer instead of minting one
/// internally. The caller owns the signer (and therefore the
/// secret key bytes), which is the seam that lets `JoinClient`
/// generate an [`Ed25519Signer`](ndn_security::Ed25519Signer)
/// from a known seed and persist that seed to IdbPib for
/// reload-restore. The signer's key name (`signer.key_name()`)
/// is the identity that gets enrolled.
pub async fn enroll_with_signer(
    engine: &Engine,
    ca_prefix: &Name,
    signer: Arc<dyn Signer>,
    challenge: Challenge,
) -> Result<EnrolledIdentity, EnrollError> {
    let key_name = signer.key_name().clone();
    let mut session = EnrollmentSession::new(key_name, Arc::clone(&signer), 86_400);

    // 2. NEW request.
    let new_params = session.new_request_body().await?;
    let new_name = ca_prefix.clone().append("CA").append("NEW");
    let new_wire = build_signed_interest(&signer, new_name.clone(), &new_params).await?;
    // Response Data name = full Interest name (with PSDC slot N-1) —
    // that's how `Producer::serve` copies the request name onto the
    // reply. Decode the wire to recover the exact PSDC-bearing name.
    let new_pending_key = pending_key_from_wire(&new_wire)?;
    let new_resp = engine
        .express_wire(new_wire, new_pending_key, ENROLL_LIFETIME)
        .await?;
    let new_content = new_resp
        .data
        .content()
        .ok_or_else(|| EnrollError::Decode("NEW response had no Content".into()))?;
    session.handle_new_response(new_content)?;

    // 3. CHALLENGE request — auto-approve "nop" challenge.
    let challenge_type = challenge.name();
    if !session
        .offered_challenges()
        .iter()
        .any(|c| c == challenge_type)
    {
        return Err(EnrollError::Protocol(format!(
            "CA did not offer '{challenge_type}' challenge; offered: {:?}",
            session.offered_challenges()
        )));
    }
    let challenge_params =
        session.challenge_request_body(challenge_type, challenge.parameters())?;
    let request_id = *session
        .request_id_bytes()
        .ok_or_else(|| EnrollError::Protocol("no request_id after NEW".into()))?;
    let challenge_name = ca_prefix
        .clone()
        .append("CA")
        .append("CHALLENGE")
        .append_component(ndn_packet::NameComponent::generic(Bytes::copy_from_slice(
            &request_id,
        )));
    let challenge_wire =
        build_signed_interest(&signer, challenge_name.clone(), &challenge_params).await?;
    let challenge_pending_key = pending_key_from_wire(&challenge_wire)?;
    let challenge_resp = engine
        .express_wire(challenge_wire, challenge_pending_key, ENROLL_LIFETIME)
        .await?;
    let challenge_content = challenge_resp
        .data
        .content()
        .ok_or_else(|| EnrollError::Decode("CHALLENGE response had no Content".into()))?;
    session.handle_challenge_response(challenge_content)?;

    if !session.is_complete() {
        return Err(EnrollError::Protocol(format!(
            "CA did not approve {challenge_type} challenge; status: {:?}",
            session.challenge_status_message()
        )));
    }

    // 4. Fetch the issued cert (separate Interest, no AppParams).
    let cert_name = session
        .issued_cert_name()
        .ok_or_else(|| EnrollError::Protocol("no issued_cert_name on success".into()))?
        .clone();
    let fetch_wire = InterestBuilder::new(cert_name.clone())
        .lifetime(ENROLL_LIFETIME)
        .must_be_fresh()
        .build();
    let cert_resp = engine
        .express_wire(fetch_wire, cert_name.to_string(), ENROLL_LIFETIME)
        .await?;
    let cert_wire = cert_resp.data.raw().clone();
    let _decoded =
        Data::decode(cert_wire.clone()).map_err(|e| EnrollError::Decode(format!("cert: {e}")))?;

    Ok(EnrolledIdentity {
        signer,
        cert_name,
        cert_wire,
    })
}

async fn build_signed_interest(
    signer: &Arc<dyn Signer>,
    name: Name,
    app_params: &[u8],
) -> Result<Bytes, EnrollError> {
    let key_locator = signer
        .cert_name()
        .cloned()
        .or_else(|| Some(signer.key_name().clone()));
    let sig_type = signer.sig_type();
    let signer = Arc::clone(signer);
    let wire = InterestBuilder::new(name)
        .lifetime(ENROLL_LIFETIME)
        .must_be_fresh()
        .app_parameters(app_params.to_vec())
        .sign_fallible::<_, _, ndn_security::error::TrustError>(
            sig_type,
            key_locator.as_ref(),
            move |region| {
                let signer = Arc::clone(&signer);
                let region = region.to_vec();
                async move { signer.sign(&region).await }
            },
        )
        .await
        .map_err(EnrollError::Trust)?;
    Ok(wire)
}

/// Decode the just-built Interest wire to recover the full name
/// (including the `ParametersSha256DigestComponent` the encoder
/// computed), then return its string form for the engine's pending-map
/// key. The CA's `Producer::serve` builds its reply Data with
/// `name = interest.name`, so this matches.
fn pending_key_from_wire(wire: &Bytes) -> Result<String, EnrollError> {
    let interest = Interest::decode(wire.clone())
        .map_err(|e| EnrollError::Decode(format!("interest re-decode: {e}")))?;
    Ok(interest.name.to_string())
}
