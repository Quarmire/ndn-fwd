//! Browser-side NDNCERT enrollment client. Drives the NEW + CHALLENGE
//! round-trip against the embedded `/demo/CA` and returns an
//! [`EnrolledIdentity`] (signer + issued cert) usable to sign
//! `/localhop/nfd/rib/register` Interests.

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

pub struct EnrolledIdentity {
    pub signer: Arc<dyn Signer>,
    /// KeyLocator name to use on signed Interests.
    pub cert_name: Name,
    /// Issued certificate Data wire, so the caller can serve it back to the
    /// forwarder on demand.
    pub cert_wire: Bytes,
}

const ENROLL_LIFETIME: Duration = Duration::from_millis(4000);

#[cfg(all(target_arch = "wasm32", feature = "web"))]
fn log(msg: &str) {
    web_sys::console::log_1(&format!("[enroll] {msg}").into());
}
#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
fn log(_msg: &str) {}

/// Enroll using the auto-approve `nop` challenge. Demo / trusted-face only.
pub async fn enroll(
    engine: &Engine,
    ca_prefix: &Name,
    identity_name: &Name,
) -> Result<EnrolledIdentity, EnrollError> {
    enroll_with_challenge(engine, ca_prefix, identity_name, Challenge::Nop).await
}

/// `Nop` matches `NopChallenge` (auto-approve, demo only). `Token` matches
/// `TokenChallenge` for the onboarding-link path (`#join=<token>`).
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

/// Mints an ephemeral signing key under `identity_name` and enrolls it. Use
/// [`enroll_with_signer`] when you need to own the seed (e.g. for IdbPib
/// persistence).
pub async fn enroll_with_challenge(
    engine: &Engine,
    ca_prefix: &Name,
    identity_name: &Name,
    challenge: Challenge,
) -> Result<EnrolledIdentity, EnrollError> {
    let keychain = KeyChain::ephemeral(identity_name.to_string()).map_err(EnrollError::Trust)?;
    let signer = keychain.signer().map_err(EnrollError::Trust)?;
    enroll_with_signer(engine, ca_prefix, signer, challenge).await
}

/// The caller owns the signer (and the secret key bytes). The signer's key
/// name is the identity that gets enrolled.
pub async fn enroll_with_signer(
    engine: &Engine,
    ca_prefix: &Name,
    signer: Arc<dyn Signer>,
    challenge: Challenge,
) -> Result<EnrolledIdentity, EnrollError> {
    let key_name = signer.key_name().clone();
    let mut session = EnrollmentSession::new(key_name, Arc::clone(&signer), 86_400);

    let new_params = session.new_request_body().await?;
    let new_name = ca_prefix.clone().append("CA").append("NEW");
    let new_wire = build_signed_interest(&signer, new_name.clone(), &new_params).await?;
    // CA reply names equal the full Interest name (including the PSDC the
    // encoder synthesized); recover it by re-decoding the wire.
    let new_pending_key = pending_key_from_wire(&new_wire)?;
    let new_resp = engine
        .express_wire(new_wire, new_pending_key, ENROLL_LIFETIME)
        .await?;
    let new_content = new_resp
        .data
        .content()
        .ok_or_else(|| EnrollError::Decode("NEW response had no Content".into()))?;
    session.handle_new_response(new_content)?;

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

/// Re-decode the encoded Interest wire to recover the full name (including
/// any synthesized `ParametersSha256DigestComponent`) for use as the
/// engine's pending-map key.
fn pending_key_from_wire(wire: &Bytes) -> Result<String, EnrollError> {
    let interest = Interest::decode(wire.clone())
        .map_err(|e| EnrollError::Decode(format!("interest re-decode: {e}")))?;
    Ok(interest.name.to_string())
}
