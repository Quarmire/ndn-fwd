//! In-process auto-approve NDNCERT CA used by the dioxus-demo scenario.
//!
//! When `[demo_ca] enabled = true`, the forwarder mints a self-signed
//! CA cert, installs it as a `/localhop` trust anchor at runtime, and
//! serves NDNCERT INFO/NEW/CHALLENGE under the configured prefix via an
//! in-process face attached to the engine's pipeline.
//!
//! The challenge handler is [`ndn_cert::NopChallenge`] — every request
//! is approved. Only safe for demo deployments behind a trusted local
//! face. Production NDNCERT CAs run out-of-process and require real
//! challenge handlers (`pin`, `email`, `token`, `possession`).

use std::sync::Arc;

use anyhow::{Context, Result};
use ndn_app::Producer;
use ndn_cert::NopChallenge;
use ndn_config::DemoCaConfig;
use ndn_engine::ForwarderEngine;
use ndn_faces::local::{InProcFace, InProcHandle};
use ndn_identity::NdncertCa;
use ndn_packet::Name;
use ndn_security::{KeyChain, Validator};
use ndn_transport::FaceId;

/// Post-build artefacts retained until the engine is up: the
/// `InProcHandle` the spawned CA task reads Interests from, the FaceId
/// to register in the FIB under `prefix`, and the keychain the CA
/// signs with.
pub(crate) struct DemoCaSpawn {
    pub handle: InProcHandle,
    pub face_id: FaceId,
    pub prefix: Name,
    pub keychain: KeyChain,
}

/// Reserved FaceId for the demo CA's in-process face.
pub(crate) const DEMO_CA_FACE_ID: u32 = 0xFFFF_0002;

/// Build pre-engine artefacts for the demo CA. Returns the face to
/// attach to the [`EngineBuilder`] and a [`DemoCaSpawn`] to retain for
/// post-build FIB wiring + task spawn.
pub(crate) fn prepare(cfg: &DemoCaConfig) -> Result<(InProcFace, DemoCaSpawn)> {
    let prefix: Name = cfg
        .prefix
        .parse()
        .with_context(|| format!("[demo_ca] invalid prefix '{}'", cfg.prefix))?;

    let keychain = KeyChain::ephemeral(&cfg.identity)
        .with_context(|| format!("[demo_ca] keychain init failed for '{}'", cfg.identity))?;

    let face_id = FaceId(DEMO_CA_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);

    Ok((
        face,
        DemoCaSpawn {
            handle,
            face_id,
            prefix,
            keychain,
        },
    ))
}

/// Install the demo CA's anchor onto the localhop validator.
///
/// Mirrors NFD `daemon/mgmt/rib-manager.cpp:340-355` — when the localhop
/// validator has at least one anchor, `/localhop/nfd/rib/register`
/// dispatches through it. The demo CA's self-signed cert is the anchor
/// for every cert it issues, so issued certs implicitly chain to a
/// `/localhop`-trusted root.
///
/// Returns a fresh validator if `existing` is `None`, or amends the
/// existing one in place and returns the same `Arc`.
pub(crate) fn install_localhop_anchor(
    keychain: &KeyChain,
    existing: Option<Arc<Validator>>,
) -> Result<Arc<Validator>> {
    let anchor = keychain
        .manager_arc()
        .trust_anchor(keychain.key_name())
        .ok_or_else(|| {
            anyhow::anyhow!("[demo_ca] keychain produced no self-signed trust anchor")
        })?;

    let validator = match existing {
        Some(v) => v,
        None => {
            let schema = ndn_security::TrustSchema::accept_all();
            Arc::new(ndn_security::Validator::new(schema))
        }
    };
    validator.add_trust_anchor(anchor.clone());
    tracing::info!(
        target: "demo_ca",
        anchor = %anchor.name,
        "installed demo CA cert as /localhop trust anchor"
    );
    Ok(validator)
}

/// Spawn the NDNCERT CA on the engine. Must be called *after* the FIB
/// entry for `prefix` → demo CA face has been added.
pub(crate) fn spawn(prep: DemoCaSpawn, _engine: &ForwarderEngine) -> Result<()> {
    let identity = ndn_identity::NdnIdentity::from_keychain_public(prep.keychain);

    let ca = NdncertCa::builder()
        .name(prep.prefix.to_string())
        .map_err(|e| anyhow::anyhow!("[demo_ca] invalid prefix: {e}"))?
        .info("ndn-rs demo NDNCERT CA (auto-approve)")
        .signing_identity(&identity)
        .challenge(NopChallenge::new())
        .build()
        .map_err(|e| anyhow::anyhow!("[demo_ca] CA build failed: {e}"))?;

    let producer = Producer::from_handle(prep.handle, prep.prefix.clone());

    let prefix_str = prep.prefix.to_string();
    tokio::spawn(async move {
        tracing::info!(target: "demo_ca", prefix = %prefix_str, "NDNCERT CA serving");
        if let Err(e) = ca.serve(producer).await {
            tracing::error!(target: "demo_ca", error = %e, "NDNCERT CA exited");
        }
    });

    Ok(())
}
