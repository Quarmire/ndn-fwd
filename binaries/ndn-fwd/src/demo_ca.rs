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
    /// Parent namespace under which the CA issues certs (per
    /// `HierarchicalPolicy`: `/demo/CA` → `/demo`). Registered in the
    /// FIB at the same face as `prefix` so the cert-fetch round trip
    /// (NDNCERT 0.3 §5) reaches the CA. `None` when the CA prefix has
    /// no usable parent (e.g. a single-component prefix).
    pub cert_namespace: Option<Name>,
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

    // Compute the issuance namespace by stripping a trailing `CA`
    // component if present, mirroring `ndn_cert::HierarchicalPolicy`.
    // For `/demo/CA` this yields `/demo`. We register both prefixes
    // at the CA face so cert-fetch Interests for issued certs (which
    // sit under `/demo/<requester>/KEY/...`, NOT under `/demo/CA`)
    // reach the producer. Browser-registered prefixes like
    // `/demo/<random>` win via longest-prefix-match.
    let cert_namespace = {
        let comps = prefix.components();
        match comps.last() {
            Some(last) if last.value.as_ref() == b"CA" && comps.len() > 1 => Some(
                ndn_packet::Name::from_components(
                    comps[..comps.len() - 1].iter().cloned(),
                ),
            ),
            _ => None,
        }
    };

    Ok((
        face,
        DemoCaSpawn {
            handle,
            face_id,
            prefix,
            cert_namespace,
            keychain,
        },
    ))
}

/// Install the demo CA's anchor onto the localhop validator and share
/// the CA's `cert_cache` with it.
///
/// Mirrors NFD `daemon/mgmt/rib-manager.cpp:340-355` — when the
/// localhop validator has at least one anchor, `/localhop/nfd/rib/register`
/// dispatches through it. The demo CA's self-signed cert is the anchor
/// for every cert it issues, so issued certs implicitly chain to a
/// `/localhop`-trusted root.
///
/// **Cache sharing**: in a real testbed deployment the validator would
/// fetch each requester's cert from the network (via `CertFetcher`).
/// In this demo the CA runs in the same process as the validator, so
/// we wire the validator to the CA's `Arc<CertCache>` directly:
/// every time the CA issues a cert via
/// `SecurityManager::certify`, the validator sees it on its very next
/// `cert_cache.get(...)`. This is end-to-end spec-correct (the
/// signature chain is the same as the network-fetched version) and
/// avoids a round-trip cert-fetch on the management hot path.
///
/// Returns a fresh validator if `existing` is `None`, or amends the
/// existing one in place and returns the same `Arc`. When `existing`
/// is `Some`, the cache is NOT replaced — the operator's pre-built
/// validator already has its own cache; we only add the anchor and
/// pre-load the CA's cert cache by inserting any certs the CA's
/// manager already holds.
pub(crate) fn install_localhop_anchor(
    keychain: &KeyChain,
    existing: Option<Arc<Validator>>,
) -> Result<Arc<Validator>> {
    let manager = keychain.manager_arc();
    let anchor = manager
        .trust_anchor(keychain.key_name())
        .ok_or_else(|| {
            anyhow::anyhow!("[demo_ca] keychain produced no self-signed trust anchor")
        })?;

    let validator = match existing {
        Some(v) => v,
        None => {
            let schema = ndn_security::TrustSchema::accept_all();
            // Build the validator with the CA's shared cert_cache so
            // newly-issued certs are visible without a network fetch.
            Arc::new(ndn_security::Validator::with_chain(
                schema,
                manager.cert_cache_arc(),
                Arc::new(dashmap::DashMap::new()),
                None,
                10,
            ))
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
