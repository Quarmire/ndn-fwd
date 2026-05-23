//! In-process NDNCERT CA used by the dioxus-demo scenario. With `[demo_ca]
//! enabled = true`, the forwarder mints a self-signed CA cert, installs it
//! as a `/localhop` trust anchor, and serves NDNCERT INFO/NEW/CHALLENGE
//! through an in-process face. Demo / trusted-face only; production CAs
//! run out-of-process with real challenges.

use std::sync::Arc;

use anyhow::{Context, Result};
use ndn_app::Producer;
use ndn_cert::{
    ChallengeHandler, EmailChallenge, EmailSender, NopChallenge, PinChallenge,
    RequireAttestationKind, TokenChallenge, TokenStore,
};
use ndn_config::DemoCaConfig;
use ndn_engine::ForwarderEngine;
use ndn_faces::local::{InProcFace, InProcHandle};
use ndn_identity::NdncertCa;
use ndn_packet::Name;
use ndn_security::{KeyChain, Validator};
use ndn_transport::FaceId;

/// Artefacts retained until post-build: the `InProcHandle` for the CA
/// task, the FaceId to register, the CA prefix, and the signing keychain.
pub(crate) struct DemoCaSpawn {
    pub handle: InProcHandle,
    pub face_id: FaceId,
    pub prefix: Name,
    /// Parent namespace where the CA issues certs (`HierarchicalPolicy`:
    /// `/demo/CA` → `/demo`). Registered alongside `prefix` so cert-fetch
    /// round trips (NDNCERT 0.3 §5) reach the CA. `None` for single-
    /// component CA prefixes.
    pub cert_namespace: Option<Name>,
    pub keychain: KeyChain,
}

pub(crate) const DEMO_CA_FACE_ID: u64 = 0xFFFF_0002;

/// Returns the face to attach to the builder and the [`DemoCaSpawn`]
/// retained for post-build FIB wiring and the task spawn.
pub(crate) fn prepare(cfg: &DemoCaConfig) -> Result<(InProcFace, DemoCaSpawn)> {
    let prefix: Name = cfg
        .prefix
        .parse()
        .with_context(|| format!("[demo_ca] invalid prefix '{}'", cfg.prefix))?;

    let keychain = KeyChain::ephemeral(&cfg.identity)
        .with_context(|| format!("[demo_ca] keychain init failed for '{}'", cfg.identity))?;

    let face_id = FaceId(DEMO_CA_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);

    // Strip a trailing `CA` to get the issuance namespace, matching
    // `ndn_cert::HierarchicalPolicy`. `/demo/CA` → `/demo`. Both prefixes
    // get FIB entries on the CA face so cert-fetch Interests for issued
    // certs (`/demo/<requester>/KEY/...`) reach the producer. More-specific
    // browser-registered prefixes still win LPM.
    let cert_namespace = {
        let comps = prefix.components();
        match comps.last() {
            Some(last) if last.value.as_ref() == b"CA" && comps.len() > 1 => Some(
                ndn_packet::Name::from_components(comps[..comps.len() - 1].iter().cloned()),
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

/// Add the demo CA's self-signed cert as a `/localhop` trust anchor and,
/// for in-process operation, share the CA's `Arc<CertCache>` with the
/// validator so newly-issued certs are visible without a network fetch.
/// When `existing` is `Some`, the validator's existing cache is preserved
/// and only the anchor is added.
pub(crate) fn install_localhop_anchor(
    keychain: &KeyChain,
    existing: Option<Arc<Validator>>,
) -> Result<Arc<Validator>> {
    let manager = keychain.manager_arc();
    let anchor = manager.trust_anchor(keychain.key_name()).ok_or_else(|| {
        anyhow::anyhow!("[demo_ca] keychain produced no self-signed trust anchor")
    })?;

    let validator = match existing {
        Some(v) => v,
        None => {
            let schema = ndn_security::TrustSchema::accept_all();
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

/// Must run after the FIB entry for `prefix` → demo CA face is in place.
/// Empty `tokens` selects [`NopChallenge`] (auto-approve, demo only);
/// non-empty selects [`TokenChallenge`] (each token consumed on first use).
pub(crate) fn spawn(
    prep: DemoCaSpawn,
    cfg: &DemoCaConfig,
    _engine: &ForwarderEngine,
) -> Result<()> {
    let identity = ndn_identity::NdnIdentity::from_keychain_public(prep.keychain);

    let challenges = build_challenges(cfg)?;
    tracing::info!(
        target: "demo_ca",
        challenges = ?challenges.iter().map(|c| c.challenge_type()).collect::<Vec<_>>(),
        "NDNCERT challenge set",
    );

    let mut builder = NdncertCa::builder()
        .name(prep.prefix.to_string())
        .map_err(|e| anyhow::anyhow!("[demo_ca] invalid prefix: {e}"))?
        .info("ndn-rs demo NDNCERT CA")
        .signing_identity(&identity)
        .emit_attestations(cfg.emit_attestations);
    for challenge in challenges {
        builder = builder.challenge_box(challenge);
    }

    if let Some(ra) = &cfg.require_attestation {
        let prefix: Name = ra
            .prefix
            .parse()
            .with_context(|| format!("[demo_ca] invalid require_attestation prefix '{}'", ra.prefix))?;
        let policy =
            RequireAttestationKind::new(prefix, ra.kind.clone()).require_signed(ra.require_signed);
        builder = builder.issuance(Box::new(policy));
        tracing::info!(
            target: "demo_ca",
            prefix = %ra.prefix, kind = %ra.kind, signed = ra.require_signed,
            "issuance gated on challenge attestation",
        );
    }

    let ca = builder
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

/// Build the CA's challenge set from config. An explicit `[[demo_ca.challenge]]`
/// list wins; otherwise fall back to the legacy `tokens`-driven nop/token
/// selection. `possession`/`yubikey`/`device-approval` need certs / secrets /
/// the approve-feed, so they're wired in code, not via this config.
fn build_challenges(cfg: &DemoCaConfig) -> Result<Vec<Box<dyn ChallengeHandler>>> {
    if cfg.challenges.is_empty() {
        let handler: Box<dyn ChallengeHandler> = if cfg.tokens.is_empty() {
            Box::new(NopChallenge::new())
        } else {
            let store = TokenStore::new();
            store.add_many(cfg.tokens.clone());
            Box::new(TokenChallenge::new(store))
        };
        return Ok(vec![handler]);
    }
    cfg.challenges.iter().map(build_challenge).collect()
}

fn build_challenge(c: &ndn_config::ChallengeConfig) -> Result<Box<dyn ChallengeHandler>> {
    match c.kind.as_str() {
        "nop" => Ok(Box::new(NopChallenge::new())),
        "token" => {
            let store = TokenStore::new();
            store.add_many(c.tokens.clone());
            Ok(Box::new(TokenChallenge::new(store)))
        }
        "pin" => {
            let pin = c
                .pin
                .as_deref()
                .with_context(|| "[demo_ca] pin challenge requires `pin`")?;
            let handler = match c.max_tries {
                Some(m) => PinChallenge::new_with_max_tries(pin, m),
                None => PinChallenge::new(pin),
            };
            Ok(Box::new(handler))
        }
        "email" => {
            let sender = make_email_sender(c.smtp.as_ref());
            let mut handler = EmailChallenge::new(sender);
            if let Some(ttl) = c.ttl_secs {
                handler = handler.with_ttl(ttl);
            }
            if let Some(m) = c.max_tries {
                handler = handler.with_max_tries(m);
            }
            Ok(Box::new(handler))
        }
        other => Err(anyhow::anyhow!(
            "[demo_ca] unsupported challenge kind '{other}' \
             (nop|token|pin|email; possession/yubikey/device-approval are wired in code)"
        )),
    }
}

/// Pick the EmailSender for the `email` challenge. With `log_only`, no `host`,
/// or the `smtp` feature disabled, falls back to [`LoggingEmailSender`] (the
/// code is logged, not delivered). With a real relay configured and the `smtp`
/// feature on, returns the SMTP sender.
fn make_email_sender(smtp: Option<&ndn_config::SmtpConfig>) -> Arc<dyn EmailSender> {
    let wants_real = smtp.is_some_and(|s| !s.log_only && !s.host.is_empty());
    if !wants_real {
        return Arc::new(ndn_identity::LoggingEmailSender);
    }
    #[cfg(feature = "smtp")]
    {
        Arc::new(crate::smtp_email::SmtpEmailSender::new(smtp.expect("checked")))
    }
    #[cfg(not(feature = "smtp"))]
    {
        tracing::warn!(
            target: "demo_ca",
            "email challenge configured with a real SMTP relay but the `smtp` feature is off; \
             logging codes instead. Rebuild ndn-fwd with --features smtp to deliver email.",
        );
        Arc::new(ndn_identity::LoggingEmailSender)
    }
}
