//! Embedded NDNCERT CA (`[demo_ca]`). Serves `/<prefix>/CA/{INFO,NEW,
//! CHALLENGE/<id>}` and cert-fetch for the certs it issued through an
//! in-process face.
//!
//! By default the CA signs with the identity `[demo_ca].identity` loaded from
//! the node's PIB: the `/<ns>/CA` key plus its certificate
//! `<pib_path>/ca/ca-cert.data` (issued by the hub root), both written by
//! `ndn-fwd init --profile hub`. Issued certs therefore chain to the same root
//! across restarts, and the issued certs, revocations and redeemed one-time
//! tokens (as hashes) persist under `<pib_path>/ca/` ([`FileCaStore`]), so an
//! invite token redeemed before a restart stays spent. `ephemeral = true`
//! mints a throwaway self-signed key at every start instead (demo only,
//! warned; nothing persists).
//!
//! A `device-approval` challenge holds each request in ONE
//! [`PendingApprovalStore`], shared by the challenge, the mgmt
//! `ca list-approvals / approve / deny` backend, and the validated
//! `/<prefix>/CA/APPROVE-FEED` (approvals checked against the node's trust
//! contexts).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_app::{Consumer, Producer};
use ndn_cert::challenge::device_approval::{DeviceApprovalChallenge, PendingApprovalStore};
use ndn_cert::hub::{ANCHOR_CERT_FILE, CA_CERT_FILE, CA_DIR};
use ndn_cert::{
    CaStore, ChallengeHandler, EmailChallenge, EmailSender, FileCaStore, NopChallenge,
    PinChallenge, RequireAttestationKind, TokenChallenge, TokenStore,
};
use ndn_config::DemoCaConfig;
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_identity::{ApprovalFeed, NdncertCa};
use ndn_packet::Name;
use ndn_security::{Certificate, FilePib, KeyChain, SecurityManager, Validator};
use ndn_transport::FaceId;

pub(crate) const DEMO_CA_FACE_ID: u64 = 0xFFFF_0002;
const APPROVE_FEED_FACE_ID: u64 = 0xFFFF_0003;
const APPROVE_SIDE_FACE_ID: u64 = 0xFFFF_0004;

/// Artefacts retained until post-build: the in-process faces' handles, the
/// CA prefix, the signing keychain and the challenge set.
pub(crate) struct DemoCaSpawn {
    pub handle: InProcHandle,
    pub face_id: FaceId,
    /// CA namespace; NDNCERT names are `/<prefix>/CA/...` and issued certs
    /// live under it, so one FIB entry covers both.
    pub prefix: Name,
    /// `/<prefix>/CA/APPROVE-FEED` faces, present with a `device-approval`
    /// challenge.
    pub feed: Option<ApproveFeedFaces>,
    keychain: KeyChain,
    /// `/localhop` trust anchor: the hub root (PIB mode) or the CA's own
    /// self-signed cert (ephemeral mode).
    anchor: Certificate,
    challenges: Vec<Box<dyn ChallengeHandler>>,
    approvals: Option<PendingApprovalStore>,
    store: Option<Arc<FileCaStore>>,
}

pub(crate) struct ApproveFeedFaces {
    pub prefix: Name,
    pub face_id: FaceId,
    handle: InProcHandle,
    side: InProcHandle,
}

/// Validate `[demo_ca]`, load (or, with `ephemeral`, mint) the CA identity and
/// build the challenge set. Returns the faces to attach to the builder and
/// the [`DemoCaSpawn`] retained for post-build FIB wiring and the task spawn.
/// Fails — so the forwarder refuses to start — on a CA with no challenge, a
/// prefix ending in `/CA`, or a missing / inconsistent PIB identity.
/// `pib_path` is the configured `[security] pib_path` (unused when
/// `ephemeral`).
pub(crate) async fn prepare(
    cfg: &DemoCaConfig,
    pib_path: &Path,
) -> Result<(Vec<InProcFace>, DemoCaSpawn)> {
    let prefix = parse_prefix(&cfg.prefix)?;
    let identity: Name = cfg
        .identity
        .parse()
        .with_context(|| format!("[demo_ca] invalid identity '{}'", cfg.identity))?;

    let (keychain, anchor, store) = if cfg.ephemeral {
        tracing::warn!(
            target: "demo_ca",
            identity = %cfg.identity,
            "[demo_ca] ephemeral = true: the CA signs with a throwaway self-signed key minted \
             at startup; every restart creates a new anchor and the certs issued before it \
             stop verifying. Demo only.",
        );
        let keychain = KeyChain::ephemeral(&cfg.identity)
            .with_context(|| format!("[demo_ca] keychain init failed for '{}'", cfg.identity))?;
        let anchor = keychain
            .manager_arc()
            .trust_anchor(keychain.key_name())
            .ok_or_else(|| anyhow::anyhow!("[demo_ca] keychain produced no self-signed anchor"))?;
        (keychain, anchor, None)
    } else {
        // The configured PIB, even if the node identity itself fell back to
        // an ephemeral key: the CA identity is a separate key in it.
        let (keychain, anchor) = load_pib_identity(&identity, pib_path).await?;
        let ca_dir = pib_path.join(CA_DIR);
        let store = FileCaStore::open(&ca_dir)
            .map_err(|e| anyhow::anyhow!("[demo_ca] CA state dir {}: {e}", ca_dir.display()))?;
        tracing::info!(
            target: "demo_ca",
            key = %keychain.key_name(),
            root = %anchor.name,
            state = %ca_dir.display(),
            "CA identity loaded from PIB",
        );
        (keychain, anchor, Some(Arc::new(store)))
    };
    let (challenges, approvals) = build_challenges(cfg, store.as_ref())?;

    let face_id = FaceId(DEMO_CA_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);
    let mut faces = vec![face];

    let feed = if approvals.is_some() {
        let feed_id = FaceId(APPROVE_FEED_FACE_ID);
        let (feed_face, feed_handle) = InProcFace::new(feed_id, 64);
        let (side_face, side_handle) = InProcFace::new(FaceId(APPROVE_SIDE_FACE_ID), 64);
        faces.push(feed_face);
        faces.push(side_face);
        Some(ApproveFeedFaces {
            prefix: prefix.clone().append("CA").append("APPROVE-FEED"),
            face_id: feed_id,
            handle: feed_handle,
            side: side_handle,
        })
    } else {
        None
    };

    Ok((
        faces,
        DemoCaSpawn {
            handle,
            face_id,
            prefix,
            feed,
            keychain,
            anchor,
            challenges,
            approvals,
            store,
        },
    ))
}

/// `[demo_ca].prefix` is the CA namespace; `NdncertCa` appends `/CA` itself
/// (as do clients), so a prefix ending in `CA` would serve `/x/CA/CA/INFO`.
fn parse_prefix(raw: &str) -> Result<Name> {
    let prefix: Name = raw
        .parse()
        .with_context(|| format!("[demo_ca] invalid prefix '{raw}'"))?;
    let comps = prefix.components();
    if comps.last().is_some_and(|c| c.value.as_ref() == b"CA") {
        let parent = Name::from_components(comps[..comps.len() - 1].iter().cloned());
        bail!(
            "[demo_ca] prefix '{raw}' ends in /CA, but the CA appends /CA itself and would \
             serve '{raw}/CA/INFO'; set prefix = \"{parent}\" (the CA identity stays \
             identity = \"{raw}\")"
        );
    }
    Ok(prefix)
}

/// Load the CA signing identity from the PIB: the certificate at
/// `<pib>/ca/ca-cert.data` names the key (`<identity>/KEY/<id>`), whose
/// private half must be in the PIB; the certificate must be signed by the
/// hub root anchor.
async fn load_pib_identity(identity: &Name, pib_path: &Path) -> Result<(KeyChain, Certificate)> {
    let pib = FilePib::open(pib_path).map_err(|e| {
        anyhow::anyhow!(
            "[demo_ca] cannot open PIB {}: {e}; run `ndn-fwd init --profile hub` or set \
             `ephemeral = true` for a throwaway demo CA",
            pib_path.display()
        )
    })?;
    let ca_dir = pib_path.join(CA_DIR);
    let cert_path = ca_dir.join(CA_CERT_FILE);
    let ca_cert = read_cert_wire(&cert_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "[demo_ca] no CA certificate at {}: run `ndn-fwd init --profile hub` to create \
             the CA identity '{identity}', or set `ephemeral = true` for a throwaway demo CA",
            cert_path.display()
        )
    })?;

    let key_name = (*ca_cert.name).clone();
    if !key_name.has_prefix(&identity.clone().append("KEY")) {
        bail!(
            "[demo_ca] {} certifies {key_name}, which is not a key of identity '{identity}'",
            cert_path.display()
        );
    }
    if !ca_cert.is_valid_now() {
        bail!("[demo_ca] CA certificate {key_name} is expired or not yet valid");
    }
    let signer = pib.get_signer(&key_name).map_err(|e| {
        anyhow::anyhow!("[demo_ca] CA key {key_name} not in PIB {}: {e}", pib_path.display())
    })?;
    if signer.public_key().as_deref() != Some(ca_cert.public_key.as_ref()) {
        bail!(
            "[demo_ca] PIB key {key_name} does not match the public key in {}",
            cert_path.display()
        );
    }

    let issuer = ca_cert.issuer.clone().ok_or_else(|| {
        anyhow::anyhow!("[demo_ca] CA certificate {key_name} has no issuer KeyLocator")
    })?;
    let anchor = match read_cert_wire(&ca_dir.join(ANCHOR_CERT_FILE))? {
        Some(anchor) => anchor,
        None => pib
            .trust_anchors()
            .map_err(|e| anyhow::anyhow!("[demo_ca] reading PIB trust anchors: {e}"))?
            .into_iter()
            .find(|a| a.name == issuer)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[demo_ca] CA certificate {key_name} is issued by {issuer}, which is not a \
                     trust anchor in PIB {}",
                    pib_path.display()
                )
            })?,
    };
    if anchor.name != issuer {
        bail!(
            "[demo_ca] CA certificate {key_name} is issued by {issuer}, not by the anchor {}",
            anchor.name
        );
    }
    let (Some(region), Some(sig)) = (&ca_cert.signed_region, &ca_cert.sig_value) else {
        bail!("[demo_ca] CA certificate {key_name} carries no signature");
    };
    let verdict =
        ndn_security::verifier::verify_by_sig_type(ca_cert.sig_type, region, sig, &anchor.public_key)
            .await;
    if !matches!(verdict, Ok(ndn_security::VerifyOutcome::Valid)) {
        bail!("[demo_ca] CA certificate {key_name} is not validly signed by anchor {issuer}");
    }

    let mgr = SecurityManager::new();
    mgr.register_signer(key_name.clone(), signer);
    mgr.cert_cache().insert(ca_cert);
    if !mgr.add_trust_anchor(anchor.clone()) {
        bail!("[demo_ca] root anchor {issuer} is expired or not yet valid");
    }
    Ok((
        KeyChain::from_parts(Arc::new(mgr), identity.clone(), key_name),
        anchor,
    ))
}

/// Decode a certificate stored as a signed Data wire; `None` if absent.
fn read_cert_wire(path: &Path) -> Result<Option<Certificate>> {
    let wire = match std::fs::read(path) {
        Ok(w) => w,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("[demo_ca] reading {}: {e}", path.display())),
    };
    ndn_cert::ca::deserialize_cert(&wire)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("[demo_ca] {} is not a certificate Data", path.display()))
}

/// Add the CA's trust anchor (hub root, or the ephemeral CA's self-signed
/// cert) as a `/localhop` trust anchor and, for in-process operation, share
/// the CA's `Arc<CertCache>` with the validator so newly-issued certs are
/// visible without a network fetch. When `existing` is `Some`, its cache is
/// preserved; the anchor and the CA cert (the chain's middle link) are added.
pub(crate) fn install_localhop_anchor(
    spawn: &DemoCaSpawn,
    existing: Option<Arc<Validator>>,
) -> Result<Arc<Validator>> {
    let manager = spawn.keychain.manager_arc();
    let validator = match existing {
        Some(v) => {
            if let Some(ca_cert) = manager
                .cert_cache()
                .get(&Arc::new(spawn.keychain.key_name().clone()))
            {
                v.cert_cache().insert(ca_cert);
            }
            v
        }
        None => Arc::new(Validator::with_chain(
            ndn_security::TrustSchema::accept_all(),
            manager.cert_cache_arc(),
            Arc::new(dashmap::DashMap::new()),
            None,
            10,
        )),
    };
    if !validator.add_trust_anchor(spawn.anchor.clone()) {
        bail!("[demo_ca] anchor {} is expired or not yet valid", spawn.anchor.name);
    }
    tracing::info!(
        target: "demo_ca",
        anchor = %spawn.anchor.name,
        "installed CA trust anchor as /localhop trust anchor"
    );
    Ok(validator)
}

/// Must run after the FIB entries for `prefix` (and the APPROVE-FEED prefix)
/// are in place. Returns the device-approval store, if any, for the mgmt
/// `ca` backend.
pub(crate) fn spawn(
    prep: DemoCaSpawn,
    cfg: &DemoCaConfig,
    engine: &ForwarderEngine,
) -> Result<Option<PendingApprovalStore>> {
    let identity = ndn_identity::Identity::from_keychain_public(prep.keychain);

    tracing::info!(
        target: "demo_ca",
        challenges = ?prep.challenges.iter().map(|c| c.challenge_type()).collect::<Vec<_>>(),
        "NDNCERT challenge set",
    );

    let mut builder = NdncertCa::builder()
        .name(prep.prefix.to_string())
        .map_err(|e| anyhow::anyhow!("[demo_ca] invalid prefix: {e}"))?
        .info("ndn-fwd NDNCERT CA")
        .signing_identity(&identity)
        .emit_attestations(cfg.emit_attestations);
    if let Some(store) = prep.store {
        builder = builder.store(store);
    }
    for challenge in prep.challenges {
        builder = builder.challenge_box(challenge);
    }

    if let Some(ra) = &cfg.require_attestation {
        let prefix: Name = ra.prefix.parse().with_context(|| {
            format!(
                "[demo_ca] invalid require_attestation prefix '{}'",
                ra.prefix
            )
        })?;
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

    match (prep.feed, &prep.approvals) {
        (Some(feed), Some(store)) => {
            let validator = approval_validator(engine)?;
            let feed_prefix = feed.prefix.to_string();
            let approval_feed = ApprovalFeed::validated(store.clone(), validator);
            let feed_producer = Producer::from_handle(feed.handle, feed.prefix);
            let side = Consumer::from_handle(feed.side);
            tokio::spawn(async move {
                tracing::info!(
                    target: "demo_ca", prefix = %prefix_str, feed = %feed_prefix,
                    "NDNCERT CA serving (with device-approval feed)"
                );
                if let Err(e) = ca
                    .serve_with_feed(producer, approval_feed, feed_producer, side)
                    .await
                {
                    tracing::error!(target: "demo_ca", error = %e, "NDNCERT CA exited");
                }
            });
        }
        _ => {
            tokio::spawn(async move {
                tracing::info!(target: "demo_ca", prefix = %prefix_str, "NDNCERT CA serving");
                if let Err(e) = ca.serve(producer).await {
                    tracing::error!(target: "demo_ca", error = %e, "NDNCERT CA exited");
                }
            });
        }
    }

    Ok(prep.approvals)
}

/// Validator for signed approvals on the APPROVE-FEED: the engine's own
/// validator (its keyring holds the node's adopted trust contexts) or, when
/// the data plane runs without one, a validator over the engine security
/// manager's keyring.
fn approval_validator(engine: &ForwarderEngine) -> Result<Arc<Validator>> {
    if let Some(v) = engine.validator() {
        return Ok(v);
    }
    let mgr = engine.security().ok_or_else(|| {
        anyhow::anyhow!(
            "[demo_ca] device-approval needs the node's trust contexts to validate approvals, \
             but the engine has no security manager"
        )
    })?;
    Ok(Arc::new(Validator::with_keyring(
        Arc::clone(mgr.keyring()),
        mgr.cert_cache_arc(),
        None,
        10,
    )))
}

/// Build the CA's challenge set from config: the `[[demo_ca.challenge]]` list
/// when set, else a `token` challenge from the legacy `tokens`. A CA with
/// neither has no way to authenticate requesters and is refused; `nop`
/// (auto-approve) is only offered when listed explicitly. All
/// `device-approval` entries share one [`PendingApprovalStore`], returned for
/// the mgmt backend and the APPROVE-FEED. With a CA `store` (PIB mode), token
/// redemptions persist in it so a redeemed token is refused after a restart.
fn build_challenges(
    cfg: &DemoCaConfig,
    store: Option<&Arc<FileCaStore>>,
) -> Result<(Vec<Box<dyn ChallengeHandler>>, Option<PendingApprovalStore>)> {
    if !cfg.challenges.is_empty() {
        let mut approvals = None;
        let handlers = cfg
            .challenges
            .iter()
            .map(|c| build_challenge(c, store, &mut approvals))
            .collect::<Result<Vec<_>>>()?;
        return Ok((handlers, approvals));
    }
    if !cfg.tokens.is_empty() {
        let challenge = token_challenge(&cfg.tokens, store)?;
        return Ok((vec![challenge], None));
    }
    bail!(
        "[demo_ca] no challenge configured, so the CA could not authenticate requesters; \
         add `[[demo_ca.challenge]]` entries (kind = \"token\" | \"device-approval\" | \
         \"pin\" | \"email\", or \"nop\" to auto-approve every request in a demo) or \
         `tokens = [...]`"
    )
}

/// A `token` challenge over `tokens`, its redemptions persisted in `store`
/// when one is given.
fn token_challenge(
    tokens: &[String],
    store: Option<&Arc<FileCaStore>>,
) -> Result<Box<dyn ChallengeHandler>> {
    let tokens_store = match store {
        Some(store) => TokenStore::with_store(Arc::clone(store) as Arc<dyn CaStore>)
            .map_err(|e| anyhow::anyhow!("[demo_ca] loading redeemed tokens: {e}"))?,
        None => TokenStore::new(),
    };
    tokens_store.add_many(tokens.iter().cloned());
    Ok(Box::new(TokenChallenge::new(tokens_store)))
}

fn build_challenge(
    c: &ndn_config::ChallengeConfig,
    store: Option<&Arc<FileCaStore>>,
    approvals: &mut Option<PendingApprovalStore>,
) -> Result<Box<dyn ChallengeHandler>> {
    match c.kind.as_str() {
        "nop" => {
            tracing::warn!(
                target: "demo_ca",
                "[demo_ca] `nop` challenge configured: every enrollment request is approved \
                 without authentication. Demo only.",
            );
            Ok(Box::new(NopChallenge::new()))
        }
        "token" => token_challenge(&c.tokens, store),
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
        "device-approval" => {
            let store = approvals.get_or_insert_with(PendingApprovalStore::new).clone();
            Ok(Box::new(DeviceApprovalChallenge::new(store)))
        }
        other => Err(anyhow::anyhow!(
            "[demo_ca] unsupported challenge kind '{other}' \
             (nop|token|pin|email|device-approval; possession/yubikey are wired in code)"
        )),
    }
}

/// Pick the EmailSender for the `email` challenge. With `log_only`, no `host`,
/// or the `smtp` feature disabled, falls back to [`ndn_identity::LoggingEmailSender`]
/// (the code is logged, not delivered). With a real relay configured and the
/// `smtp` feature on, returns the SMTP sender.
fn make_email_sender(smtp: Option<&ndn_config::SmtpConfig>) -> Arc<dyn EmailSender> {
    let wants_real = smtp.is_some_and(|s| !s.log_only && !s.host.is_empty());
    if !wants_real {
        return Arc::new(ndn_identity::LoggingEmailSender);
    }
    #[cfg(feature = "smtp")]
    {
        Arc::new(crate::smtp_email::SmtpEmailSender::new(
            smtp.expect("checked"),
        ))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_cert::CaExchange;
    use ndn_config::ChallengeConfig;
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_identity::NdncertClient;
    use ndn_mgmt::ApprovalMgmtBackend;
    use ndn_security::{Ed25519Signer, Signer, VerifyOutcome};

    use super::*;

    const CLIENT_FACE: u64 = 10;
    /// A PIB path that does not exist (ephemeral CAs never open it).
    fn no_pib() -> &'static Path {
        Path::new("/nonexistent/ndn-fwd-demo-ca-test-pib")
    }

    fn challenge(kind: &str, tokens: &[&str]) -> ChallengeConfig {
        ChallengeConfig {
            kind: kind.to_string(),
            tokens: tokens.iter().map(|t| t.to_string()).collect(),
            pin: None,
            max_tries: None,
            ttl_secs: None,
            smtp: None,
        }
    }

    fn hub_cfg(challenges: Vec<ChallengeConfig>) -> DemoCaConfig {
        DemoCaConfig {
            enabled: true,
            prefix: "/home/bob".to_string(),
            identity: "/home/bob/CA".to_string(),
            challenges,
            ..DemoCaConfig::default()
        }
    }

    /// Provision the PIB exactly as `ndn-fwd init --profile hub` does (root
    /// key + anchor, `/home/bob/CA` key, CA cert issued by the root under
    /// `ca/`). Returns the root anchor.
    fn write_hub_pib(dir: &Path) -> Certificate {
        let pib = FilePib::new(dir).unwrap();
        ndn_cert::init_hub_in_pib(
            &pib,
            &"/home/bob".parse().unwrap(),
            ndn_cert::hub::DEFAULT_NODE_NAME,
            false,
        )
        .expect("hub init");
        read_cert_wire(&dir.join(CA_DIR).join(ANCHOR_CERT_FILE))
            .unwrap()
            .expect("init writes the root anchor cert")
    }

    struct RunningCa {
        client: NdncertClient,
        approvals: Option<PendingApprovalStore>,
        engine: ForwarderEngine,
        shutdown: ShutdownHandle,
    }

    impl RunningCa {
        async fn stop(self) {
            drop(self.client);
            drop(self.engine);
            self.shutdown.shutdown().await;
        }
    }

    /// Boot an engine with the CA wired exactly as `main` does, plus one
    /// client face. The content store is off so every fetch reaches the CA
    /// (a revoked cert would otherwise still be answered from the cache).
    async fn run_ca(cfg: &DemoCaConfig, pib: &Path) -> RunningCa {
        let (faces, spawn_state) = prepare(cfg, pib).await.expect("CA prepares");
        let (client_face, client_handle) = InProcFace::new(FaceId(CLIENT_FACE), 64);
        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(client_face);
        for face in faces {
            builder = builder.face(face);
        }
        let (engine, shutdown) = builder.build().await.expect("engine builds");
        engine.cs().set_admit(false);
        engine.cs().set_serve(false);
        engine
            .fib()
            .add_nexthop(&spawn_state.prefix, spawn_state.face_id, 0);
        if let Some(feed) = &spawn_state.feed {
            engine.fib().add_nexthop(&feed.prefix, feed.face_id, 0);
        }
        let prefix = spawn_state.prefix.clone();
        let approvals = spawn(spawn_state, cfg, &engine).expect("CA spawns");
        RunningCa {
            client: NdncertClient::new(Consumer::from_handle(client_handle), prefix),
            approvals,
            engine,
            shutdown,
        }
    }

    /// Enroll `/home/bob/<who>` over the CA's NDN face, re-polling pending
    /// CHALLENGE rounds (device-approval) every 20 ms.
    async fn enroll(
        client: &mut NdncertClient,
        who: &str,
        kind: &str,
        params: serde_json::Map<String, serde_json::Value>,
    ) -> std::result::Result<ndn_packet::Data, ndn_cert::CertError> {
        let signer = device_signer(who);
        let ca_prefix: Name = "/home/bob".parse().unwrap();
        let cert_name = ndn_cert::client::enroll(client, &ca_prefix, signer, 86_400, kind, |r| {
            let params = params.clone();
            async move {
                if r.round > 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok((r.round < 250).then_some(params))
            }
        })
        .await?;
        ndn_cert::client::fetch_issued_cert(client, &cert_name).await
    }

    fn token(t: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("token".into(), serde_json::Value::String(t.into()));
        m
    }

    /// The key `enroll` uses for `/home/bob/<who>`.
    fn device_signer(who: &str) -> Arc<dyn Signer> {
        let key: Name = format!("/home/bob/{who}/KEY/k1").parse().unwrap();
        Arc::new(Ed25519Signer::from_seed(&[7; 32], key))
    }

    /// Whether the CA itself (not the engine's content store, hence
    /// MustBeFresh) answers a cert-fetch for `name`.
    async fn ca_serves(client: &mut NdncertClient, name: &Name) -> bool {
        let interest = ndn_packet::encode::InterestBuilder::new(name.clone())
            .must_be_fresh()
            .build();
        matches!(
            tokio::time::timeout(Duration::from_millis(500), client.express(interest)).await,
            Ok(Ok(_))
        )
    }

    async fn revoke_as(
        client: &mut NdncertClient,
        cert: &Name,
        signer: Arc<dyn Signer>,
    ) -> ndn_cert::RevokeStatus {
        ndn_cert::client::revoke(client, &"/home/bob".parse().unwrap(), cert, signer)
            .await
            .expect("CA answers REVOKE")
    }

    /// A one-time token redeemed before a restart must stay spent although
    /// it is still listed in the config; only its hash is persisted.
    #[tokio::test]
    async fn redeemed_token_is_refused_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_hub_pib(dir.path());
        let cfg = hub_cfg(vec![challenge("token", &["invite-1", "invite-2"])]);

        let mut ca = run_ca(&cfg, dir.path()).await;
        enroll(&mut ca.client, "laptop", "token", token("invite-1"))
            .await
            .expect("first redemption enrolls");
        ca.stop().await;

        let mut ca = run_ca(&cfg, dir.path()).await;
        let replay = enroll(&mut ca.client, "phone", "token", token("invite-1")).await;
        assert!(replay.is_err(), "redeemed token must be refused after restart: {replay:?}");
        enroll(&mut ca.client, "phone", "token", token("invite-2"))
            .await
            .expect("an unredeemed token still works");
        ca.stop().await;

        let redeemed = dir.path().join(CA_DIR).join("redeemed-tokens");
        let entries: Vec<_> = redeemed.read_dir().unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(entries.len(), 2);
        for path in entries {
            let stored = std::fs::read_to_string(path).unwrap();
            assert!(!stored.contains("invite"), "raw token stored: {stored}");
        }
    }

    /// NDNCERT REVOKE over NDN: an unrelated key is refused; the holder's
    /// revocation is persisted, the CA stops serving the cert, and after a
    /// restart it still refuses it (no fetch, no re-enrollment of the key).
    /// The CA identity may revoke any cert it issued.
    #[tokio::test]
    async fn revoke_over_ndn_by_holder_or_ca_only() {
        let dir = tempfile::tempdir().unwrap();
        write_hub_pib(dir.path());
        let cfg = hub_cfg(vec![challenge("token", &["invite-1", "invite-2", "invite-3"])]);

        let mut ca = run_ca(&cfg, dir.path()).await;
        let laptop = enroll(&mut ca.client, "laptop", "token", token("invite-1"))
            .await
            .expect("laptop enrolls");
        let laptop = (*laptop.name).clone();
        let phone = enroll(&mut ca.client, "phone", "token", token("invite-2"))
            .await
            .expect("phone enrolls");
        let phone = (*phone.name).clone();

        let mallory = Arc::new(Ed25519Signer::from_seed(
            &[9; 32],
            "/home/bob/mallory/KEY/k1".parse().unwrap(),
        ));
        assert_eq!(
            revoke_as(&mut ca.client, &laptop, mallory).await,
            ndn_cert::RevokeStatus::Unauthorized
        );
        assert!(ca_serves(&mut ca.client, &laptop).await, "refused REVOKE changes nothing");

        assert_eq!(
            revoke_as(&mut ca.client, &laptop, device_signer("laptop")).await,
            ndn_cert::RevokeStatus::Revoked
        );
        assert!(!ca_serves(&mut ca.client, &laptop).await, "revoked cert is not served");
        assert_eq!(
            dir.path().join(CA_DIR).join("revoked").read_dir().unwrap().count(),
            1,
            "revocation persisted"
        );

        // The CA identity revokes a cert it issued.
        let pib = FilePib::open(dir.path()).unwrap();
        let ca_key = ndn_cert::ca_key_name(&"/home/bob".parse().unwrap());
        let ca_signer = pib.get_signer(&ca_key).unwrap();
        assert_eq!(
            revoke_as(&mut ca.client, &phone, ca_signer).await,
            ndn_cert::RevokeStatus::Revoked
        );
        ca.stop().await;

        let mut ca = run_ca(&cfg, dir.path()).await;
        assert!(!ca_serves(&mut ca.client, &laptop).await, "still revoked after restart");
        assert!(!ca_serves(&mut ca.client, &phone).await, "still revoked after restart");
        let again = enroll(&mut ca.client, "laptop", "token", token("invite-3")).await;
        assert!(again.is_err(), "a revoked key is not re-certified: {again:?}");
        ca.stop().await;
    }

    async fn signed_by(data: &ndn_packet::Data, signer_key: &[u8]) -> bool {
        let sig_type = data.sig_info().map(|s| s.sig_type).unwrap();
        matches!(
            ndn_security::verifier::verify_by_sig_type(
                sig_type,
                data.signed_region(),
                data.sig_value(),
                signer_key,
            )
            .await,
            Ok(VerifyOutcome::Valid)
        )
    }

    #[tokio::test]
    async fn ca_without_challenges_refuses_to_start() {
        let cfg = DemoCaConfig {
            enabled: true,
            ephemeral: true,
            ..DemoCaConfig::default()
        };
        let err = prepare(&cfg, no_pib())
            .await
            .err()
            .expect("no-challenge CA must not start");
        assert!(
            err.to_string().contains("no challenge configured"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn nop_is_only_offered_when_listed() {
        let mut cfg = hub_cfg(vec![challenge("nop", &[])]);
        cfg.ephemeral = true;
        let (_, spawn_state) = prepare(&cfg, no_pib()).await.expect("explicit nop is allowed");
        let kinds: Vec<_> = spawn_state
            .challenges
            .iter()
            .map(|c| c.challenge_type())
            .collect();
        assert_eq!(kinds, ["nop"]);
    }

    #[tokio::test]
    async fn prefix_ending_in_ca_is_rejected() {
        let mut cfg = hub_cfg(vec![challenge("nop", &[])]);
        cfg.ephemeral = true;
        cfg.prefix = "/home/bob/CA".to_string();
        let err = prepare(&cfg, no_pib()).await.err().expect("/CA prefix rejected");
        assert!(err.to_string().contains("ends in /CA"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn pib_ca_without_hub_identity_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        FilePib::new(dir.path()).unwrap();
        let cfg = hub_cfg(vec![challenge("token", &["t"])]);
        let err = prepare(&cfg, dir.path())
            .await
            .err()
            .expect("missing CA cert must fail startup");
        assert!(err.to_string().contains("no CA certificate"), "unexpected error: {err}");
        let err = prepare(&cfg, no_pib())
            .await
            .err()
            .expect("a PIB-backed CA without a PIB must fail startup");
        assert!(err.to_string().contains("cannot open PIB"), "unexpected error: {err}");
    }

    /// Restart with the same PIB: the CA signs with the same root-certified
    /// key, still serves the cert it issued before the restart, and new
    /// certs chain to the same root.
    #[tokio::test]
    async fn pib_backed_ca_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_hub_pib(dir.path());
        let cfg = hub_cfg(vec![challenge("token", &["invite-1", "invite-2"])]);
        let ca_cert = read_cert_wire(&dir.path().join(CA_DIR).join(CA_CERT_FILE))
            .unwrap()
            .unwrap();

        let mut ca = run_ca(&cfg, dir.path()).await;
        let first = enroll(&mut ca.client, "laptop", "token", token("invite-1"))
            .await
            .expect("first enrollment");
        ca.stop().await;

        let mut ca = run_ca(&cfg, dir.path()).await;
        let refetched = ca
            .client
            .express(ndn_packet::encode::InterestBuilder::new((*first.name).clone()).build())
            .await
            .expect("cert issued before the restart is still served");
        assert_eq!(refetched.raw(), first.raw());

        let second = enroll(&mut ca.client, "phone", "token", token("invite-2"))
            .await
            .expect("enrollment after restart");
        for issued in [&first, &second] {
            let cert = Certificate::decode(issued).unwrap();
            assert_eq!(cert.issuer.as_deref(), Some(&*ca_cert.name));
            assert!(signed_by(issued, &ca_cert.public_key).await);
        }
        let ca_data = ndn_packet::Data::decode(bytes::Bytes::from(
            ndn_cert::ca::serialize_cert(&ca_cert),
        ))
        .unwrap();
        assert!(signed_by(&ca_data, &root.public_key).await, "CA cert chains to root");
        assert!(dir.path().join(CA_DIR).join("issued").read_dir().unwrap().count() >= 2);
        ca.stop().await;
    }

    fn ephemeral_approval_cfg() -> DemoCaConfig {
        let mut cfg = hub_cfg(vec![challenge("device-approval", &[])]);
        cfg.ephemeral = true;
        cfg
    }

    /// Resolve the first pending request through the mgmt backend the
    /// forwarder registers (`approval_handler`).
    fn resolve_via_mgmt(store: PendingApprovalStore, approve: bool) -> tokio::task::JoinHandle<()> {
        let mgmt: Arc<dyn ApprovalMgmtBackend> = Arc::new(store);
        tokio::spawn(async move {
            loop {
                if let Some(req) = mgmt.pending().into_iter().next() {
                    assert!(req.cert_name.starts_with("/home/bob/tablet"));
                    let done = if approve {
                        mgmt.approve(&req.id, "approved-via-mgmt")
                    } else {
                        mgmt.deny(&req.id, "not my device")
                    };
                    assert!(done);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    }

    #[tokio::test]
    async fn device_approval_approved_via_mgmt_completes_enrollment() {
        let cfg = ephemeral_approval_cfg();
        let mut ca = run_ca(&cfg, no_pib()).await;
        let store = ca.approvals.clone().expect("device-approval store is exposed");
        let approver = resolve_via_mgmt(store.clone(), true);

        let issued = enroll(
            &mut ca.client,
            "tablet",
            "device-approval",
            serde_json::Map::new(),
        )
        .await
        .expect("approved request enrolls");
        approver.await.unwrap();
        assert!(issued.name.to_string().starts_with("/home/bob/tablet"));
        assert!(store.pending().is_empty());
        ca.stop().await;
    }

    #[tokio::test]
    async fn device_approval_denied_via_mgmt_fails_enrollment() {
        let cfg = ephemeral_approval_cfg();
        let mut ca = run_ca(&cfg, no_pib()).await;
        let approver = resolve_via_mgmt(ca.approvals.clone().unwrap(), false);

        let result = enroll(
            &mut ca.client,
            "tablet",
            "device-approval",
            serde_json::Map::new(),
        )
        .await;
        approver.await.unwrap();
        assert!(result.is_err(), "denied request must not enroll: {result:?}");
        ca.stop().await;
    }
}
