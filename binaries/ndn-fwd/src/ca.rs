//! Embedded NDNCERT CAs (`[ca]`, or one `[[ca]]` table per CA). Each serves
//! `/<prefix>/CA/{INFO,NEW,CHALLENGE/<id>}` and cert-fetch for the certs it
//! issued through its own in-process face; a device that is the root of
//! several trusted prefixes runs the CA of each.
//!
//! By default a CA signs with the identity `identity` of its entry loaded
//! from the node's PIB: the `/<ns>/CA` key plus its certificate
//! `ca-cert.data` (issued by the namespace root) in the CA's directory
//! ([`ndn_cert::ca_dir_of`]: `<pib_path>/ca/<hex of the namespace URI>/`, or
//! `<pib_path>/ca/` for the CA a PIB from before several CAs holds), both
//! written by `ndn-fwd init --namespace <ns>`. Issued certs therefore chain
//! to the same root across restarts, and the issued certs, revocations and
//! invites (with a hash of their token, never the token) persist in that
//! directory ([`FileCaStore`]), so an invite made before a restart is still
//! redeemable after it and one redeemed stays spent. `ephemeral = true`
//! mints a throwaway self-signed key at every start instead (demo only,
//! warned; nothing persists).
//!
//! A PIB-backed CA identity `/<ns>/CA` serves the namespace `/<ns>`:
//! issuance follows the role layout ([`RolePolicy`]) — device keys
//! `/<ns>/<role>/<device>/KEY/…` only; the roles the namespace's trust
//! context certifies on an admin's approval (its enrollment hint, default
//! `admin` and `node`; [`ApprovalPolicy`]) need one, invites admit members
//! and guests. Every CA offers the `token` challenge over its invites
//! ([`CaInvites`]): a trust administrator makes them at runtime through the
//! management verbs `ca/invite-create|list|withdraw` (`ndn-fwd-tokens`), each
//! scoped to `/<ns>/<role>`, so it cannot certify any other role. Each role's
//! certificates last its `[ca] cert_validity_days`, and a device holding a
//! current certificate of a role in `[ca] renewable_roles` renews it without
//! an invite (the CA's built-in `renewal` challenge; [`ndn_cert::renewal`]) —
//! also a certificate an earlier CA of the same identity issued (the CA of a
//! root device replaced through a recovery kit) when it chains to the
//! namespace root under the node's trust contexts; the CA then serves that
//! earlier CA's certificate.
//!
//! Enrollment by an admin's approval ([`ndn_cert::approval`]): the
//! `device-approval` challenge — offered by a namespace CA whether listed or
//! not — keeps one durable record per requesting key in an
//! [`ApprovalStore`] persisted under `approvals/` of the CA's directory, so a pending
//! request survives a restart of the CA. The same store backs the mgmt `ca
//! list-approvals / approve / deny` verbs (the CA host's local operator) and
//! `/<prefix>/CA/APPROVAL` + `/<prefix>/CA/PENDING` (an admin device's signed
//! decisions, validated under the node's trust contexts). The policy is the
//! one the namespace's trust context advertises: `[ca] approval_roles` /
//! `approval_requires_invite`, when set, must agree with it, or the CA
//! refuses to start.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_app::Producer;
use ndn_cert::approval::{ApprovalStore, DEVICE_APPROVAL};
use ndn_cert::challenge::device_approval::DeviceApprovalChallenge;
use ndn_cert::namespace::{ANCHOR_CERT_FILE, CA_CERT_FILE};
use ndn_cert::roles::Role;
use ndn_cert::{
    AllIssuance, ApprovalPolicy, CaInvites, CaStore, ChallengeHandler, ChallengeSlot,
    EmailChallenge, EmailSender, FileCaStore, InviteIssuer, IssuancePolicy, NopChallenge,
    PinChallenge, RequireAttestationKind, RolePolicy, TokenChallenge, TokenStore,
};
use ndn_config::CaTomlConfig;
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_identity::NdncertCa;
use ndn_packet::Name;
use ndn_security::{
    Certificate, FilePib, KeyChain, SecurityManager, SignedTrustContext, Validator,
};
use ndn_transport::FaceId;

/// The in-process face of the `index`-th configured CA: fixed, like the
/// other in-process faces of the daemon, one per CA.
pub(crate) fn ca_face_id(index: usize) -> FaceId {
    FaceId(CA_FACE_ID_BASE + index as u64)
}

/// The face of the first CA; the next ones follow ([`ca_face_id`]).
const CA_FACE_ID_BASE: u64 = 0xFFFF_0100;
/// The most CAs one daemon runs (the face ids reserved for them).
pub(crate) const MAX_CAS: usize = 0x100;

/// [`prepare`] every enabled CA of `cas`, in config order: each with its
/// own face. An error names the CA it is about.
pub(crate) async fn prepare_all(
    cas: &[CaTomlConfig],
    pib_path: &Path,
) -> Result<Vec<(Vec<InProcFace>, CaSpawn)>> {
    let enabled: Vec<&CaTomlConfig> = cas.iter().filter(|c| c.enabled).collect();
    if enabled.len() > MAX_CAS {
        bail!(
            "{} CAs are enabled; one daemon runs at most {MAX_CAS}",
            enabled.len()
        );
    }
    let mut prepared = Vec::with_capacity(enabled.len());
    for (index, cfg) in enabled.into_iter().enumerate() {
        prepared.push(
            prepare(cfg, index, pib_path)
                .await
                .with_context(|| format!("the CA {} ({})", cfg.identity, cfg.prefix))?,
        );
    }
    Ok(prepared)
}

/// Artefacts retained until post-build: the in-process face's handle, the
/// CA prefix, its configuration entry, the signing keychain and the
/// challenge set.
pub(crate) struct CaSpawn {
    pub handle: InProcHandle,
    pub face_id: FaceId,
    /// CA namespace; NDNCERT names are `/<prefix>/CA/...` and issued certs
    /// live under it, so one FIB entry covers both.
    pub prefix: Name,
    /// Its `[ca]` / `[[ca]]` entry.
    cfg: CaTomlConfig,
    keychain: KeyChain,
    /// `/localhop` trust anchor: the namespace root (PIB mode) or the CA's own
    /// self-signed cert (ephemeral mode).
    anchor: Certificate,
    /// The namespace this CA serves (`/<ns>` of a PIB-backed
    /// `/<ns>/CA` identity): issuance follows its role layout. `None` for an
    /// ephemeral demo CA, which keeps accepting any challenge-passing name.
    namespace: Option<Name>,
    /// What needs an admin's approval: what the namespace's trust context
    /// advertises (a namespace CA only).
    approval_policy: Option<ApprovalPolicy>,
    challenges: Vec<Box<dyn ChallengeHandler>>,
    /// The device-approval records; main gives them the change observer
    /// before the CA runs.
    pub approvals: Option<ApprovalStore>,
    /// The CA's invites, which its `token` challenge redeems (persisted in
    /// `store` on a PIB-backed CA); main gives them the change observer
    /// and the `ca/invite-*` verbs.
    pub invites: CaInvites,
    store: Option<Arc<FileCaStore>>,
}

/// Validate one `[ca]` / `[[ca]]` entry, load (or, with `ephemeral`, mint)
/// the CA identity and build the challenge set. Returns the face to attach
/// to the builder (the `index`-th CA's, [`ca_face_id`]) and the
/// [`CaSpawn`] retained for post-build FIB wiring and the task spawn.
/// Fails — so the forwarder refuses to start — on a prefix ending in `/CA`,
/// a missing / inconsistent PIB identity, or an
/// approval policy in the entry that disagrees with the namespace's trust
/// context. `pib_path` is the configured `[security] pib_path` (unused when
/// `ephemeral`).
pub(crate) async fn prepare(
    cfg: &CaTomlConfig,
    index: usize,
    pib_path: &Path,
) -> Result<(Vec<InProcFace>, CaSpawn)> {
    let prefix = parse_prefix(&cfg.prefix)?;
    // Refuse a lifetime or role the CA could not issue with before anything
    // starts (the role policy is built again at spawn).
    role_policy(prefix.clone(), cfg)?;
    let identity: Name = cfg
        .identity
        .parse()
        .with_context(|| format!("[ca] invalid identity '{}'", cfg.identity))?;

    let (keychain, anchor, store, namespace) = if cfg.ephemeral {
        tracing::warn!(
            target: "ca",
            identity = %cfg.identity,
            "[ca] ephemeral = true: the CA signs with a throwaway self-signed key minted \
             at startup; every restart creates a new anchor and the certs issued before it \
             stop verifying. Demo only.",
        );
        let keychain = KeyChain::ephemeral(&cfg.identity)
            .with_context(|| format!("[ca] keychain init failed for '{}'", cfg.identity))?;
        let anchor = keychain
            .manager_arc()
            .trust_anchor(keychain.key_name())
            .ok_or_else(|| anyhow::anyhow!("[ca] keychain produced no self-signed anchor"))?;
        (keychain, anchor, None, None)
    } else {
        // The configured PIB, even if the node identity itself fell back to
        // an ephemeral key: the CA identity is a separate key in it.
        let (keychain, anchor) = load_pib_identity(&identity, pib_path).await?;
        let ca_dir = ndn_cert::ca_dir_of(pib_path, &identity);
        let store = FileCaStore::open(&ca_dir)
            .map_err(|e| anyhow::anyhow!("[ca] CA state dir {}: {e}", ca_dir.display()))?;
        // A namespace CA: identity `/<ns>/CA` certified by the namespace root `/<ns>/KEY/…`.
        let namespace =
            namespace_of(&identity).filter(|ns| anchor.name.has_prefix(&ns.clone().append("KEY")));
        tracing::info!(
            target: "ca",
            key = %keychain.key_name(),
            root = %anchor.name,
            state = %ca_dir.display(),
            namespace = ?namespace.as_ref().map(Name::to_string),
            "CA identity loaded from PIB",
        );
        (keychain, anchor, Some(Arc::new(store)), namespace)
    };
    // Invite links name the CA, the namespace and, on a namespace CA, the
    // fingerprint of its root anchor (the invitee adopts that context).
    let invites = CaInvites::new(
        token_store(store.as_ref())?,
        InviteIssuer {
            ca_prefix: prefix.clone(),
            namespace: namespace.clone().unwrap_or_else(|| prefix.clone()),
            expected_fingerprint: namespace
                .is_some()
                .then(|| ndn_security::anchor_fingerprint(&anchor)),
        },
    );
    let approval_policy = match &namespace {
        Some(ns) => {
            let held = newest_context(pib_path, ns)?;
            Some(cfg.policy_input()?.enforced_policy(held.as_ref())?)
        }
        None => None,
    };
    let ttl = days(cfg.approval_request_ttl_days);
    if ttl.is_zero() {
        bail!(
            "[ca] approval_request_ttl_days = 0 would expire every request for an admin's \
             approval at once; set how many days a request waits for a decision (default {})",
            CaTomlConfig::DEFAULT_APPROVAL_REQUEST_TTL_DAYS
        );
    }
    let approval_store = || match &store {
        Some(store) => ApprovalStore::with_store(
            prefix.clone(),
            namespace.clone(),
            ttl,
            Arc::clone(store) as Arc<dyn CaStore>,
        )
        .map_err(|e| anyhow::anyhow!("[ca] loading the approval requests: {e}")),
        None => Ok(ApprovalStore::new(prefix.clone(), namespace.clone(), ttl)),
    };
    let Challenges {
        handlers: challenges,
        approvals,
    } = build_challenges(
        cfg,
        invites.tokens(),
        approval_policy
            .as_ref()
            .map(|p| (namespace.as_ref().unwrap_or(&prefix), p)),
        approval_store,
    )?;

    let face_id = ca_face_id(index);
    let (face, handle) = InProcFace::new(face_id, 64);

    Ok((
        vec![face],
        CaSpawn {
            handle,
            face_id,
            prefix,
            cfg: cfg.clone(),
            keychain,
            anchor,
            namespace,
            approval_policy,
            challenges,
            approvals,
            invites,
            store,
        },
    ))
}

/// The newest stored trust context of `namespace`; `None` when none is
/// stored.
fn newest_context(pib_path: &Path, namespace: &Name) -> Result<Option<SignedTrustContext>> {
    let stored = ndn_cert::read_stored_contexts(pib_path)
        .map_err(|e| anyhow::anyhow!("[ca] reading the stored trust contexts: {e}"))?;
    Ok(stored
        .into_iter()
        .filter_map(|(_, ctx)| ctx.ok())
        .filter(|(ctx, _)| ctx.namespace() == namespace)
        .max_by_key(|(ctx, _)| ctx.version())
        .map(|(ctx, _)| ctx))
}

/// `[ca].prefix` is the CA namespace; `NdncertCa` appends `/CA` itself
/// (as do clients), so a prefix ending in `CA` would serve `/x/CA/CA/INFO`.
fn parse_prefix(raw: &str) -> Result<Name> {
    let prefix: Name = raw
        .parse()
        .with_context(|| format!("[ca] invalid prefix '{raw}'"))?;
    let comps = prefix.components();
    if comps.last().is_some_and(|c| c.value.as_ref() == b"CA") {
        let parent = Name::from_components(comps[..comps.len() - 1].iter().cloned());
        bail!(
            "[ca] prefix '{raw}' ends in /CA, but the CA appends /CA itself and would \
             serve '{raw}/CA/INFO'; set prefix = \"{parent}\" (the CA identity stays \
             identity = \"{raw}\")"
        );
    }
    Ok(prefix)
}

/// A day as a `Duration`.
fn days(n: u32) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(n) * 86_400)
}

/// The namespace CA's issuance by role: each role's certificates last its
/// `[ca] cert_validity_days`; the roles in `[ca] renewable_roles` renew.
/// Refuses a lifetime of 0 days and an unknown role name.
fn role_policy(namespace: Name, cfg: &CaTomlConfig) -> Result<RolePolicy> {
    let lifetimes = &cfg.cert_validity_days;
    if lifetimes.default == 0
        || Role::ALL
            .iter()
            .any(|r| lifetimes.for_role(r.as_str()) == 0)
    {
        bail!(
            "[ca] cert_validity_days: 0 days would issue certificates that are already \
             expired; set the lifetime of issued certificates in days (default {})",
            CaTomlConfig::DEFAULT_CERT_VALIDITY_DAYS
        );
    }
    let renewable = cfg
        .renewable_roles
        .iter()
        .map(|r| {
            r.parse::<Role>()
                .map_err(|e| anyhow::anyhow!("[ca] renewable_roles: {e}"))
        })
        .collect::<Result<Vec<Role>>>()?;
    Ok(Role::ALL
        .into_iter()
        .fold(RolePolicy::new(namespace), |policy, role| {
            policy
                .with_validity(role, days(lifetimes.for_role(role.as_str())))
                .with_renewable(role, renewable.contains(&role))
        }))
}

/// The namespace a CA identity `/<ns>/CA` serves: `/<ns>`.
fn namespace_of(identity: &Name) -> Option<Name> {
    let comps = identity.components();
    let (last, parent) = comps.split_last()?;
    (last.value.as_ref() == b"CA" && !parent.is_empty())
        .then(|| Name::from_components(parent.iter().cloned()))
}

/// Load the CA signing identity from the PIB: the certificate
/// `ca-cert.data` in the CA's directory ([`ndn_cert::ca_dir_of`];
/// `<identity>/KEY/<id>/<issuer>/<version>`) names the key, whose private
/// half must be in the PIB; the certificate must be signed by the namespace
/// root anchor (the key its KeyLocator names).
async fn load_pib_identity(identity: &Name, pib_path: &Path) -> Result<(KeyChain, Certificate)> {
    let pib = FilePib::open(pib_path).map_err(|e| {
        anyhow::anyhow!(
            "[ca] cannot open PIB {}: {e}; run `ndn-fwd init --namespace <ns>` or set \
             `ephemeral = true` for a throwaway demo CA",
            pib_path.display()
        )
    })?;
    let ca_dir = ndn_cert::ca_dir_of(pib_path, identity);
    let cert_path = ca_dir.join(CA_CERT_FILE);
    let ca_cert = read_cert_wire(&cert_path)?.ok_or_else(|| {
        let ns = namespace_of(identity).map_or_else(|| "<ns>".to_string(), |n| n.to_string());
        anyhow::anyhow!(
            "[ca] no CA certificate at {}: run `ndn-fwd init --namespace {ns}` to create \
             the CA identity '{identity}', or set `ephemeral = true` for a throwaway demo CA",
            cert_path.display()
        )
    })?;

    let cert_name = (*ca_cert.name).clone();
    let key_name = ca_cert.key_name();
    if !key_name.has_prefix(&identity.clone().append("KEY")) {
        bail!(
            "[ca] {} certifies {key_name}, which is not a key of identity '{identity}'",
            cert_path.display()
        );
    }
    if !ca_cert.is_valid_now() {
        bail!("[ca] CA certificate {cert_name} is expired or not yet valid");
    }
    let signer = pib.get_signer(&key_name).map_err(|e| {
        anyhow::anyhow!(
            "[ca] CA key {key_name} not in PIB {}: {e}",
            pib_path.display()
        )
    })?;
    if signer.public_key().as_deref() != Some(ca_cert.public_key.as_ref()) {
        bail!(
            "[ca] PIB key {key_name} does not match the public key in {}",
            cert_path.display()
        );
    }

    let issuer = ca_cert.issuer.clone().ok_or_else(|| {
        anyhow::anyhow!("[ca] CA certificate {cert_name} has no issuer KeyLocator")
    })?;
    // The KeyLocator names the root key (or one certificate of it).
    let issuer_key = ndn_security::cert_name::key_name_of(&issuer);
    let anchor = match read_cert_wire(&ca_dir.join(ANCHOR_CERT_FILE))? {
        Some(anchor) => anchor,
        None => pib
            .trust_anchors()
            .map_err(|e| anyhow::anyhow!("[ca] reading PIB trust anchors: {e}"))?
            .into_iter()
            .find(|a| a.key_name() == issuer_key)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[ca] CA certificate {cert_name} is issued by {issuer}, which is not a \
                     trust anchor in PIB {}",
                    pib_path.display()
                )
            })?,
    };
    if anchor.key_name() != issuer_key {
        bail!(
            "[ca] CA certificate {cert_name} is issued by {issuer}, not by the anchor {}",
            anchor.name
        );
    }
    let (Some(region), Some(sig)) = (&ca_cert.signed_region, &ca_cert.sig_value) else {
        bail!("[ca] CA certificate {cert_name} carries no signature");
    };
    let verdict = ndn_security::verifier::verify_by_sig_type(
        ca_cert.sig_type,
        region,
        sig,
        &anchor.public_key,
    )
    .await;
    if !matches!(verdict, Ok(ndn_security::VerifyOutcome::Valid)) {
        bail!("[ca] CA certificate {cert_name} is not validly signed by anchor {issuer}");
    }

    let mgr = SecurityManager::new();
    mgr.register_signer(key_name.clone(), signer);
    mgr.cert_cache().insert(ca_cert);
    if !mgr.add_trust_anchor(anchor.clone()) {
        bail!("[ca] root anchor {issuer} is expired or not yet valid");
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
        Err(e) => return Err(anyhow::anyhow!("[ca] reading {}: {e}", path.display())),
    };
    ndn_cert::ca::deserialize_cert(&wire)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("[ca] {} is not a certificate Data", path.display()))
}

/// Add the CA's trust anchor (namespace root, or the ephemeral CA's self-signed
/// cert) as a `/localhop` trust anchor and, for in-process operation, share
/// the CA's `Arc<CertCache>` with the validator so newly-issued certs are
/// visible without a fetch over NDN. When `existing` is `Some`, its cache is
/// preserved; the anchor and the CA cert (the chain's middle link) are added.
pub(crate) fn install_localhop_anchor(
    spawn: &CaSpawn,
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
        bail!(
            "[ca] anchor {} is expired or not yet valid",
            spawn.anchor.name
        );
    }
    tracing::info!(
        target: "ca",
        anchor = %spawn.anchor.name,
        "installed CA trust anchor as /localhop trust anchor"
    );
    Ok(validator)
}

/// The CA once spawned: its approval store (with a `device-approval`
/// challenge) for the mgmt `ca` module, its state, which `ndn-fwd revoke`
/// administers directly, and its approval service, whose held status
/// Interests the daemon answers when it stops
/// ([`ndn_cert::ApprovalService::release_held`]).
pub(crate) struct RunningCa {
    pub approvals: Option<ApprovalStore>,
    pub state: Arc<ndn_cert::CaState>,
    pub status: Option<ndn_cert::ApprovalService>,
}

/// Must run after the FIB entry for `prefix` is in place.
pub(crate) fn spawn(prep: CaSpawn, engine: &ForwarderEngine) -> Result<RunningCa> {
    let cfg = &prep.cfg;
    let identity = ndn_identity::Identity::from_keychain_public(prep.keychain);
    tracing::info!(
        target: "ca",
        challenges = ?prep.challenges.iter().map(|c| c.challenge_type()).collect::<Vec<_>>(),
        "NDNCERT challenge set",
    );

    // A request that names no lifetime (what `ndn-fwd enroll`, `ndn-fwd
    // renew` and the mobile enroll send) gets its role's `cert_validity_days`
    // (the default for a CA without the role layout), and INFO advertises the
    // longest as the maximum.
    let lifetimes = &cfg.cert_validity_days;
    let mut builder = NdncertCa::builder()
        .name(prep.prefix.to_string())
        .map_err(|e| anyhow::anyhow!("[ca] invalid prefix: {e}"))?
        .info("ndn-fwd NDNCERT CA")
        .signing_identity(&identity)
        .emit_attestations(cfg.emit_attestations)
        .cert_lifetime(days(lifetimes.default))
        .max_cert_lifetime(days(lifetimes.max_days()));
    if let Some(store) = prep.store {
        builder = builder.store(store);
    }
    for challenge in prep.challenges {
        builder = builder.challenge_box(challenge);
    }

    let mut issuance: Vec<Box<dyn IssuancePolicy>> = Vec::new();
    if let Some(namespace) = prep.namespace {
        let approval = prep.approval_policy.clone().unwrap_or_default();
        let policy = role_policy(namespace.clone(), cfg)?.with_approval(approval.clone());
        let terms: Vec<String> = Role::ALL
            .iter()
            .map(|&role| {
                let t = policy.terms(role);
                let days = t.validity.map_or(0, |v| v.as_secs() / 86_400);
                let renew = if t.renewable {
                    "renewable"
                } else {
                    "not renewable"
                };
                format!("{role} {days}d {renew}")
            })
            .collect();
        tracing::info!(
            target: "ca",
            namespace = %namespace,
            roles = %terms.join(", "),
            enrollment = %approval.describe(),
            approval_request_ttl_days = cfg.approval_request_ttl_days,
            "issuance follows the role layout: <namespace>/<role>/<device>/KEY/...; a current \
             certificate of a renewable role renews without an invite",
        );
        issuance.push(Box::new(policy));
    }
    if let Some(ra) = &cfg.require_attestation {
        let prefix: Name = ra
            .prefix
            .parse()
            .with_context(|| format!("[ca] invalid require_attestation prefix '{}'", ra.prefix))?;
        issuance.push(Box::new(
            RequireAttestationKind::new(prefix, ra.kind.clone())
                .require_signed(ra.require_signed)
                .accept_local_operator(ra.accept_local_operator),
        ));
        tracing::info!(
            target: "ca",
            prefix = %ra.prefix, kind = %ra.kind, signed = ra.require_signed,
            local_operator = ra.accept_local_operator,
            "issuance gated on challenge attestation",
        );
    }
    match issuance.len() {
        0 => {}
        1 => builder = builder.issuance(issuance.remove(0)),
        _ => builder = builder.issuance(Box::new(AllIssuance::new(issuance))),
    }

    let mut ca = builder
        .build()
        .map_err(|e| anyhow::anyhow!("[ca] CA build failed: {e}"))?;
    let state = ca.state();
    // The node's trust contexts: the CA stops serving what the held version
    // of its namespace's context revokes (one adopted while it did not run,
    // e.g. stored for this start by `ndn-fwd revoke`), renewals of
    // certificates an earlier CA of this identity issued are verified under
    // them, and so are the decisions admin devices push.
    let keyring = engine
        .validator()
        .map(|v| Arc::clone(v.keyring()))
        .or_else(|| engine.security().map(|mgr| Arc::clone(mgr.keyring())));
    match &keyring {
        Some(keyring) => {
            state.follow_held(keyring);
            state.accept_earlier_ca_certificates(Arc::clone(keyring));
        }
        None => tracing::debug!(
            target: "ca",
            "no trust contexts on this node: the CA renews only the certificates it issued"
        ),
    }
    if let Some(store) = &prep.approvals {
        let keyring = keyring.ok_or_else(|| {
            anyhow::anyhow!(
                "[ca] device-approval needs the node's trust contexts to validate the \
                 decisions admin devices push, but the engine has no security manager"
            )
        })?;
        ca = ca.approvals(store.clone(), keyring);
    }

    let status = ca.approval_service();
    let producer = Producer::from_handle(prep.handle, prep.prefix.clone());
    let prefix_str = prep.prefix.to_string();
    let approvals = prep.approvals.is_some();
    tokio::spawn(async move {
        tracing::info!(
            target: "ca",
            prefix = %prefix_str,
            approvals,
            "NDNCERT CA serving{}",
            if approvals { " (and CA/APPROVAL, CA/PENDING, CA/STATUS)" } else { "" }
        );
        if let Err(e) = ca.serve(producer).await {
            tracing::error!(target: "ca", error = %e, "NDNCERT CA exited");
        }
    });

    Ok(RunningCa {
        approvals: prep.approvals,
        state,
        status,
    })
}

/// A CA's challenge set, in offer order, and the approval store its
/// `device-approval` challenge reads (when it offers one).
struct Challenges {
    handlers: Vec<Box<dyn ChallengeHandler>>,
    approvals: Option<ApprovalStore>,
}

/// Build the CA's challenge set from config: the `[[ca.challenge]]` list,
/// plus the `token` challenge every CA offers over its invites `tokens`
/// (made at runtime; persisted in the CA store in PIB mode). `nop`
/// (auto-approve) is only offered when listed explicitly. The offer order
/// is [`ndn_cert::challenge_order`]'s.
///
/// `approval`: the namespace and approval policy of a namespace CA, which
/// offers `device-approval` whether listed or not when the policy names
/// roles, with the invite it requires redeemed from the same invites. The
/// `device-approval` challenge reads the [`ApprovalStore`] `approval_store`
/// opens, returned for the mgmt backend and `/CA/APPROVAL`.
fn build_challenges(
    cfg: &CaTomlConfig,
    tokens: &TokenStore,
    approval: Option<(&Name, &ApprovalPolicy)>,
    approval_store: impl FnOnce() -> Result<ApprovalStore>,
) -> Result<Challenges> {
    let configured = &cfg.challenges;
    let order = ndn_cert::challenge_order(
        configured.iter().map(|c| c.kind.as_str()),
        approval.map(|(_, policy)| policy),
    );

    // Every entry read in config order; the token and device-approval
    // handlers are built once every entry is read.
    let mut built: Vec<Option<Box<dyn ChallengeHandler>>> = Vec::with_capacity(configured.len());
    for c in configured {
        built.push(match c.kind.as_str() {
            "token" | DEVICE_APPROVAL => None,
            _ => Some(build_challenge(c)?),
        });
    }
    if order.approval_unlisted
        && let Some((namespace, policy)) = approval
    {
        tracing::info!(
            target: "ca",
            namespace = %namespace,
            "offering the device-approval challenge although [ca] does not list it: the \
             namespace's trust context advertises {}",
            policy.describe()
        );
    }

    let mut approvals = None;
    let mut handlers = Vec::with_capacity(order.slots.len());
    let mut approval_store = Some(approval_store);
    for slot in order.slots {
        handlers.push(match slot {
            ChallengeSlot::Configured(i) => built[i].take().expect("built in config order"),
            ChallengeSlot::Token => Box::new(TokenChallenge::new(tokens.clone())),
            ChallengeSlot::DeviceApproval => {
                let open = approval_store.take().expect("one device-approval slot");
                let store = open()?;
                let mut challenge = DeviceApprovalChallenge::new(store.clone());
                if let Some((namespace, policy)) = approval
                    && policy.needs_invite()
                {
                    challenge = challenge.requiring_invite(
                        namespace.clone(),
                        policy.roles.clone(),
                        tokens.clone(),
                    );
                }
                approvals = Some(store);
                Box::new(challenge)
            }
        });
    }
    Ok(Challenges {
        handlers,
        approvals,
    })
}

/// The CA's invites, persisted in `store` when one is given.
fn token_store(store: Option<&Arc<FileCaStore>>) -> Result<TokenStore> {
    match store {
        Some(store) => TokenStore::with_store(Arc::clone(store) as Arc<dyn CaStore>)
            .map_err(|e| anyhow::anyhow!("[ca] loading the invites: {e}")),
        None => Ok(TokenStore::new()),
    }
}

/// A challenge other than `token` and `device-approval` (built by
/// [`build_challenges`] itself).
fn build_challenge(c: &ndn_config::ChallengeConfig) -> Result<Box<dyn ChallengeHandler>> {
    match c.kind.as_str() {
        "nop" => {
            tracing::warn!(
                target: "ca",
                "[ca] `nop` challenge configured: every enrollment request is approved \
                 without authentication. Demo only.",
            );
            Ok(Box::new(NopChallenge::new()))
        }
        "pin" => {
            let pin = c
                .pin
                .as_deref()
                .with_context(|| "[ca] pin challenge requires `pin`")?;
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
            "[ca] unsupported challenge kind '{other}' \
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
            target: "ca",
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
    use ndn_config::{CaRelayConfig, ChallengeConfig};
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

    fn challenge(kind: &str) -> ChallengeConfig {
        ChallengeConfig {
            kind: kind.to_string(),
            pin: None,
            max_tries: None,
            ttl_secs: None,
            smtp: None,
        }
    }

    fn namespace_cfg(challenges: Vec<ChallengeConfig>) -> CaTomlConfig {
        CaTomlConfig {
            enabled: true,
            prefix: "/home/bob".to_string(),
            identity: "/home/bob/CA".to_string(),
            challenges,
            ..CaTomlConfig::default()
        }
    }

    /// Provision the PIB exactly as `ndn-fwd init` does (root
    /// key + anchor, `/home/bob/CA` key, CA cert issued by the root under
    /// `ca/`, admin device `/home/bob/admin/desk`). Returns the root anchor.
    fn write_namespace_pib(dir: &Path) -> Certificate {
        let pib = FilePib::new(dir).unwrap();
        futures::executor::block_on(ndn_cert::init_namespace_in_pib(
            &pib,
            &"/home/bob".parse().unwrap(),
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
        ))
        .expect("namespace_ca init");
        read_cert_wire(&bob_ca_dir(dir).join(ANCHOR_CERT_FILE))
            .unwrap()
            .expect("init writes the root anchor cert")
    }

    /// The CA directory of `/home/bob` in the PIB at `dir`.
    fn bob_ca_dir(dir: &Path) -> std::path::PathBuf {
        ndn_cert::ca_dir(dir, &"/home/bob".parse().unwrap())
    }

    struct RunningCa {
        client: NdncertClient,
        approvals: Option<ApprovalStore>,
        invites: CaInvites,
        state: Arc<ndn_cert::CaState>,
        engine: ForwarderEngine,
        shutdown: ShutdownHandle,
    }

    impl RunningCa {
        /// The token of a new invite for `role`, made as the `ca/invite-create`
        /// verb makes it.
        fn invite(&self, role: &str) -> String {
            make_invite(&self.invites, role)
        }

        async fn stop(self) {
            drop(self.client);
            drop(self.engine);
            self.shutdown.shutdown().await;
        }
    }

    /// The token of a new invite of `invites` for `role`.
    fn make_invite(invites: &CaInvites, role: &str) -> String {
        let request = ndn_cert::InviteRequest {
            role: role.into(),
            ..Default::default()
        };
        invites
            .create(&request, "uid 1000 (alice)")
            .expect("the CA makes the invite")
            .token
    }

    /// Boot an engine with the CA wired exactly as `main` does, plus one
    /// client face. The content store is off so every fetch reaches the CA
    /// (a revoked cert would otherwise still be answered from the cache).
    async fn run_ca(cfg: &CaTomlConfig, pib: &Path) -> RunningCa {
        let (faces, spawn_state) = prepare(cfg, 0, pib).await.expect("CA prepares");
        let invites = spawn_state.invites.clone();
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
        let prefix = spawn_state.prefix.clone();
        let running = spawn(spawn_state, &engine).expect("CA spawns");
        RunningCa {
            client: NdncertClient::new(ndn_app::Consumer::from_handle(client_handle), prefix),
            approvals: running.approvals,
            invites,
            state: running.state,
            engine,
            shutdown,
        }
    }

    /// Enroll `/home/bob/<who>` (e.g. `member/laptop`) over the CA's NDN face,
    /// re-polling pending CHALLENGE rounds (device-approval) every 20 ms.
    async fn enroll(
        client: &mut NdncertClient,
        who: &str,
        kind: &str,
        params: serde_json::Map<String, serde_json::Value>,
    ) -> std::result::Result<ndn_packet::Data, ndn_cert::CertError> {
        enroll_with(client, device_signer(who), kind, params).await
    }

    /// As [`enroll`], with the key `signer` (its key name names the device).
    async fn enroll_with(
        client: &mut NdncertClient,
        signer: Arc<dyn Signer>,
        kind: &str,
        params: serde_json::Map<String, serde_json::Value>,
    ) -> std::result::Result<ndn_packet::Data, ndn_cert::CertError> {
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
    /// MustBeFresh) answers a cert-fetch for the certificate `name`.
    async fn ca_serves(client: &mut NdncertClient, name: &Name) -> bool {
        let interest = ndn_packet::encode::InterestBuilder::new(name.clone())
            .must_be_fresh()
            .build();
        matches!(
            tokio::time::timeout(Duration::from_millis(500), client.express(interest)).await,
            Ok(Ok(_))
        )
    }

    /// The certificate the CA answers for the key `key` (CanBePrefix, as a
    /// verifier resolves a key-name KeyLocator with a cold cache).
    async fn ca_serves_key(client: &mut NdncertClient, key: &Name) -> Option<Name> {
        let interest = ndn_packet::encode::InterestBuilder::new(key.clone())
            .can_be_prefix()
            .must_be_fresh()
            .build();
        match tokio::time::timeout(Duration::from_millis(500), client.express(interest)).await {
            Ok(Ok(data)) => Some((*data.name).clone()),
            _ => None,
        }
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

    /// Invites survive a restart of the CA: one redeemed before it stays
    /// spent, one made before it is still redeemable after it, a withdrawn
    /// one stays withdrawn; the store keeps no token.
    #[tokio::test]
    async fn invites_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(Vec::new());

        let mut ca = run_ca(&cfg, dir.path()).await;
        let make = |role: &str| {
            let request = ndn_cert::InviteRequest {
                role: role.into(),
                ..Default::default()
            };
            ca.invites.create(&request, "").unwrap()
        };
        let (used, kept, gone) = (make("member"), make("member"), make("guest"));
        ca.invites.withdraw(&gone.id).unwrap();
        enroll(&mut ca.client, "member/laptop", "token", token(&used.token))
            .await
            .expect("first redemption enrolls");
        ca.stop().await;

        let mut ca = run_ca(&cfg, dir.path()).await;
        let state = |id: &str| {
            ca.invites
                .list()
                .into_iter()
                .find(|e| e.id == id)
                .map(|e| e.info.state)
        };
        use ndn_cert::InviteState::{Outstanding, Redeemed, Withdrawn};
        assert_eq!(state(&used.id), Some(Redeemed));
        assert_eq!(state(&kept.id), Some(Outstanding));
        assert_eq!(state(&gone.id), Some(Withdrawn));
        let replay = enroll(&mut ca.client, "member/phone", "token", token(&used.token)).await;
        assert!(
            replay.is_err(),
            "a redeemed invite is refused after a restart: {replay:?}"
        );
        let withdrawn = enroll(&mut ca.client, "guest/tv", "token", token(&gone.token)).await;
        assert!(
            withdrawn.is_err(),
            "a withdrawn invite is refused after a restart: {withdrawn:?}"
        );
        enroll(&mut ca.client, "member/phone", "token", token(&kept.token))
            .await
            .expect("an invite made before the restart enrolls after it");
        ca.stop().await;

        let stored = bob_ca_dir(dir.path()).join("invites");
        let entries: Vec<_> = stored
            .read_dir()
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 3);
        for path in entries {
            let stored = std::fs::read_to_string(path).unwrap();
            for made in [&used, &kept, &gone] {
                assert!(!stored.contains(&made.token), "token stored: {stored}");
            }
        }
    }

    /// NDNCERT REVOKE over NDN: an unrelated key is refused; the holder's
    /// revocation is persisted, the CA stops serving the cert, and after a
    /// restart it still refuses it (no fetch, no re-enrollment of the key).
    /// The CA identity may revoke any cert it issued.
    #[tokio::test]
    async fn revoke_over_ndn_by_holder_or_ca_only() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token")]);

        let mut ca = run_ca(&cfg, dir.path()).await;
        let invite = [
            ca.invite("member"),
            ca.invite("member"),
            ca.invite("member"),
        ];
        let laptop = enroll(&mut ca.client, "member/laptop", "token", token(&invite[0]))
            .await
            .expect("laptop enrolls");
        let laptop = (*laptop.name).clone();
        let phone = enroll(&mut ca.client, "member/phone", "token", token(&invite[1]))
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
        assert!(
            ca_serves(&mut ca.client, &laptop).await,
            "refused REVOKE changes nothing"
        );

        assert_eq!(
            revoke_as(&mut ca.client, &laptop, device_signer("member/laptop")).await,
            ndn_cert::RevokeStatus::Revoked
        );
        assert!(
            !ca_serves(&mut ca.client, &laptop).await,
            "revoked cert is not served"
        );
        assert_eq!(
            bob_ca_dir(dir.path())
                .join("revoked")
                .read_dir()
                .unwrap()
                .count(),
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
        assert!(
            !ca_serves(&mut ca.client, &laptop).await,
            "still revoked after restart"
        );
        assert!(
            !ca_serves(&mut ca.client, &phone).await,
            "still revoked after restart"
        );
        let again = enroll(&mut ca.client, "member/laptop", "token", token(&invite[2])).await;
        assert!(
            again.is_err(),
            "a revoked key is not re-certified: {again:?}"
        );
        ca.stop().await;
    }

    /// `ndn-fwd revoke`'s CA side (`CaState::revoke_issued_under`, no
    /// possession proof — the CA host's own administration): every cert of
    /// the key stops being served, the revocation is persisted, and the
    /// device name is free for a new key (one key per name), while the
    /// revoked key itself is never certified again.
    #[tokio::test]
    async fn admin_revocation_stops_serving_and_frees_the_device_name() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token")]);
        let mut ca = run_ca(&cfg, dir.path()).await;
        let invite: Vec<String> = (0..4).map(|_| ca.invite("member")).collect();
        let phone = enroll(&mut ca.client, "member/phone", "token", token(&invite[0]))
            .await
            .expect("phone enrolls");
        let phone = (*phone.name).clone();
        let new_key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[8; 32],
            "/home/bob/member/phone/KEY/k2".parse().unwrap(),
        ));
        let taken = enroll_with(
            &mut ca.client,
            Arc::clone(&new_key),
            "token",
            token(&invite[1]),
        )
        .await;
        assert!(
            taken.is_err(),
            "the name is held by the first key: {taken:?}"
        );

        let key = ndn_cert::key_name_of(&phone).unwrap();
        assert_eq!(
            ca_serves_key(&mut ca.client, &key).await,
            Some(phone.clone()),
            "by key name"
        );
        let ca_cert = ca_serves_key(
            &mut ca.client,
            &ndn_cert::ca_key_name(&"/home/bob".parse().unwrap()),
        )
        .await
        .expect("the CA's own certificate by its key name");
        assert!(ndn_security::cert_name::is_cert_name(&ca_cert), "{ca_cert}");
        let out = ca.state.revoke_issued_under(&key);
        assert_eq!(out.revoked, vec![phone.clone()]);
        assert!(out.not_persisted.is_none());
        assert!(
            !ca_serves(&mut ca.client, &phone).await,
            "a revoked cert is not served"
        );
        assert_eq!(
            ca_serves_key(&mut ca.client, &key).await,
            None,
            "nor by key name"
        );
        assert_eq!(
            bob_ca_dir(dir.path())
                .join("revoked")
                .read_dir()
                .unwrap()
                .count(),
            1,
            "revocation persisted"
        );
        assert!(
            ca.state.revoke_issued_under(&key).revoked.is_empty(),
            "revoked once"
        );

        let again = enroll(&mut ca.client, "member/phone", "token", token(&invite[2])).await;
        assert!(
            again.is_err(),
            "the revoked key is never certified again: {again:?}"
        );
        enroll_with(&mut ca.client, new_key, "token", token(&invite[3]))
            .await
            .expect("the device name is free for a new key");
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

    /// A CA that lists no challenge starts and admits by invite only: every
    /// CA offers `token` over its invites, never `nop` unless listed.
    #[tokio::test]
    async fn a_ca_without_challenges_admits_by_invite() {
        let mut cfg = namespace_cfg(Vec::new());
        cfg.ephemeral = true;
        let (_, spawn_state) = prepare(&cfg, 0, no_pib())
            .await
            .expect("a CA without challenges starts");
        let kinds: Vec<_> = spawn_state
            .challenges
            .iter()
            .map(|c| c.challenge_type())
            .collect();
        assert_eq!(kinds, ["token"]);
    }

    #[tokio::test]
    async fn nop_is_only_offered_when_listed() {
        let mut cfg = namespace_cfg(vec![challenge("nop")]);
        cfg.ephemeral = true;
        let (_, spawn_state) = prepare(&cfg, 0, no_pib())
            .await
            .expect("explicit nop is allowed");
        let kinds: Vec<_> = spawn_state
            .challenges
            .iter()
            .map(|c| c.challenge_type())
            .collect();
        assert_eq!(kinds, ["nop", "token"]);
    }

    #[tokio::test]
    async fn prefix_ending_in_ca_is_rejected() {
        let mut cfg = namespace_cfg(vec![challenge("nop")]);
        cfg.ephemeral = true;
        cfg.prefix = "/home/bob/CA".to_string();
        let err = prepare(&cfg, 0, no_pib())
            .await
            .err()
            .expect("/CA prefix rejected");
        assert!(
            err.to_string().contains("ends in /CA"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn pib_ca_without_namespace_identity_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        FilePib::new(dir.path()).unwrap();
        let cfg = namespace_cfg(vec![challenge("token")]);
        let err = prepare(&cfg, 0, dir.path())
            .await
            .err()
            .expect("missing CA cert must fail startup");
        assert!(
            err.to_string().contains("no CA certificate"),
            "unexpected error: {err}"
        );
        let err = prepare(&cfg, 0, no_pib())
            .await
            .err()
            .expect("a PIB-backed CA without a PIB must fail startup");
        assert!(
            err.to_string().contains("cannot open PIB"),
            "unexpected error: {err}"
        );
    }

    /// Restart with the same PIB: the CA signs with the same root-certified
    /// key, still serves the cert it issued before the restart, and new
    /// certs chain to the same root.
    #[tokio::test]
    async fn pib_backed_ca_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token")]);
        let ca_cert = read_cert_wire(&bob_ca_dir(dir.path()).join(CA_CERT_FILE))
            .unwrap()
            .unwrap();

        let mut ca = run_ca(&cfg, dir.path()).await;
        let invite = [ca.invite("member"), ca.invite("member")];
        let first = enroll(&mut ca.client, "member/laptop", "token", token(&invite[0]))
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

        let second = enroll(&mut ca.client, "member/phone", "token", token(&invite[1]))
            .await
            .expect("enrollment after restart");
        for issued in [&first, &second] {
            let cert = Certificate::decode(issued).unwrap();
            // The KeyLocator names the CA's key, not one certificate of it.
            assert_eq!(cert.issuer.as_deref(), Some(&ca_cert.key_name()));
            assert!(signed_by(issued, &ca_cert.public_key).await);
        }
        let ca_data =
            ndn_packet::Data::decode(bytes::Bytes::from(ndn_cert::ca::serialize_cert(&ca_cert)))
                .unwrap();
        assert!(
            signed_by(&ca_data, &root.public_key).await,
            "CA cert chains to root"
        );
        assert!(
            bob_ca_dir(dir.path())
                .join("issued")
                .read_dir()
                .unwrap()
                .count()
                >= 2
        );
        ca.stop().await;
    }

    fn ephemeral_approval_cfg() -> CaTomlConfig {
        let mut cfg = namespace_cfg(vec![challenge("device-approval")]);
        cfg.ephemeral = true;
        cfg
    }

    /// Decide the first pending request (for a name under `/home/bob/<who>`)
    /// by its verification code through the mgmt backend the forwarder
    /// registers, as the CA host's local operator; the record names them.
    fn resolve_via_mgmt(
        store: ApprovalStore,
        who: &'static str,
        approve: bool,
    ) -> tokio::task::JoinHandle<()> {
        let mgmt: Arc<dyn ApprovalMgmtBackend> = Arc::new(store);
        tokio::spawn(async move {
            loop {
                let rows = mgmt.list().await.expect("the CA lists its requests");
                if let Some(req) = rows.rows.into_iter().find(|r| r.state == "pending") {
                    assert!(req.key_name.starts_with(&format!("/home/bob/{who}/")));
                    let decision = if approve {
                        ndn_cert::Decision::Approve
                    } else {
                        ndn_cert::Decision::Deny {
                            reason: "not my device".into(),
                        }
                    };
                    let row = mgmt
                        .decide(req.code.clone(), decision, "uid 1000 (alice)".into())
                        .await
                        .expect("a pending request is decided");
                    assert_eq!(
                        row.approver,
                        "the CA host's local operator uid 1000 (alice)"
                    );
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
        let store = ca
            .approvals
            .clone()
            .expect("device-approval store is exposed");
        let approver = resolve_via_mgmt(store.clone(), "tablet", true);

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
        assert_eq!(store.records()[0].state.as_str(), "approved");
        ca.stop().await;
    }

    #[tokio::test]
    async fn device_approval_denied_via_mgmt_fails_enrollment() {
        let cfg = ephemeral_approval_cfg();
        let mut ca = run_ca(&cfg, no_pib()).await;
        let approver = resolve_via_mgmt(ca.approvals.clone().unwrap(), "tablet", false);

        let result = enroll(
            &mut ca.client,
            "tablet",
            "device-approval",
            serde_json::Map::new(),
        )
        .await;
        approver.await.unwrap();
        assert!(
            result.is_err(),
            "denied request must not enroll: {result:?}"
        );
        ca.stop().await;
    }

    /// A namespace CA (PIB-backed `/home/bob/CA`) issues only role-layout
    /// names, and an invite's role bounds what it can certify: a member
    /// invite never yields an admin, node or guest cert, a guest invite
    /// never a member cert. A request the CA refuses does not spend the
    /// invite: it still enrolls a member after.
    #[tokio::test]
    async fn namespace_ca_invites_are_bounded_by_role() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token")]);
        let mut ca = run_ca(&cfg, dir.path()).await;
        let (m1, m2) = (ca.invite("member"), ca.invite("member"));
        let (g1, g2) = (ca.invite("guest"), ca.invite("guest"));

        // A member invite is scoped to /home/bob/member: no admin cert (an
        // admin needs a device approval), nor a node, guest or non-role name.
        for name in ["admin/evil", "node/vps", "guest/bob", "laptop"] {
            let refused = enroll(&mut ca.client, name, "token", token(&m1)).await;
            assert!(
                refused.is_err(),
                "a member invite must not certify {name}: {refused:?}"
            );
        }

        // The refused requests did not spend it: it still enrolls a member.
        let phone = enroll(&mut ca.client, "member/phone", "token", token(&m1))
            .await
            .expect("a member invite survives refused requests and certifies a member");
        assert_eq!(
            ndn_security::cert_name::key_name_of(&phone.name).to_string(),
            "/home/bob/member/phone/KEY/k1",
            "a certificate of the requested key: {}",
            phone.name
        );
        let guest = enroll(&mut ca.client, "guest/alice", "token", token(&m2)).await;
        assert!(
            guest.is_err(),
            "a member invite must not certify a guest: {guest:?}"
        );
        let member = enroll(&mut ca.client, "member/tv", "token", token(&g1)).await;
        assert!(
            member.is_err(),
            "a guest invite must not certify a member: {member:?}"
        );
        enroll(&mut ca.client, "guest/alice", "token", token(&g2))
            .await
            .expect("a guest invite certifies a guest");
        ca.stop().await;
    }

    /// On a namespace CA an admin cert needs an admin's device approval: the token
    /// path is refused, the approved device-approval path issues it.
    #[tokio::test]
    async fn namespace_ca_admin_cert_needs_device_approval() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token"), challenge("device-approval")]);
        let mut ca = run_ca(&cfg, dir.path()).await;
        let member = ca.invite("member");
        let by_token = enroll(&mut ca.client, "admin/tablet", "token", token(&member)).await;
        assert!(
            by_token.is_err(),
            "admin by token must be refused: {by_token:?}"
        );

        let store = ca
            .approvals
            .clone()
            .expect("device-approval store is exposed");
        let approver = resolve_via_mgmt(store, "admin/tablet", true);
        let issued = enroll(
            &mut ca.client,
            "admin/tablet",
            "device-approval",
            serde_json::Map::new(),
        )
        .await
        .expect("an approved admin request enrolls");
        approver.await.unwrap();
        assert_eq!(
            ndn_security::cert_name::key_name_of(&issued.name).to_string(),
            "/home/bob/admin/tablet/KEY/k1",
            "a certificate of the requested key: {}",
            issued.name
        );
        ca.stop().await;
    }

    /// A namespace CA enforces the approval policy its trust context
    /// advertises: it offers `device-approval` although `[ca]` lists only
    /// tokens, and refuses to start when `[ca]` states another policy.
    #[tokio::test]
    async fn namespace_ca_enforces_the_policy_its_context_advertises() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let mut cfg = namespace_cfg(vec![challenge("token")]);
        let (_, spawn_state) = prepare(&cfg, 0, dir.path()).await.expect("the CA prepares");
        let kinds: Vec<_> = spawn_state
            .challenges
            .iter()
            .map(|c| c.challenge_type())
            .collect();
        assert_eq!(kinds, ["token", DEVICE_APPROVAL]);
        assert_eq!(spawn_state.approval_policy, Some(ApprovalPolicy::default()));

        cfg.approval_roles = Some(vec!["node".into(), "admin".into()]);
        cfg.approval_requires_invite = Some(false);
        prepare(&cfg, 0, dir.path())
            .await
            .expect("[ca] restating the context's policy");
        for (roles, invite) in [
            (vec!["admin".to_string()], false),
            (vec!["admin".into(), "node".into()], true),
        ] {
            cfg.approval_roles = Some(roles);
            cfg.approval_requires_invite = Some(invite);
            let err = prepare(&cfg, 0, dir.path())
                .await
                .err()
                .expect("a disagreeing [ca] is refused");
            assert!(
                err.to_string()
                    .contains("disagree with the namespace's trust context"),
                "{err}"
            );
        }
    }

    /// `ndn-fwd init -c` writes the `[ca]` link policy and relays into the
    /// context (unset keys: the default), and a namespace CA refuses to
    /// start when `[ca]` states another link policy or other relays than
    /// its context.
    #[tokio::test]
    async fn the_context_carries_the_configured_link_policy_and_the_ca_checks_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = namespace_cfg(vec![challenge("token")]);
        cfg.link_roles = Some(vec!["admin".into(), "node".into()]);
        cfg.enrollment_links = Some(false);
        cfg.direct_paths = Some(false);
        cfg.direct_pairs = Some(vec!["admin:node".into()]);
        let relay = CaRelayConfig {
            device: "/home/bob/node/vps".into(),
            key: None,
            endpoint: vec!["vps.example.net:6367".into()],
            preference: 0,
        };
        cfg.relays = Some(vec![relay.clone()]);
        let ns: Name = "/home/bob".parse().unwrap();
        let policies = cfg
            .policy_input()
            .unwrap()
            .new_namespace_policies(&ns)
            .unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        ndn_cert::init_namespace_in_pib_with(
            &pib,
            &ns,
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
            &policies,
        )
        .await
        .unwrap();
        let (ctx, _) = ndn_cert::read_stored_context(dir.path(), &ns)
            .unwrap()
            .unwrap();
        let expected = ndn_security::LinkPolicy {
            roles: vec!["admin".into(), "node".into()],
            relay_roles: vec!["node".into()],
            enrollment_links: false,
            direct_paths: false,
            direct_pairs: vec![("admin".into(), "node".into())],
        };
        assert_eq!(ctx.stated_link_policy(), Some(&expected));
        assert_eq!(ctx.relays(), [relay.advertised().unwrap()]);

        prepare(&cfg, 0, dir.path())
            .await
            .expect("[ca] restating the context's link policy");
        cfg.relays = Some(Vec::new());
        let err = prepare(&cfg, 0, dir.path())
            .await
            .err()
            .expect("other [ca] relays are refused");
        assert!(
            err.to_string().contains("[ca] relay entries disagree"),
            "{err}"
        );
        cfg.relays = None;
        cfg.link_roles = Some(Vec::new());
        let err = prepare(&cfg, 0, dir.path())
            .await
            .err()
            .expect("a disagreeing [ca] is refused");
        assert!(
            err.to_string()
                .contains("ndn-fwd schema update -c <config>"),
            "{err}"
        );
    }

    /// A device that is the root of two trusted prefixes runs both CAs on
    /// one engine (`[[ca]]`, as `main` wires them), each from its own
    /// directory and face: each certifies devices of its own namespace only,
    /// and their state (redeemed tokens, issued certificates) is apart.
    #[tokio::test]
    async fn a_root_of_two_namespaces_runs_both_cas() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let bob: Name = "/home/bob".parse().unwrap();
        let acme: Name = "/work/acme".parse().unwrap();
        for ns in [&bob, &acme] {
            ndn_cert::init_namespace_in_pib(&pib, ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .expect("root of both");
        }
        let cas: Vec<CaTomlConfig> = [&bob, &acme]
            .into_iter()
            .map(|ns| CaTomlConfig {
                enabled: true,
                prefix: ns.to_string(),
                identity: format!("{ns}/CA"),
                challenges: Vec::new(),
                ..CaTomlConfig::default()
            })
            .collect();
        let prepared = prepare_all(&cas, dir.path())
            .await
            .expect("both CAs prepare");
        assert_eq!(prepared.len(), 2);
        assert_ne!(prepared[0].1.face_id, prepared[1].1.face_id, "a face each");

        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()));
        let mut client_handles = Vec::new();
        for i in 0..2 {
            let (face, handle) = InProcFace::new(FaceId(CLIENT_FACE + i), 64);
            builder = builder.face(face);
            client_handles.push(handle);
        }
        let mut spawns = Vec::new();
        for (faces, spawn_state) in prepared {
            for face in faces {
                builder = builder.face(face);
            }
            spawns.push(spawn_state);
        }
        let (engine, shutdown) = builder.build().await.expect("engine builds");
        engine.cs().set_admit(false);
        engine.cs().set_serve(false);
        let mut states = Vec::new();
        let invites: Vec<CaInvites> = spawns.iter().map(|s| s.invites.clone()).collect();
        for spawn_state in spawns {
            engine
                .fib()
                .add_nexthop(&spawn_state.prefix, spawn_state.face_id, 0);
            states.push(spawn(spawn_state, &engine).expect("CA spawns").state);
        }
        let mut clients: Vec<NdncertClient> = client_handles
            .into_iter()
            .zip([&bob, &acme])
            .map(|(handle, ns)| {
                NdncertClient::new(ndn_app::Consumer::from_handle(handle), ns.clone())
            })
            .collect();

        let enroll_in = |ns: &Name, device_ns: &Name| {
            let key: Name = format!("{device_ns}/member/laptop/KEY/k1").parse().unwrap();
            (
                ns.clone(),
                Arc::new(Ed25519Signer::from_seed(&[9; 32], key)) as Arc<dyn Signer>,
            )
        };
        let answer = |params: serde_json::Map<String, serde_json::Value>| {
            move |_: ndn_cert::client::ChallengeRound| {
                let params = params.clone();
                async move { Ok::<_, ndn_cert::CertError>(Some(params)) }
            }
        };
        for (i, ns) in [&bob, &acme].into_iter().enumerate() {
            let other = if i == 0 { &acme } else { &bob };
            let own = token(&make_invite(&invites[i], "member"));
            let theirs = token(&make_invite(&invites[1 - i], "member"));
            // The other CA's invite is not this CA's.
            let (prefix, signer) = enroll_in(ns, ns);
            let refused = ndn_cert::client::enroll(
                &mut clients[i],
                &prefix,
                signer,
                86_400,
                "token",
                answer(theirs),
            )
            .await;
            assert!(refused.is_err(), "{ns}'s CA took an invite of {other}");
            // A device of the other namespace is refused by this CA.
            let (prefix, signer) = enroll_in(ns, other);
            let refused = ndn_cert::client::enroll(
                &mut clients[i],
                &prefix,
                signer,
                86_400,
                "token",
                answer(own.clone()),
            )
            .await;
            assert!(refused.is_err(), "{ns}'s CA certified a device of {other}");
            // Its own device enrolls with its own invite.
            let (prefix, signer) = enroll_in(ns, ns);
            let cert = ndn_cert::client::enroll(
                &mut clients[i],
                &prefix,
                signer,
                86_400,
                "token",
                answer(own),
            )
            .await
            .expect("its own device enrolls");
            assert!(cert.has_prefix(ns), "{cert}");
            assert_eq!(states[i].issued_under(ns).len(), 1);
            assert!(states[i].issued_under(other).is_empty());
            assert!(states[i].is_ca_of(ns) && !states[i].is_ca_of(other));
        }
        assert_ne!(
            ndn_cert::ca_dir(dir.path(), &bob),
            ndn_cert::ca_dir(dir.path(), &acme)
        );
        for ns in [&bob, &acme] {
            let issued = ndn_cert::ca_dir(dir.path(), ns).join("issued");
            assert_eq!(issued.read_dir().unwrap().count(), 1, "{ns}");
        }
        drop(clients);
        drop(engine);
        shutdown.shutdown().await;
    }
}
