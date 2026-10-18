//! Embedded NDNCERT CA (`[ca]`). Serves `/<prefix>/CA/{INFO,NEW,
//! CHALLENGE/<id>}` and cert-fetch for the certs it issued through an
//! in-process face.
//!
//! By default the CA signs with the identity `[ca].identity` loaded from
//! the node's PIB: the `/<ns>/CA` key plus its certificate
//! `<pib_path>/ca/ca-cert.data` (issued by the namespace root), both written by
//! `ndn-fwd init --namespace <ns>`. Issued certs therefore chain to the same root
//! across restarts, and the issued certs, revocations and redeemed one-time
//! tokens (as hashes) persist under `<pib_path>/ca/` ([`FileCaStore`]), so an
//! invite token redeemed before a restart stays spent. `ephemeral = true`
//! mints a throwaway self-signed key at every start instead (demo only,
//! warned; nothing persists).
//!
//! A PIB-backed CA identity `/<ns>/CA` serves the namespace `/<ns>`:
//! issuance follows the role layout ([`RolePolicy`]) — device keys
//! `/<ns>/<role>/<device>/KEY/…` only; the roles the namespace's trust
//! context certifies on an admin's approval (its enrollment hint, default
//! `admin` and `node`; [`ApprovalPolicy`]) need one, tokens admit members
//! and (guest-scoped) guests. An invite token
//! minted with a role (`ndn-fwd-tokens new --role guest` → `guest-<hex>`) is
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
//! [`ApprovalStore`] persisted under `<pib>/ca/approvals/`, so a pending
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
use ndn_cert::namespace::{ANCHOR_CERT_FILE, CA_CERT_FILE, CA_DIR};
use ndn_cert::roles::{Role, role_prefix, token_expiry, token_role};
use ndn_cert::{
    ApprovalPolicy, CaStore, ChallengeHandler, EmailChallenge, EmailSender, FileCaStore,
    IssuanceContext, IssuanceDecision, IssuancePolicy, NopChallenge, PinChallenge,
    RequireAttestationKind, RolePolicy, SingleKeyIdentity, TokenChallenge, TokenStore,
};
use ndn_config::CaTomlConfig;
use ndn_engine::ForwarderEngine;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_identity::NdncertCa;
use ndn_packet::Name;
use ndn_security::{Certificate, FilePib, KeyChain, LinkPolicy, SecurityManager, SignedTrustContext, Validator};
use ndn_transport::FaceId;

pub(crate) const CA_FACE_ID: u64 = 0xFFFF_0002;

/// Artefacts retained until post-build: the in-process face's handle, the
/// CA prefix, the signing keychain and the challenge set.
pub(crate) struct CaSpawn {
    pub handle: InProcHandle,
    pub face_id: FaceId,
    /// CA namespace; NDNCERT names are `/<prefix>/CA/...` and issued certs
    /// live under it, so one FIB entry covers both.
    pub prefix: Name,
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
    approvals: Option<ApprovalStore>,
    store: Option<Arc<FileCaStore>>,
}

/// Validate `[ca]`, load (or, with `ephemeral`, mint) the CA identity and
/// build the challenge set. Returns the face to attach to the builder and
/// the [`CaSpawn`] retained for post-build FIB wiring and the task spawn.
/// Fails — so the forwarder refuses to start — on a CA with no challenge, a
/// prefix ending in `/CA`, a missing / inconsistent PIB identity, or an
/// approval policy in `[ca]` that disagrees with the namespace's trust
/// context. `pib_path` is the configured `[security] pib_path` (unused when
/// `ephemeral`).
pub(crate) async fn prepare(
    cfg: &CaTomlConfig,
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
        let ca_dir = pib_path.join(CA_DIR);
        let store = FileCaStore::open(&ca_dir)
            .map_err(|e| anyhow::anyhow!("[ca] CA state dir {}: {e}", ca_dir.display()))?;
        // A namespace CA: identity `/<ns>/CA` certified by the namespace root `/<ns>/KEY/…`.
        let namespace = namespace_of(&identity)
            .filter(|ns| anchor.name.has_prefix(&ns.clone().append("KEY")));
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
    // Role-carrying invite tokens are scoped under the namespace (the CA
    // prefix for an ephemeral demo CA); on a namespace CA every token is.
    let token_ns = namespace.clone().unwrap_or_else(|| prefix.clone());
    let approval_policy = match &namespace {
        Some(ns) => {
            let held = newest_context(pib_path, ns)?;
            if let Some(ctx) = &held {
                check_link_policy(cfg, ctx)?;
            }
            let advertised = held.and_then(|ctx| {
                let policy = ApprovalPolicy::from_hint(ctx.enrollment_hint()?)?;
                Some((ctx.version(), policy))
            });
            Some(approval_policy(cfg, advertised)?)
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
    let (challenges, approvals) = build_challenges(
        cfg,
        store.as_ref(),
        &token_ns,
        approval_policy.as_ref().map(|p| (namespace.as_ref().unwrap_or(&prefix), p)),
        approval_store,
    )?;

    let face_id = FaceId(CA_FACE_ID);
    let (face, handle) = InProcFace::new(face_id, 64);

    Ok((
        vec![face],
        CaSpawn {
            handle,
            face_id,
            prefix,
            keychain,
            anchor,
            namespace,
            approval_policy,
            challenges,
            approvals,
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

/// Refuses `[ca] link_roles` / `relay_roles` / `enrollment_links` that
/// disagree with the link policy of the namespace's trust context `ctx`:
/// devices admit links by the context, so `[ca]` only states it again
/// here; `ndn-fwd schema update -c <config>` is what changes it.
pub(crate) fn check_link_policy(cfg: &CaTomlConfig, ctx: &SignedTrustContext) -> Result<()> {
    let held = ctx.link_policy();
    let Some(configured) = configured_link_policy(cfg, &held)? else {
        return Ok(());
    };
    if same_link_policy(&configured, &held) {
        return Ok(());
    }
    let quoted = |roles: &[String]| {
        roles.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>().join(", ")
    };
    bail!(
        "[ca] link_roles / relay_roles / enrollment_links disagree with the namespace's trust \
         context (v{}), which states: {}. Devices admit links by the context, so the CA does \
         not start with another policy: to change it, run `ndn-fwd schema update -c <config>` \
         on the root device (a narrowing needs --accept-narrowing); to keep it, set \
         link_roles = [{}], relay_roles = [{}] and enrollment_links = {} in [ca], or remove \
         the keys",
        ctx.version(),
        held.describe(),
        quoted(&held.roles),
        quoted(&held.relay_roles),
        held.enrollment_links
    );
}

/// Whether two link policies admit the same (role lists compared as sets).
pub(crate) fn same_link_policy(a: &LinkPolicy, b: &LinkPolicy) -> bool {
    let set = |roles: &[String]| {
        let mut roles = roles.to_vec();
        roles.sort();
        roles.dedup();
        roles
    };
    set(&a.roles) == set(&b.roles)
        && set(&a.relay_roles) == set(&b.relay_roles)
        && a.enrollment_links == b.enrollment_links
}

/// The link policy `[ca] link_roles` / `relay_roles` / `enrollment_links`
/// state, each unset key taken from `base` (the held context's policy, or
/// the default for a new namespace); `None` when none is set. Refuses an
/// unknown role, and a relay role that may not link.
pub(crate) fn configured_link_policy(
    cfg: &CaTomlConfig,
    base: &LinkPolicy,
) -> Result<Option<LinkPolicy>> {
    if cfg.link_roles.is_none() && cfg.relay_roles.is_none() && cfg.enrollment_links.is_none() {
        return Ok(None);
    }
    let roles = |key: &str, roles: &Option<Vec<String>>, base: &[String]| -> Result<Vec<String>> {
        let Some(roles) = roles else {
            return Ok(base.to_vec());
        };
        let mut parsed = Vec::with_capacity(roles.len());
        for r in roles {
            let role = r
                .parse::<Role>()
                .map_err(|e| anyhow::anyhow!("[ca] {key}: {e}"))?;
            let role = role.as_str().to_string();
            if !parsed.contains(&role) {
                parsed.push(role);
            }
        }
        Ok(parsed)
    };
    let policy = LinkPolicy {
        roles: roles("link_roles", &cfg.link_roles, &base.roles)?,
        relay_roles: roles("relay_roles", &cfg.relay_roles, &base.relay_roles)?,
        enrollment_links: cfg.enrollment_links.unwrap_or(base.enrollment_links),
    };
    if let Some(role) = policy.relay_roles.iter().find(|r| !policy.allows_link(r)) {
        bail!(
            "[ca] relay_roles names {role:?}, but link_roles ({}) does not let {role} devices \
             link, so none could relay: add {role:?} to link_roles, or remove it from \
             relay_roles",
            policy.roles.join(", ")
        );
    }
    Ok(Some(policy))
}

/// The approval policy a namespace CA enforces: what its trust context
/// advertises (`advertised`: its version and policy). `[ca]
/// approval_roles` / `approval_requires_invite` only state it again, and
/// the CA refuses to start when they disagree — the devices read the
/// policy from the context. A context that advertises none (made before
/// the hint carried it) takes the `[ca]` keys, else the default.
pub(crate) fn approval_policy(
    cfg: &CaTomlConfig,
    advertised: Option<(u64, ApprovalPolicy)>,
) -> Result<ApprovalPolicy> {
    let configured = configured_policy(cfg)?;
    let Some((version, advertised)) = advertised else {
        return Ok(configured.unwrap_or_default());
    };
    let sorted = |roles: &[Role]| {
        let mut roles = roles.to_vec();
        roles.sort_by_key(|r| r.as_str());
        roles.dedup();
        roles
    };
    let disagrees = configured.is_some_and(|c| {
        (cfg.approval_roles.is_some() && sorted(&c.roles) != sorted(&advertised.roles))
            || (cfg.approval_requires_invite.is_some() && c.invite_also != advertised.invite_also)
    });
    if disagrees {
        let roles: Vec<String> = advertised.roles.iter().map(|r| format!("{:?}", r.as_str())).collect();
        bail!(
            "[ca] approval_roles / approval_requires_invite disagree with the namespace's trust \
             context (v{version}), which advertises: {}. Devices read the policy from the \
             context, so the CA enforces exactly that: set approval_roles = [{}] and \
             approval_requires_invite = {} in [ca], or remove both keys",
            advertised.describe(),
            roles.join(", "),
            advertised.invite_also
        );
    }
    Ok(advertised)
}

/// The policy `[ca] approval_roles` / `approval_requires_invite` state;
/// `None` when neither is set. Refuses an unknown role.
pub(crate) fn configured_policy(cfg: &CaTomlConfig) -> Result<Option<ApprovalPolicy>> {
    if cfg.approval_roles.is_none() && cfg.approval_requires_invite.is_none() {
        return Ok(None);
    }
    let defaults = ApprovalPolicy::default();
    let roles = match &cfg.approval_roles {
        Some(roles) => roles
            .iter()
            .map(|r| {
                r.parse::<Role>()
                    .map_err(|e| anyhow::anyhow!("[ca] approval_roles: {e}"))
            })
            .collect::<Result<Vec<Role>>>()?,
        None => defaults.roles,
    };
    Ok(Some(ApprovalPolicy {
        roles,
        invite_also: cfg.approval_requires_invite.unwrap_or(defaults.invite_also),
    }))
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
    if lifetimes.default == 0 || Role::ALL.iter().any(|r| lifetimes.for_role(r.as_str()) == 0) {
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
    Ok(Role::ALL.into_iter().fold(RolePolicy::new(namespace), |policy, role| {
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

/// Issues only when every policy issues, at the shortest validity offered;
/// an identity is held to one key when any policy holds it so.
struct AllIssuance(Vec<Box<dyn IssuancePolicy>>);

impl IssuancePolicy for AllIssuance {
    fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision {
        let mut validity = ctx.max_validity;
        for policy in &self.0 {
            match policy.decide(ctx) {
                IssuanceDecision::Issue { validity: v } => validity = validity.min(v),
                deny @ IssuanceDecision::Deny(_) => return deny,
            }
        }
        IssuanceDecision::Issue { validity }
    }

    fn single_key_identity(&self, key_name: &Name) -> Option<SingleKeyIdentity> {
        self.0.iter().find_map(|p| p.single_key_identity(key_name))
    }

    fn offers_renewal(&self) -> bool {
        self.0.iter().any(|p| p.offers_renewal())
    }
}

/// Load the CA signing identity from the PIB: the certificate at
/// `<pib>/ca/ca-cert.data` (`<identity>/KEY/<id>/<issuer>/<version>`) names
/// the key, whose private half must be in the PIB; the certificate must be
/// signed by the namespace root anchor (the key its KeyLocator names).
async fn load_pib_identity(identity: &Name, pib_path: &Path) -> Result<(KeyChain, Certificate)> {
    let pib = FilePib::open(pib_path).map_err(|e| {
        anyhow::anyhow!(
            "[ca] cannot open PIB {}: {e}; run `ndn-fwd init --namespace <ns>` or set \
             `ephemeral = true` for a throwaway demo CA",
            pib_path.display()
        )
    })?;
    let ca_dir = pib_path.join(CA_DIR);
    let cert_path = ca_dir.join(CA_CERT_FILE);
    let ca_cert = read_cert_wire(&cert_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "[ca] no CA certificate at {}: run `ndn-fwd init --namespace <ns>` to create \
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
        anyhow::anyhow!("[ca] CA key {key_name} not in PIB {}: {e}", pib_path.display())
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
    let verdict =
        ndn_security::verifier::verify_by_sig_type(ca_cert.sig_type, region, sig, &anchor.public_key)
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
        bail!("[ca] anchor {} is expired or not yet valid", spawn.anchor.name);
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
pub(crate) fn spawn(
    prep: CaSpawn,
    cfg: &CaTomlConfig,
    engine: &ForwarderEngine,
) -> Result<RunningCa> {
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
                let renew = if t.renewable { "renewable" } else { "not renewable" };
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
        let prefix: Name = ra.prefix.parse().with_context(|| {
            format!(
                "[ca] invalid require_attestation prefix '{}'",
                ra.prefix
            )
        })?;
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
        _ => builder = builder.issuance(Box::new(AllIssuance(issuance))),
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
            crate::revoke::ca_follow_held(&state, keyring);
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

/// Build the CA's challenge set from config: the `[[ca.challenge]]` list
/// when set, else a `token` challenge from the legacy `tokens`. A CA with
/// neither has no way to authenticate requesters and is refused; `nop`
/// (auto-approve) is only offered when listed explicitly. Every `token`
/// entry feeds one [`TokenStore`] behind one `token` challenge; with a CA
/// `store` (PIB mode), redemptions persist in it so a redeemed token is
/// refused after a restart. Role-carrying tokens are scoped under
/// `token_ns` ([`add_tokens`]).
///
/// `approval`: the namespace and approval policy of a namespace CA, which
/// offers `device-approval` whether listed or not when the policy names
/// roles, with the invite it requires redeemed from the same tokens. The
/// `device-approval` challenge reads the [`ApprovalStore`] `approval_store`
/// opens, returned for the mgmt backend and `/CA/APPROVAL`.
fn build_challenges(
    cfg: &CaTomlConfig,
    store: Option<&Arc<FileCaStore>>,
    token_ns: &Name,
    approval: Option<(&Name, &ApprovalPolicy)>,
    approval_store: impl FnOnce() -> Result<ApprovalStore>,
) -> Result<(Vec<Box<dyn ChallengeHandler>>, Option<ApprovalStore>)> {
    let namespace_ca = approval.is_some();
    let configured: Vec<ndn_config::ChallengeConfig> = if !cfg.challenges.is_empty() {
        cfg.challenges.clone()
    } else if !cfg.tokens.is_empty() {
        vec![ndn_config::ChallengeConfig {
            kind: "token".into(),
            tokens: cfg.tokens.clone(),
            pin: None,
            max_tries: None,
            ttl_secs: None,
            smtp: None,
        }]
    } else {
        bail!(
            "[ca] no challenge configured, so the CA could not authenticate requesters; \
             add `[[ca.challenge]]` entries (kind = \"token\" | \"device-approval\" | \
             \"pin\" | \"email\", or \"nop\" to auto-approve every request in a demo) or \
             `tokens = [...]`"
        )
    };

    // Slots in offer order; the token and device-approval handlers are
    // built once every entry is read.
    enum Slot {
        Built(Box<dyn ChallengeHandler>),
        Token,
        Approval,
    }
    let mut slots = Vec::new();
    let mut tokens: Option<TokenStore> = None;
    for c in &configured {
        match c.kind.as_str() {
            "token" => {
                if tokens.is_none() {
                    tokens = Some(token_store(store)?);
                    slots.push(Slot::Token);
                }
                add_tokens(tokens.as_ref().expect("set above"), &c.tokens, token_ns, namespace_ca)?;
            }
            DEVICE_APPROVAL => {
                if !slots.iter().any(|s| matches!(s, Slot::Approval)) {
                    slots.push(Slot::Approval);
                }
            }
            _ => slots.push(Slot::Built(build_challenge(c)?)),
        }
    }
    if let Some((namespace, policy)) = approval
        && !policy.roles.is_empty()
        && !slots.iter().any(|s| matches!(s, Slot::Approval))
    {
        tracing::info!(
            target: "ca",
            namespace = %namespace,
            "offering the device-approval challenge although [ca] does not list it: the \
             namespace's trust context advertises {}",
            policy.describe()
        );
        slots.push(Slot::Approval);
    }

    let mut approvals = None;
    let mut handlers = Vec::with_capacity(slots.len());
    let mut approval_store = Some(approval_store);
    for slot in slots {
        handlers.push(match slot {
            Slot::Built(handler) => handler,
            Slot::Token => Box::new(TokenChallenge::new(
                tokens.clone().expect("a token slot has its store"),
            )),
            Slot::Approval => {
                let open = approval_store.take().expect("one device-approval slot");
                let store = open()?;
                let mut challenge = DeviceApprovalChallenge::new(store.clone());
                if let Some((namespace, policy)) = approval
                    && policy.invite_also
                    && !policy.roles.is_empty()
                {
                    let Some(tokens) = &tokens else {
                        bail!(
                            "[ca] the namespace's trust context advertises {}, but [ca] offers \
                             no token challenge to redeem the invites: add a [[ca.challenge]] \
                             entry with kind = \"token\" and the invite tokens",
                            policy.describe()
                        );
                    };
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
    Ok((handlers, approvals))
}

/// The CA's invite tokens, their redemptions persisted in `store` when one
/// is given.
fn token_store(store: Option<&Arc<FileCaStore>>) -> Result<TokenStore> {
    match store {
        Some(store) => TokenStore::with_store(Arc::clone(store) as Arc<dyn CaStore>)
            .map_err(|e| anyhow::anyhow!("[ca] loading redeemed tokens: {e}")),
        None => Ok(TokenStore::new()),
    }
}

/// Add `tokens` to `store`. A token naming a role (`member-…`, `guest-…`,
/// as `ndn-fwd-tokens new --role` mints them) is scoped to
/// `<token_ns>/<role>`: it certifies only names under that prefix. Other
/// tokens are unscoped, except on a namespace CA (`namespace_ca`).
///
/// On a namespace CA the issuance policy admits a token only for a member or a
/// guest, after the challenge has consumed it. So every token is scoped
/// there: the scope check refuses a request the policy would refuse
/// *before* the token is spent. Unscoped tokens are scoped to
/// `/<ns>/member` (the only role the policy grants them), and `admin-…` /
/// `node-…` tokens, which could never issue anything, are refused here.
fn add_tokens(
    store: &TokenStore,
    tokens: &[String],
    token_ns: &Name,
    namespace_ca: bool,
) -> Result<()> {
    for token in tokens {
        let role = match token_role(token) {
            Some(role @ (Role::Admin | Role::Node)) if namespace_ca => bail!(
                "[ca] token '{token}' names the {role} role, but a namespace CA never issues \
                 {role} certificates on a token alone; remove it from the config. A {role} \
                 device asks with `ndn-fwd enroll <anchor link> --role {role}` and an admin \
                 approves it (`ndn-fwd approvals approve <code>`)"
            ),
            None if namespace_ca => Some(Role::Member),
            role => role,
        };
        // A token minted with `ndn-fwd-tokens new --ttl` carries its expiry:
        // redeemable until then, measured from now (past: refused).
        let ttl = token_expiry(token).map(|at| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            std::time::Duration::from_secs(at.saturating_sub(now))
        });
        store.add_scoped(
            token.clone(),
            ttl,
            role.map(|role| role_prefix(token_ns, role)),
        );
    }
    Ok(())
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
        read_cert_wire(&dir.join(CA_DIR).join(ANCHOR_CERT_FILE))
            .unwrap()
            .expect("init writes the root anchor cert")
    }

    struct RunningCa {
        client: NdncertClient,
        approvals: Option<ApprovalStore>,
        state: Arc<ndn_cert::CaState>,
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
    async fn run_ca(cfg: &CaTomlConfig, pib: &Path) -> RunningCa {
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
        let prefix = spawn_state.prefix.clone();
        let running = spawn(spawn_state, cfg, &engine).expect("CA spawns");
        RunningCa {
            client: NdncertClient::new(ndn_app::Consumer::from_handle(client_handle), prefix),
            approvals: running.approvals,
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

    /// A one-time token redeemed before a restart must stay spent although
    /// it is still listed in the config; only its hash is persisted.
    #[tokio::test]
    async fn redeemed_token_is_refused_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token", &["invite-1", "invite-2"])]);

        let mut ca = run_ca(&cfg, dir.path()).await;
        enroll(&mut ca.client, "member/laptop", "token", token("invite-1"))
            .await
            .expect("first redemption enrolls");
        ca.stop().await;

        let mut ca = run_ca(&cfg, dir.path()).await;
        let replay = enroll(&mut ca.client, "member/phone", "token", token("invite-1")).await;
        assert!(replay.is_err(), "redeemed token must be refused after restart: {replay:?}");
        enroll(&mut ca.client, "member/phone", "token", token("invite-2"))
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
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token", &["invite-1", "invite-2", "invite-3"])]);

        let mut ca = run_ca(&cfg, dir.path()).await;
        let laptop = enroll(&mut ca.client, "member/laptop", "token", token("invite-1"))
            .await
            .expect("laptop enrolls");
        let laptop = (*laptop.name).clone();
        let phone = enroll(&mut ca.client, "member/phone", "token", token("invite-2"))
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
            revoke_as(&mut ca.client, &laptop, device_signer("member/laptop")).await,
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
        let again = enroll(&mut ca.client, "member/laptop", "token", token("invite-3")).await;
        assert!(again.is_err(), "a revoked key is not re-certified: {again:?}");
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
        let cfg = namespace_cfg(vec![challenge(
            "token",
            &["invite-1", "invite-2", "invite-3", "invite-4"],
        )]);
        let mut ca = run_ca(&cfg, dir.path()).await;
        let phone = enroll(&mut ca.client, "member/phone", "token", token("invite-1"))
            .await
            .expect("phone enrolls");
        let phone = (*phone.name).clone();
        let new_key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[8; 32],
            "/home/bob/member/phone/KEY/k2".parse().unwrap(),
        ));
        let taken = enroll_with(&mut ca.client, Arc::clone(&new_key), "token", token("invite-2"))
            .await;
        assert!(taken.is_err(), "the name is held by the first key: {taken:?}");

        let key = ndn_cert::key_name_of(&phone).unwrap();
        assert_eq!(ca_serves_key(&mut ca.client, &key).await, Some(phone.clone()), "by key name");
        let ca_cert = ca_serves_key(&mut ca.client, &ndn_cert::ca_key_name(&"/home/bob".parse().unwrap()))
            .await
            .expect("the CA's own certificate by its key name");
        assert!(ndn_security::cert_name::is_cert_name(&ca_cert), "{ca_cert}");
        let out = ca.state.revoke_issued_under(&key);
        assert_eq!(out.revoked, vec![phone.clone()]);
        assert!(out.not_persisted.is_none());
        assert!(!ca_serves(&mut ca.client, &phone).await, "a revoked cert is not served");
        assert_eq!(ca_serves_key(&mut ca.client, &key).await, None, "nor by key name");
        assert_eq!(
            dir.path().join(CA_DIR).join("revoked").read_dir().unwrap().count(),
            1,
            "revocation persisted"
        );
        assert!(ca.state.revoke_issued_under(&key).revoked.is_empty(), "revoked once");

        let again = enroll(&mut ca.client, "member/phone", "token", token("invite-3")).await;
        assert!(again.is_err(), "the revoked key is never certified again: {again:?}");
        enroll_with(&mut ca.client, new_key, "token", token("invite-4"))
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

    #[tokio::test]
    async fn ca_without_challenges_refuses_to_start() {
        let cfg = CaTomlConfig {
            enabled: true,
            ephemeral: true,
            ..CaTomlConfig::default()
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
        let mut cfg = namespace_cfg(vec![challenge("nop", &[])]);
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
        let mut cfg = namespace_cfg(vec![challenge("nop", &[])]);
        cfg.ephemeral = true;
        cfg.prefix = "/home/bob/CA".to_string();
        let err = prepare(&cfg, no_pib()).await.err().expect("/CA prefix rejected");
        assert!(err.to_string().contains("ends in /CA"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn pib_ca_without_namespace_identity_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        FilePib::new(dir.path()).unwrap();
        let cfg = namespace_cfg(vec![challenge("token", &["t"])]);
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
        let root = write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![challenge("token", &["invite-1", "invite-2"])]);
        let ca_cert = read_cert_wire(&dir.path().join(CA_DIR).join(CA_CERT_FILE))
            .unwrap()
            .unwrap();

        let mut ca = run_ca(&cfg, dir.path()).await;
        let first = enroll(&mut ca.client, "member/laptop", "token", token("invite-1"))
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

        let second = enroll(&mut ca.client, "member/phone", "token", token("invite-2"))
            .await
            .expect("enrollment after restart");
        for issued in [&first, &second] {
            let cert = Certificate::decode(issued).unwrap();
            // The KeyLocator names the CA's key, not one certificate of it.
            assert_eq!(cert.issuer.as_deref(), Some(&ca_cert.key_name()));
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

    fn ephemeral_approval_cfg() -> CaTomlConfig {
        let mut cfg = namespace_cfg(vec![challenge("device-approval", &[])]);
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
                    assert_eq!(row.approver, "the CA host's local operator uid 1000 (alice)");
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
        assert!(result.is_err(), "denied request must not enroll: {result:?}");
        ca.stop().await;
    }

    /// A namespace CA (PIB-backed `/home/bob/CA`) issues only role-layout names, and
    /// an invite token's role bounds what it can certify: a member token never
    /// yields an admin cert, an unscoped one never a guest cert. A request the
    /// CA refuses does not spend the token: it still enrolls a member after.
    #[tokio::test]
    async fn namespace_ca_tokens_are_bounded_by_role() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let tokens = ["member-m1", "member-m2", "guest-g1", "guest-g2", "invite-1"];
        let cfg = namespace_cfg(vec![challenge("token", &tokens)]);
        let mut ca = run_ca(&cfg, dir.path()).await;

        // A member token is scoped to /home/bob/member: no admin cert.
        let admin = enroll(&mut ca.client, "admin/evil", "token", token("member-m1")).await;
        assert!(admin.is_err(), "member token must not certify an admin: {admin:?}");
        // Nor does an unscoped token (admins need a device approval), nor a
        // node, guest or non-role name.
        for name in ["admin/evil", "node/vps", "guest/bob", "laptop"] {
            let refused = enroll(&mut ca.client, name, "token", token("invite-1")).await;
            assert!(refused.is_err(), "an unscoped token must not certify {name}: {refused:?}");
        }

        // The refused requests spent neither token: both still enroll a member.
        enroll(&mut ca.client, "member/laptop", "token", token("invite-1"))
            .await
            .expect("an unscoped token survives refused requests and certifies a member");
        // Members by member (or unscoped) tokens; guests only by guest tokens.
        let phone = enroll(&mut ca.client, "member/phone", "token", token("member-m1"))
            .await
            .expect("member token certifies a member");
        assert_eq!(
            ndn_security::cert_name::key_name_of(&phone.name).to_string(),
            "/home/bob/member/phone/KEY/k1",
            "a certificate of the requested key: {}",
            phone.name
        );
        let guest = enroll(&mut ca.client, "guest/alice", "token", token("member-m2")).await;
        assert!(guest.is_err(), "member token must not certify a guest: {guest:?}");
        let member = enroll(&mut ca.client, "member/tv", "token", token("guest-g1")).await;
        assert!(member.is_err(), "guest token must not certify a member: {member:?}");
        enroll(&mut ca.client, "guest/alice", "token", token("guest-g2"))
            .await
            .expect("guest token certifies a guest");
        ca.stop().await;
    }

    /// On a namespace CA an admin cert needs an admin's device approval: the token
    /// path is refused, the approved device-approval path issues it.
    #[tokio::test]
    async fn namespace_ca_admin_cert_needs_device_approval() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let cfg = namespace_cfg(vec![
            challenge("token", &["invite-1"]),
            challenge("device-approval", &[]),
        ]);
        let mut ca = run_ca(&cfg, dir.path()).await;
        let by_token = enroll(&mut ca.client, "admin/tablet", "token", token("invite-1")).await;
        assert!(by_token.is_err(), "admin by token must be refused: {by_token:?}");

        let store = ca.approvals.clone().expect("device-approval store is exposed");
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

    /// On a namespace CA an admin or node token could never issue anything, so the
    /// CA refuses to start with one instead of letting requests spend it.
    #[test]
    fn namespace_ca_refuses_admin_and_node_tokens() {
        let ns: Name = "/home/bob".parse().unwrap();
        for t in ["admin-a1", "node-n1"] {
            let tokens = [t.to_string()];
            assert!(add_tokens(&TokenStore::new(), &tokens, &ns, true).is_err(), "{t}");
            assert!(add_tokens(&TokenStore::new(), &tokens, &ns, false).is_ok(), "{t}");
        }
    }

    /// A namespace CA enforces the approval policy its trust context
    /// advertises: it offers `device-approval` although `[ca]` lists only
    /// tokens, and refuses to start when `[ca]` states another policy.
    #[tokio::test]
    async fn namespace_ca_enforces_the_policy_its_context_advertises() {
        let dir = tempfile::tempdir().unwrap();
        write_namespace_pib(dir.path());
        let mut cfg = namespace_cfg(vec![challenge("token", &["invite-1"])]);
        let (_, spawn_state) = prepare(&cfg, dir.path()).await.expect("the CA prepares");
        let kinds: Vec<_> = spawn_state.challenges.iter().map(|c| c.challenge_type()).collect();
        assert_eq!(kinds, ["token", DEVICE_APPROVAL]);
        assert_eq!(spawn_state.approval_policy, Some(ApprovalPolicy::default()));

        cfg.approval_roles = Some(vec!["node".into(), "admin".into()]);
        cfg.approval_requires_invite = Some(false);
        prepare(&cfg, dir.path()).await.expect("[ca] restating the context's policy");
        for (roles, invite) in [(vec!["admin".to_string()], false), (vec!["admin".into(), "node".into()], true)] {
            cfg.approval_roles = Some(roles);
            cfg.approval_requires_invite = Some(invite);
            let err = prepare(&cfg, dir.path()).await.err().expect("a disagreeing [ca] is refused");
            assert!(err.to_string().contains("disagree with the namespace's trust context"), "{err}");
        }
    }

    /// `ndn-fwd init -c` writes the `[ca]` link policy into the context
    /// (unset keys: the default), and a namespace CA refuses to start when
    /// `[ca]` states another link policy than its context.
    #[tokio::test]
    async fn the_context_carries_the_configured_link_policy_and_the_ca_checks_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = namespace_cfg(vec![challenge("token", &["invite-1"])]);
        cfg.link_roles = Some(vec!["admin".into(), "node".into()]);
        cfg.enrollment_links = Some(false);
        let link = configured_link_policy(&cfg, &LinkPolicy::default()).unwrap().unwrap();
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        ndn_cert::init_namespace_in_pib_with(
            &pib,
            &ns,
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
            &ApprovalPolicy::default(),
            &link,
        )
        .await
        .unwrap();
        let (ctx, _) = ndn_cert::read_stored_context(dir.path(), &ns).unwrap().unwrap();
        let expected = LinkPolicy {
            roles: vec!["admin".into(), "node".into()],
            relay_roles: vec!["node".into()],
            enrollment_links: false,
        };
        assert_eq!(ctx.stated_link_policy(), Some(&expected));

        prepare(&cfg, dir.path()).await.expect("[ca] restating the context's link policy");
        cfg.link_roles = Some(Vec::new());
        let err = prepare(&cfg, dir.path()).await.err().expect("a disagreeing [ca] is refused");
        assert!(err.to_string().contains("ndn-fwd schema update -c <config>"), "{err}");

        cfg.link_roles = Some(vec!["admin".into()]);
        cfg.relay_roles = Some(vec!["node".into()]);
        assert!(configured_link_policy(&cfg, &LinkPolicy::default()).is_err(), "a relay that may not link");
        cfg.link_roles = Some(vec!["robot".into()]);
        assert!(configured_link_policy(&cfg, &LinkPolicy::default()).is_err(), "an unknown role");
    }
}
