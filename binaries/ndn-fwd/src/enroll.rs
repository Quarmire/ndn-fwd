//! The running daemon's side of `ndn-fwd enroll`: the `security/enroll` and
//! `security/enroll-status` management verbs, and the status watch that
//! finishes an enrollment the moment an admin approves it.
//!
//! The daemon owns every piece of state: it generates the device key
//! `/<ns>/<role>/<device>/KEY/<id>` in its own PIB (the private key never
//! leaves it), adopts the namespace's trust context if it is not held (the
//! link names the expected fingerprint of its root), obtains a certificate
//! from the namespace's CA, stores it beside the key (and the issuer
//! certificates of its chain under `<pib>/issuers`, [`ndn_cert::issuers`]),
//! and makes the identity the PIB's default — loaded at every start unless
//! `[security] identity` names another one (the config file is never
//! edited). The running daemon then signs its management responses and
//! discovery records with the new key from the next packet on. DV routing in
//! the `static`/`lvs` trust modes keeps the key it started with (neighbours
//! list it in their `trusted_keys`) until the next start.
//!
//! How the certificate is obtained is the namespace's policy, read from its
//! trust context ([`ndn_cert::ApprovalPolicy`]):
//!
//! - a role it certifies **by invite** (member, guest by default): an
//!   `ndn-trust://invite` link's token is redeemed in one exchange
//!   ([`ndn_identity::enroll_with_invite_via_engine`]);
//! - a role it certifies **on an admin's approval** (admin, node by
//!   default): the request opens a durable record at the CA
//!   ([`ndn_cert::approval`]) and answers `pending` with the request id and
//!   the verification code, computed from this node's own key. The daemon
//!   keeps an outgoing request record under `<pib>/requests/`
//!   ([`ndn_cert::RequestStore`]) and keeps one held status Interest
//!   outstanding at the CA for it ([`spawn_status_watch`]), across restarts
//!   of either side, until the record resolves: approved — the CA answers
//!   at once and the certificate is issued and installed with no further
//!   action; denied or expired — the record says why and what to do, and
//!   the key is deleted. With an invite link too when the namespace
//!   requires one beside the approval.
//!
//! A failed enrollment leaves the previous state: the new key (and anything
//! stored for it) is deleted and the default identity is only changed as the
//! last step, after the certificate is stored.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ndn_cert::roles::{Role, parse_device_identity, parse_device_key};
use ndn_cert::{
    AnchorLink, ApprovalEnrollError, ApprovalPoll, ApprovalPolicy, InviteEnrollError, InviteLink,
    IssuedCertificate, OutgoingRequest, OutgoingState, RequestStatus, RequestStore,
    anchor_fingerprint, new_device_key_name,
};
use ndn_mgmt::{
    AdoptedContextInfo, ContextRefreshInfo, EnrollOutcome, EnrollRequest, EnrolledInfo,
    PendingEnrollInfo, RefreshState, TrustRefusal,
};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, Signer, SignedTrustContext};
use tokio_util::sync::CancellationToken;

use crate::context_adopt::{TrustAdmin, hex, refusal};
use crate::context_refresh::refresh_contexts;

fn status_of(e: &InviteEnrollError) -> u64 {
    use InviteEnrollError as E;
    match e {
        E::BadInvite(_)
        | E::NotInvite(_)
        | E::InviteField { .. }
        | E::InviteRole(_)
        | E::TokenRole { .. }
        | E::Device(_)
        | E::KeyOutsideInvite { .. }
        | E::NoExpectedFingerprint { .. } => status::BAD_PARAMS,
        E::ContextUnreachable { .. } | E::CaUnreachable { .. } => 504,
        E::NameRefused(_) => 409,
        E::Adopt {
            source: ndn_cert::AdoptError::InProgress(_),
            ..
        } => 409,
        E::Signing(_) => status::SERVER_ERROR,
        _ => status::UNAUTHORIZED,
    }
}

pub(crate) fn iso(ns: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(ns);
    format!("{}Z", String::from_utf8_lossy(&basic))
}

/// The device component of `identity` when it is `<identity_prefix>/<device>`.
fn device_of<'a>(invite: &InviteLink, identity: &'a Name) -> Result<&'a str, TrustRefusal> {
    let comps = identity.components();
    let device = (identity.has_prefix(&invite.identity_prefix)
        && comps.len() == invite.identity_prefix.len() + 1)
        .then(|| std::str::from_utf8(&comps[comps.len() - 1].value).ok())
        .flatten();
    device.ok_or_else(|| {
        refusal(
            status::BAD_PARAMS,
            format!(
                "the identity to enroll, {identity}, is not <device> under the invite's \
                 identity namespace {}",
                invite.identity_prefix
            ),
        )
    })
}

/// A device key of a namespace this PIB holds a currently valid certificate
/// for.
struct Certified {
    key: Name,
    valid_until: u64,
    /// What the held trust context revokes on the certificate's chain — the
    /// key itself, or an issuer up to the root: the certificate validates
    /// nowhere.
    revoked: Option<Name>,
}

impl Certified {
    /// `<key> (valid until <ISO 8601>)`.
    fn still_valid(&self) -> String {
        format!("{} (valid until {})", self.key, iso(self.valid_until))
    }

    /// `<key> (revoked: <name>)` when the trust context revokes its chain.
    fn unusable(&self) -> Option<String> {
        Some(format!("{} (revoked: {})", self.key, self.revoked.as_ref()?))
    }
}

/// Device keys in `namespace` this PIB holds a currently valid certificate
/// for, each with what revokes its chain, if anything. Issuer certificates
/// come from those kept under `<pib>/issuers` ([`ndn_cert::issuers`]), else
/// the validation cache.
fn certified_in(admin: &TrustAdmin, pib: &FilePib, namespace: &Name) -> Vec<Certified> {
    let kept: Vec<Certificate> = ndn_cert::issuers::stored_issuer_certs(&admin.pib_root)
        .into_iter()
        .filter_map(|wire| Certificate::decode(&Data::decode(wire).ok()?).ok())
        .collect();
    let issuer_cert = |key: &Name| {
        kept.iter()
            .filter(|c| c.name.has_prefix(key))
            .max_by_key(|c| c.valid_from)
            .cloned()
            .or_else(|| admin.engine.security()?.cert_cache().get_valid(key))
    };
    let mut held: Vec<Certified> = pib
        .list_keys()
        .unwrap_or_default()
        .into_iter()
        .filter(|k| parse_device_key(namespace, k).is_some())
        .filter_map(|key| {
            let cert = pib.get_cert(&key).ok()?;
            if !cert.is_valid_now() {
                return None;
            }
            let revoked = revoked_on_chain(&admin.keyring.context_for(&key), &cert, &issuer_cert);
            Some(Certified {
                key,
                valid_until: cert.valid_until,
                revoked,
            })
        })
        .collect();
    held.sort_by(|a, b| a.key.cmp(&b.key));
    held
}

/// [`certified_in`] without `key` (the key just enrolled).
fn held_besides(admin: &TrustAdmin, pib: &FilePib, namespace: &Name, key: &Name) -> Vec<Certified> {
    let mut held = certified_in(admin, pib, namespace);
    held.retain(|c| &c.key != key);
    held
}

/// How long enrollment waits for the check of its namespace's trust
/// context: the metadata fetch and the newest version's fetch. A longer
/// catch-up across several versions (after a recovery) is left to `ndn-fwd
/// context refresh`, and the enrollment reports that it judged against the
/// version held.
pub(crate) fn context_check_budget() -> Duration {
    ndn_app::DEFAULT_TIMEOUT * 2
}

/// Check the held trust context of `namespace` for a newer version through
/// the daemon's refresh path ([`refresh_contexts`]: adopted only under the
/// continuity rule, then stored and published), so certificates are judged
/// against the newest version reachable. `None` when the context is not
/// held. Best effort: whatever the outcome, the held version stays in force,
/// and the result says which version the judgement used.
async fn check_context(admin: &TrustAdmin, namespace: &Name) -> Option<ContextRefreshInfo> {
    let held = admin.keyring.version_of(namespace)?;
    let not_checked = |detail: String| ContextRefreshInfo {
        namespace: namespace.to_string(),
        state: RefreshState::Failed,
        held_version: held,
        version: held,
        revoked: Vec::new(),
        detail,
    };
    let budget = context_check_budget();
    // Dropping the refresh at the deadline is safe: it adopts, stores and
    // publishes only after its last fetch, with no await in between.
    match tokio::time::timeout(budget, refresh_contexts(admin, Some(namespace.clone()))).await {
        Ok(Ok(mut results)) => results.pop(),
        Ok(Err(e)) => Some(not_checked(e.reason)),
        Err(_) => Some(not_checked(format!(
            "no newer version was confirmed within {}s (following several versions takes \
             longer); `ndn-fwd context refresh {namespace}` completes the check",
            budget.as_secs()
        ))),
    }
}

/// The clause a refusal adds when the check of the trust context did not
/// confirm the version held is the newest: the judgement used that version.
fn judged_on_held(check: &ContextRefreshInfo) -> String {
    match check.state {
        RefreshState::Updated | RefreshState::Current | RefreshState::Source => String::new(),
        RefreshState::UpstreamOlder
        | RefreshState::Behind
        | RefreshState::Unreachable
        | RefreshState::Failed => {
            format!(
                " (judged against the trust context v{} this node holds; whether a newer \
                 version revokes it could not be checked: {})",
                check.version, check.detail
            )
        }
    }
}

/// The first name on `cert`'s chain that `ctx` revokes: each certificate
/// (a revoked key or identity is a prefix of its certificates' names) and
/// each issuer key, walking issuer certificates `issuer_cert` resolves up to
/// a self-signed one or one it cannot resolve.
fn revoked_on_chain(
    ctx: &SignedTrustContext,
    cert: &Certificate,
    issuer_cert: impl Fn(&Name) -> Option<Certificate>,
) -> Option<Name> {
    const MAX_CHAIN: usize = 8;
    let mut current = cert.clone();
    for _ in 0..MAX_CHAIN {
        if ctx.is_revoked(&current.name) {
            return Some((*current.name).clone());
        }
        let issuer = current.issuer.clone()?;
        if ctx.is_revoked(&issuer) {
            return Some((*issuer).clone());
        }
        let next = issuer_cert(&issuer)?;
        if next.name == current.name {
            return None;
        }
        current = next;
    }
    None
}

/// Delete a key this enrollment generated (and whatever was stored for it).
fn discard(pib: &FilePib, key: &Name) {
    if let Err(e) = pib.delete_key(key) {
        tracing::error!(
            target: "security",
            key = %key,
            error = %e,
            "could not delete the key of a failed enrollment; it is not the default identity"
        );
    }
}

/// End this node's pending requests the CA never answered before they
/// expired ([`RequestStore::expire_overdue`]) and delete their keys from the
/// PIB, so a new request may go out.
fn expire_overdue(admin: &TrustAdmin, store: &RequestStore) -> Result<(), TrustRefusal> {
    let ended = store.expire_overdue().map_err(|e| {
        refusal(status::SERVER_ERROR, format!("cannot update this node's request records: {e}"))
    })?;
    if ended.is_empty() {
        return Ok(());
    }
    let pib = FilePib::open(&admin.pib_root);
    for r in ended {
        match (&pib, r.key_name.parse::<Name>()) {
            (Ok(pib), Ok(key)) => discard(pib, &key),
            (Err(e), _) => tracing::error!(target: "security", key = %r.key_name, error = %e, "could not open the PIB to delete the key of an expired request: delete it from the PIB"),
            (_, Err(_)) => {}
        }
        tracing::warn!(target: "security", request = %r.request_id, key = %r.key_name, "the CA never answered before the request expired; it ended here and its key was deleted: ask again (`ndn-fwd enroll`)");
    }
    Ok(())
}

/// The link `ndn-fwd enroll` was given.
enum EnrollLink {
    /// `ndn-trust://invite`: a token of the namespace's CA.
    Invite(InviteLink),
    /// `ndn-trust://anchor`: the namespace and its root's expected
    /// fingerprint, for a role it certifies on an admin's approval.
    Anchor(AnchorLink),
}

impl EnrollLink {
    fn parse(uri: &str) -> Result<Self, TrustRefusal> {
        if let Ok(invite) = InviteLink::from_uri(uri) {
            return Ok(Self::Invite(invite));
        }
        if let Ok(anchor) = AnchorLink::from_uri(uri) {
            return Ok(Self::Anchor(anchor));
        }
        // Report the invite's own reason: an invite is the common case.
        let e = InviteLink::from_uri(uri).err().map(|e| e.to_string()).unwrap_or_default();
        Err(refusal(
            status::BAD_PARAMS,
            format!(
                "the link is neither an invite nor an anchor link ({e}): give an \
                 ndn-trust://invite link (`ndn-fwd-tokens new` prints one) or, for a role the \
                 namespace certifies on an admin's approval, its ndn-trust://anchor link \
                 (`ndn-fwd init` prints it as anchor_uri)"
            ),
        ))
    }

    fn namespace(&self) -> &Name {
        match self {
            Self::Invite(invite) => &invite.namespace,
            Self::Anchor(anchor) => &anchor.namespace,
        }
    }

    fn expected_fingerprint(&self) -> Option<[u8; 32]> {
        match self {
            Self::Invite(invite) => invite.expected_fingerprint,
            Self::Anchor(anchor) => Some(anchor.expected_fingerprint),
        }
    }
}

/// Hold the trust context of the namespace `link` names: adopt it (and keep
/// it) when it is not held — the link must name its root's expected
/// fingerprint — else check the held one is signed by the root the link
/// expects. `Some`: the context adopted now.
async fn ensure_context(
    admin: &TrustAdmin,
    link: &EnrollLink,
) -> Result<Option<AdoptedContextInfo>, TrustRefusal> {
    let namespace = link.namespace();
    if let Some(held) = held_context(admin, namespace) {
        let Some(expected) = link.expected_fingerprint() else {
            return Ok(None);
        };
        let fingerprints: Vec<[u8; 32]> = held
            .anchors()
            .iter()
            .map(|a| anchor_fingerprint(a.value()))
            .collect();
        if fingerprints.contains(&expected) {
            return Ok(None);
        }
        return Err(refusal(
            status::UNAUTHORIZED,
            format!(
                "the trust context this node holds for {namespace} is signed by a different \
                 root (fingerprint {}) than the link expects ({}): check where the link came \
                 from; this node keeps the context it holds",
                fingerprints.first().map(|f| hex(f)).unwrap_or_default(),
                hex(&expected)
            ),
        ));
    }
    let from_invite;
    let anchor = match link {
        EnrollLink::Anchor(anchor) => anchor,
        EnrollLink::Invite(invite) => {
            let Some(expected_fingerprint) = invite.expected_fingerprint else {
                let e = InviteEnrollError::NoExpectedFingerprint {
                    namespace: namespace.to_string(),
                };
                return Err(refusal(status_of(&e), e.to_string()));
            };
            from_invite = AnchorLink {
                namespace: namespace.clone(),
                expected_fingerprint,
                min_version: None,
                context_data: None,
            };
            &from_invite
        }
    };
    admin.adopt_link(anchor).await.map(Some)
}

/// The trust context this node holds for `namespace`.
fn held_context(admin: &TrustAdmin, namespace: &Name) -> Option<Arc<SignedTrustContext>> {
    admin
        .keyring
        .contexts()
        .into_iter()
        .find(|c| c.namespace() == namespace)
}

/// What enrollment in `namespace` needs an admin's approval for: what its
/// held trust context advertises (the default for a context made before
/// the hint carried it).
fn namespace_policy(admin: &TrustAdmin, namespace: &Name) -> ApprovalPolicy {
    held_context(admin, namespace)
        .map(|ctx| ApprovalPolicy::of_context(&ctx))
        .unwrap_or_default()
}

/// The prefix of the CA of `namespace` its held trust context names, else
/// the namespace itself.
fn ca_prefix_of(admin: &TrustAdmin, namespace: &Name) -> Name {
    held_context(admin, namespace)
        .map(|ctx| ndn_cert::approval::ca_prefix_of(&ctx))
        .unwrap_or_else(|| namespace.clone())
}

pub(crate) async fn enroll(
    admin: &TrustAdmin,
    request: EnrollRequest,
) -> Result<EnrollOutcome, TrustRefusal> {
    let Ok(_one_at_a_time) = admin.enrolling.try_lock() else {
        return Err(refusal(
            409,
            "another enrollment is running on this node; wait for it to finish",
        ));
    };
    let link = EnrollLink::parse(&request.link_uri)?;
    let namespace = link.namespace().clone();
    let identity = request.identity.clone();
    let Some(device) = parse_device_identity(&namespace, &identity) else {
        return Err(refusal(
            status::BAD_PARAMS,
            format!(
                "the identity to enroll, {identity}, is not /<namespace>/<role>/<device> in the \
                 namespace {namespace} the link names (roles: admin, member, node, guest; a \
                 device name of letters, digits, '-', '_', '.')"
            ),
        ));
    };
    // The device name the invite admits, before anything is fetched.
    if let EnrollLink::Invite(invite) = &link
        && device.role == invite.role
    {
        device_of(invite, &identity)?;
    }

    let adopted_context = ensure_context(admin, &link).await?;
    let policy = namespace_policy(admin, &namespace);
    let by_approval = policy.roles.contains(&device.role);
    let invite = match (&link, by_approval) {
        (EnrollLink::Invite(invite), false) if invite.role == device.role => Some(invite),
        (_, true) => None,
        (EnrollLink::Invite(invite), false) => {
            return Err(refusal(
                status::BAD_PARAMS,
                format!(
                    "the invite admits a {} device, not a {} device; {namespace} certifies {} \
                     devices by invite: ask for a {} invite (`ndn-fwd-tokens new --role {}`)",
                    invite.role, device.role, device.role, device.role, device.role
                ),
            ));
        }
        (EnrollLink::Anchor(_), false) => {
            return Err(refusal(
                status::BAD_PARAMS,
                format!(
                    "{namespace} certifies {} devices by invite, not on an admin's approval \
                     ({}): ask an admin for an invite (`ndn-fwd-tokens new --role {}` on the \
                     root device) and run `ndn-fwd enroll <invite link>`",
                    device.role,
                    policy.describe(),
                    device.role
                ),
            ));
        }
    };
    let token = match (&link, by_approval && policy.invite_also) {
        (EnrollLink::Invite(invite), true) => Some(invite.token.clone()),
        (EnrollLink::Anchor(_), true) => {
            return Err(refusal(
                status::BAD_PARAMS,
                format!(
                    "{namespace} certifies a {role} device only on an invite AND an admin's \
                     approval: ask an admin for an invite and run `ndn-fwd enroll <invite link> \
                     --role {role}`",
                    role = device.role
                ),
            ));
        }
        _ => None,
    };

    let pib = FilePib::new(&admin.pib_root).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot open the PIB {}: {e}", admin.pib_root.display()),
        )
    })?;
    let previous_identity = pib.get_default_identity().ok().flatten();
    // Judge the certificates held against the namespace's newest trust
    // context, not a possibly stale held one: a newer version may revoke one.
    let context_check = check_context(admin, &namespace).await;
    let held: Vec<Certified> = certified_in(admin, &pib, &namespace)
        .into_iter()
        .filter(|c| c.revoked.is_none())
        .collect();
    if !held.is_empty() && !request.force {
        let still_valid: Vec<String> = held.iter().map(Certified::still_valid).collect();
        return Err(refusal(
            409,
            format!(
                "this node already holds a certificate in {namespace}: {}{}. To enroll another \
                 key anyway, run again with --force and another --device name (the CA certifies \
                 a new key for a device name it already certified only once that certificate \
                 is revoked or an admin approves the new key); the certificate this node holds \
                 stays valid until it expires or is revoked",
                still_valid.join(", "),
                context_check.as_ref().map(judged_on_held).unwrap_or_default()
            ),
        ));
    }

    let enrolling = Enrolling {
        namespace,
        identity,
        previous_identity,
        adopted_context,
        context_check,
    };
    match invite {
        Some(invite) => enroll_by_invite(admin, &pib, invite, enrolling).await,
        None => {
            let ca_prefix = match &link {
                EnrollLink::Invite(invite) => invite.ca_prefix.clone(),
                EnrollLink::Anchor(_) => ca_prefix_of(admin, &enrolling.namespace),
            };
            enroll_by_approval(admin, &pib, &ca_prefix, device.role, token, enrolling).await
        }
    }
}

/// What an enrollment knows before it asks the CA.
struct Enrolling {
    namespace: Name,
    identity: Name,
    previous_identity: Option<Name>,
    adopted_context: Option<AdoptedContextInfo>,
    context_check: Option<ContextRefreshInfo>,
}

/// Generate the device key for `identity` in the PIB.
fn generate_key(admin: &TrustAdmin, pib: &FilePib, identity: &Name) -> Result<(Name, Arc<dyn Signer>), TrustRefusal> {
    let key = new_device_key_name(identity);
    let generated = pib.generate_ed25519(&key).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot generate the device key in {}: {e}", admin.pib_root.display()),
        )
    })?;
    Ok((key, Arc::new(generated)))
}

async fn enroll_by_invite(
    admin: &TrustAdmin,
    pib: &FilePib,
    invite: &InviteLink,
    enrolling: Enrolling,
) -> Result<EnrollOutcome, TrustRefusal> {
    let identity = &enrolling.identity;
    let (key, signer) = generate_key(admin, pib, identity)?;
    tracing::info!(
        target: "security",
        key = %key,
        ca = %invite.ca_prefix,
        "enrolling with an invite"
    );
    let issued = match ndn_identity::enroll_with_invite_via_engine(
        &admin.engine,
        &admin.keyring,
        invite,
        Arc::clone(&signer),
    )
    .await
    {
        Ok(enrollment) => enrollment.issued,
        Err(failure) => {
            discard(pib, &key);
            let mut reason = failure.error.to_string();
            if let Some(adopted) = &enrolling.adopted_context {
                reason.push_str(&format!(
                    ". The trust context {} v{} was adopted on the way and stays adopted",
                    adopted.namespace, adopted.version
                ));
            }
            tracing::warn!(
                target: "security",
                identity = %identity,
                error = %reason,
                "enrollment failed; nothing was kept for the new key"
            );
            return Err(refusal(status_of(&failure.error), reason));
        }
    };
    install(
        admin,
        pib,
        &key,
        signer,
        &issued,
        enrolling,
        "The token is spent: fix the PIB directory and ask for a new invite",
    )
    .await
    .map(EnrollOutcome::Enrolled)
}

/// The status code a refused approval request is answered with.
fn approval_status(e: &ApprovalEnrollError) -> u64 {
    match e {
        ApprovalEnrollError::CaUnreachable { .. } | ApprovalEnrollError::UntrustedAnswer(_) => 504,
        ApprovalEnrollError::NameRefused(_) => 409,
        ApprovalEnrollError::Signing(_) => status::SERVER_ERROR,
        ApprovalEnrollError::Expired(_) => 410,
        ApprovalEnrollError::Denied(_)
        | ApprovalEnrollError::CaRefused(_)
        | ApprovalEnrollError::IssuedCertificate(_) => status::UNAUTHORIZED,
    }
}

/// The `<pib>/requests` store of this node's requests for an admin's
/// approval.
fn request_store(admin: &TrustAdmin) -> Result<RequestStore, TrustRefusal> {
    RequestStore::open(admin.pib_root.join(REQUESTS_DIR)).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot open this node's request records: {e}"),
        )
    })
}

/// Where the outgoing requests live, beside the PIB.
const REQUESTS_DIR: &str = "requests";

fn pending_info(
    request: &OutgoingRequest,
    adopted_context: Option<AdoptedContextInfo>,
) -> PendingEnrollInfo {
    PendingEnrollInfo {
        identity: request.identity.clone(),
        key: request.key_name.clone(),
        namespace: request.namespace.clone(),
        ca: request.ca_prefix.clone(),
        request: request.request_id.clone(),
        code: request.code.clone(),
        expires: match request.expires_secs {
            0 => String::new(),
            secs => ndn_cert::approval::iso_secs(secs),
        },
        adopted_context,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Ask the CA at `ca_prefix` to certify a new key for the identity on an
/// admin's approval: answered `pending` (the request is recorded under
/// `<pib>/requests/` and [`spawn_status_watch`] finishes it), or `enrolled` if
/// the CA issued at once. A request for this identity still pending is
/// answered as it stands: no second key, no second request.
async fn enroll_by_approval(
    admin: &TrustAdmin,
    pib: &FilePib,
    ca_prefix: &Name,
    role: Role,
    token: Option<String>,
    enrolling: Enrolling,
) -> Result<EnrollOutcome, TrustRefusal> {
    let requests = request_store(admin)?;
    let identity = enrolling.identity.to_string();
    let outstanding = expire_overdue(admin, &requests).and_then(|()| {
        requests.outstanding(&identity).map_err(|e| {
            refusal(status::SERVER_ERROR, format!("cannot read this node's request records: {e}"))
        })
    })?;
    if let Some(outstanding) = outstanding {
        return Ok(EnrollOutcome::Pending(pending_info(
            &outstanding,
            enrolling.adopted_context,
        )));
    }
    let (key, signer) = generate_key(admin, pib, &enrolling.identity)?;
    tracing::info!(
        target: "security",
        key = %key,
        ca = %ca_prefix,
        role = %role,
        "asking for an admin's approval"
    );
    let poll = ndn_identity::poll_approval_via_engine(
        &admin.engine,
        &admin.keyring,
        &enrolling.namespace,
        ca_prefix,
        Arc::clone(&signer),
        None,
        token.as_deref(),
    )
    .await;
    match poll {
        Ok(ApprovalPoll::Pending(pending)) => {
            let record = OutgoingRequest {
                namespace: enrolling.namespace.to_string(),
                ca_prefix: ca_prefix.to_string(),
                identity,
                key_name: key.to_string(),
                request_id: pending.request_id,
                code: pending.code,
                created_secs: now_secs(),
                expires_secs: pending.expires_secs,
                state: OutgoingState::Pending,
            };
            if let Err(e) = requests.save(&record) {
                discard(pib, &key);
                return Err(refusal(
                    status::SERVER_ERROR,
                    format!(
                        "the CA holds request {} (code {}), but this node could not record it \
                         ({e}), so it would never finish it: the key was deleted. Fix the PIB \
                         directory ({}) and ask again; an admin can deny request {}",
                        record.request_id,
                        record.code,
                        admin.pib_root.display(),
                        record.request_id
                    ),
                ));
            }
            // Its status Interest goes out now.
            admin.requests_changed.notify_one();
            tracing::info!(
                target: "security",
                key = %key,
                request = %record.request_id,
                code = %record.code,
                "waiting for an admin's approval; the daemon finishes the enrollment once approved"
            );
            Ok(EnrollOutcome::Pending(pending_info(
                &record,
                enrolling.adopted_context,
            )))
        }
        Ok(ApprovalPoll::Issued(issued)) => install(
            admin,
            pib,
            &key,
            signer,
            &issued,
            enrolling,
            "The approval is used: fix the PIB directory, ask again (`ndn-fwd enroll`) and have \
             an admin approve the new request",
        )
        .await
        .map(EnrollOutcome::Enrolled),
        Err(e) => {
            discard(pib, &key);
            tracing::warn!(
                target: "security",
                identity = %enrolling.identity,
                error = %e,
                "request for an admin's approval refused; nothing was kept for the new key"
            );
            Err(refusal(approval_status(&e), e.to_string()))
        }
    }
}

/// Keep the certificate the CA issued for `key` (generated for
/// `enrolling.identity`) and select it: PIB (the identity becomes its
/// default), issuer chain, the engine's key store and validation cache,
/// served by name, the renewal timer told, the node's signer switched
/// unless the config names another identity. `kept_failed`: what to do
/// when storing it fails (the key is then deleted).
async fn install(
    admin: &TrustAdmin,
    pib: &FilePib,
    key: &Name,
    signer: Arc<dyn Signer>,
    issued: &IssuedCertificate,
    enrolling: Enrolling,
    kept_failed: &str,
) -> Result<EnrolledInfo, TrustRefusal> {
    let Enrolling {
        namespace,
        identity,
        previous_identity,
        adopted_context,
        mut context_check,
    } = enrolling;
    let kept = pib
        .store_issued_cert(key, issued.data.raw())
        .and_then(|_| pib.set_default_identity(&identity));
    if let Err(e) = kept {
        discard(pib, key);
        return Err(refusal(
            status::SERVER_ERROR,
            format!(
                "the CA issued {}, but storing it in {} failed ({e}); nothing was kept and the \
                 previous identity stays selected. {kept_failed}",
                issued.cert.name,
                admin.pib_root.display()
            ),
        ));
    }

    // The certificate's issuer chain, kept beside the PIB: it is served with
    // this node's certificates and sent with a renewal, so a later CA of the
    // namespace can verify the chain once nobody else serves this CA's
    // certificate (`ndn_cert::issuers`).
    if let Err(e) = ndn_cert::issuers::keep_issuer_certs(&admin.pib_root, &issued.issuers) {
        tracing::warn!(
            target: "security",
            error = %e,
            "enrolled, but the issuer certificates of its chain were not kept"
        );
    }

    // The live daemon: the engine's key store holds the identity (so an app
    // asking the engine to sign as it can), and — unless the config pins
    // another identity — this key signs the daemon's own packets from now on.
    if let Some(mgr) = admin.engine.security() {
        mgr.register_signer(key.clone(), Arc::clone(&signer));
        mgr.cert_cache().insert(issued.cert.clone());
    }
    // Peers validating this node's Data can fetch the certificate, and its
    // issuers, from it.
    if let Some(own) = &admin.own_certs {
        own.serve(issued.data.raw().clone());
        for issuer in &issued.issuers {
            own.serve(issuer.raw().clone());
        }
    }
    // The renewal timer schedules the new certificate's renewal.
    admin.certificates_changed.notify_one();
    let mut at_next_start = Vec::new();
    if admin.dv_keeps_startup_key {
        at_next_start.push(format!(
            "DV routing: it keeps signing with the key this node started with (DV `static`/`lvs` \
             trust); it signs with {key} after a restart, so add that key to every DV \
             neighbour's [routing.dv.trust] trusted_keys before restarting"
        ));
    }
    let signing_now = match (&admin.configured_identity, &admin.signing) {
        (Some(configured), _) => {
            at_next_start.push(format!(
                "nothing: [security] identity = \"{configured}\" in this node's config takes \
                 precedence over the PIB's default identity; remove that line to sign as \
                 {identity}"
            ));
            false
        }
        (None, Some(active)) => {
            active.switch_to(Arc::clone(&signer));
            true
        }
        (None, None) => {
            at_next_start.push(format!(
                "management responses: this node started without a signing key; it signs as \
                 {identity} after a restart"
            ));
            false
        }
    };
    // The other certificates this node holds in the namespace, judged
    // against the context held now: the one checked before asking, or the
    // one adopted on the way (checked here when there is something to
    // judge).
    let mut others = held_besides(admin, pib, &namespace, key);
    if context_check.is_none() && !others.is_empty() {
        context_check = check_context(admin, &namespace).await;
        others = held_besides(admin, pib, &namespace, key);
    }
    let (unusable, still_valid): (Vec<Certified>, Vec<Certified>) =
        others.into_iter().partition(|c| c.revoked.is_some());
    tracing::info!(
        target: "security",
        identity = %identity,
        certificate = %issued.cert.name,
        issuer = ?issued.issuer.as_ref().map(Name::to_string),
        signing_now,
        "enrolled; the PIB's default identity is now this one"
    );
    Ok(EnrolledInfo {
        identity: identity.to_string(),
        key: key.to_string(),
        certificate: issued.cert.name.to_string(),
        issuer: issued
            .issuer
            .as_ref()
            .map(Name::to_string)
            .unwrap_or_default(),
        valid_until: iso(issued.cert.valid_until),
        validity_secs: issued.cert.valid_until.saturating_sub(issued.cert.valid_from)
            / 1_000_000_000,
        adopted_context,
        pib: admin.pib_root.display().to_string(),
        previous_identity: previous_identity.map(|n| n.to_string()),
        signing_now,
        at_next_start,
        still_valid: still_valid.iter().map(Certified::still_valid).collect(),
        unusable: unusable.iter().filter_map(Certified::unusable).collect(),
        context_check,
    })
}

/// `security/enroll-status`: this node's requests for an admin's approval,
/// oldest first.
pub(crate) fn enroll_status(admin: &TrustAdmin) -> Result<Vec<OutgoingRequest>, TrustRefusal> {
    let store = request_store(admin)?;
    expire_overdue(admin, &store)?;
    store
        .list()
        .map_err(|e| refusal(status::SERVER_ERROR, format!("cannot read this node's request records: {e}")))
}

/// The first pause after the CA could not be asked (or answered a status
/// early); it doubles up to [`RETRY_MAX`] while that goes on.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);

/// Finish this node's requests for an admin's approval, until `cancel`:
/// each pending record under `<pib>/requests/` is watched by its own task
/// ([`watch`]) — at start (a request made before a restart resumes) and as
/// soon as `security/enroll` records a new one
/// ([`TrustAdmin::requests_changed`]).
pub(crate) fn spawn_status_watch(admin: Arc<TrustAdmin>, cancel: CancellationToken) {
    tokio::spawn(async move {
        // Per request key: its watch task.
        let mut watching: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            watching.retain(|_, task| !task.is_finished());
            let listed = request_store(&admin).and_then(|store| {
                store
                    .list()
                    .map_err(|e| refusal(status::SERVER_ERROR, e.to_string()))
            });
            let read_again = match listed {
                Ok(list) => {
                    for request in list.into_iter().filter(|r| r.state == OutgoingState::Pending) {
                        if !watching.contains_key(&request.key_name) {
                            let task = tokio::spawn(watch(
                                Arc::clone(&admin),
                                request.key_name.clone(),
                                cancel.child_token(),
                            ));
                            watching.insert(request.key_name, task);
                        }
                    }
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        target: "security",
                        error = %e.reason,
                        "cannot read this node's requests for an admin's approval; reading them \
                         again in {}s",
                        RETRY_MAX.as_secs()
                    );
                    Some(RETRY_MAX)
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = admin.requests_changed.notified() => {}
                _ = tokio::time::sleep(read_again.unwrap_or(RETRY_MAX)), if read_again.is_some() => {}
            }
        }
    });
}

/// Wait for the CA's decision on this node's request for `key_name`, until
/// it ends or `cancel`: one held status Interest outstanding at a time
/// ([`ndn_identity::request_status_via_engine`], lifetime
/// [`ndn_cert::approval::STATUS_LIFETIME`]), sent again as soon as the CA
/// answers pending or the Interest expires. On the CA-signed answer:
/// approved — the issuance exchange runs at once ([`issue`]); denied or
/// expired — the record says why (and what to do) and the key is deleted.
/// An answer that is not the CA's changes nothing. When the CA cannot be
/// asked, or answers early (it stopped), it asks again after a pause
/// doubling from [`RETRY_FIRST`] to [`RETRY_MAX`] (logged once per outage)
/// with short Interests ([`ndn_cert::approval::STATUS_PROBE_LIFETIME`])
/// until the CA holds one again.
async fn watch(admin: Arc<TrustAdmin>, key_name: String, cancel: CancellationToken) {
    use ndn_cert::approval::{STATUS_LIFETIME, STATUS_PROBE_LIFETIME, status_hold};
    let mut retry = RETRY_FIRST;
    let mut unreachable = false;
    let mut probing = false;
    loop {
        // The record as kept now: another task may have ended it.
        let current = request_store(&admin).and_then(|store| {
            let found = store
                .list()
                .map_err(|e| refusal(status::SERVER_ERROR, e.to_string()))?
                .into_iter()
                .find(|r| r.key_name == key_name);
            Ok((store, found))
        });
        let (store, mut request) = match current {
            Ok((store, Some(request))) if request.state == OutgoingState::Pending => (store, request),
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(target: "security", key = %key_name, error = %e.reason, "cannot read a request record; reading it again in {}s", RETRY_MAX.as_secs());
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(RETRY_MAX) => continue,
                }
            }
        };
        if request.overdue(now_secs()) {
            if let Err(e) = expire_overdue(&admin, &store) {
                tracing::warn!(target: "security", key = %key_name, error = %e.reason, "a request past its expiry could not be ended here");
            }
            return;
        }
        let id = request.request_id.clone();
        let (Ok(namespace), Ok(ca_prefix)) =
            (request.namespace.parse::<Name>(), request.ca_prefix.parse::<Name>())
        else {
            request.state = OutgoingState::Failed {
                reason: "the request record names no valid namespace or CA; ask again \
                         (`ndn-fwd enroll`)"
                    .into(),
            };
            record(&store, &request);
            return;
        };
        let lifetime = if probing { STATUS_PROBE_LIFETIME } else { STATUS_LIFETIME };
        let asked = std::time::Instant::now();
        let status = tokio::select! {
            _ = cancel.cancelled() => return,
            status = ndn_identity::request_status_via_engine(
                &admin.engine,
                &admin.keyring,
                &namespace,
                &ca_prefix,
                &id,
                &request.key_name,
                lifetime,
            ) => status,
        };
        if status.is_ok() && unreachable {
            unreachable = false;
            tracing::info!(target: "security", request = %id, ca = %ca_prefix, "the CA is reachable again; waiting for its decision");
        }
        let pause = match status {
            Ok(RequestStatus::Pending { expires_secs, .. }) => {
                if expires_secs != request.expires_secs && expires_secs != 0 {
                    request.expires_secs = expires_secs;
                    record(&store, &request);
                }
                // The CA answers pending shortly before the Interest
                // expires. An earlier answer (the CA stopped; a relay's
                // aggregated Interest of another device answered) is
                // followed by a pause, growing while they keep coming
                // early, and short Interests until the CA holds one again.
                if asked.elapsed() < status_hold(Some(lifetime)) / 2 {
                    probing = true;
                    Some(retry)
                } else {
                    probing = false;
                    retry = RETRY_FIRST;
                    None
                }
            }
            Ok(RequestStatus::Approved { .. }) => match issue(&admin, &store, request).await {
                Issue::Ended => return,
                // The status said approved, the exchange says pending (the
                // CA was replaced in between): wait, never loop fast.
                Issue::Pending => Some(retry),
                Issue::Retry(why) => {
                    tracing::warn!(target: "security", request = %id, error = %why, "approved, but the certificate is not kept yet; the key and the request are kept, asking again in {}s", retry.as_secs());
                    Some(retry)
                }
            },
            Ok(RequestStatus::Denied { reason, .. }) => {
                end(&admin, &store, request, |reason| OutgoingState::Denied { reason }, &reason);
                return;
            }
            Ok(RequestStatus::Expired { reason, .. }) => {
                end(&admin, &store, request, |reason| OutgoingState::Expired { reason }, &reason);
                return;
            }
            Err(e @ ApprovalEnrollError::UntrustedAnswer(_)) => {
                tracing::warn!(target: "security", request = %id, error = %e, "asking again in {}s", retry.as_secs());
                probing = true;
                Some(retry)
            }
            Err(e) => {
                if !unreachable {
                    unreachable = true;
                    tracing::warn!(
                        target: "security",
                        request = %id,
                        error = %e,
                        "the CA could not be asked about a request for an admin's approval; asking \
                         again after a pause growing from {}s to {}s",
                        RETRY_FIRST.as_secs(),
                        RETRY_MAX.as_secs()
                    );
                }
                probing = true;
                Some(retry)
            }
        };
        if let Some(pause) = pause {
            retry = (retry * 2).min(RETRY_MAX);
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(pause) => {}
            }
        }
    }
}

/// End `request` on the CA-signed denial or expiry `reason`: its key is
/// deleted and the record says why (`state`).
fn end(
    admin: &TrustAdmin,
    store: &RequestStore,
    mut request: OutgoingRequest,
    state: impl FnOnce(String) -> OutgoingState,
    reason: &str,
) {
    let reason = match (FilePib::open(&admin.pib_root), request.key_name.parse::<Name>()) {
        (Ok(pib), Ok(key)) => {
            discard(&pib, &key);
            format!("{reason}; the key {key} was deleted")
        }
        (Err(e), _) => format!(
            "{reason}; the key {} could not be deleted ({e}): delete it from the PIB",
            request.key_name
        ),
        (_, Err(_)) => reason.to_owned(),
    };
    tracing::warn!(target: "security", request = %request.request_id, error = %reason, "request for an admin's approval ended");
    request.state = state(reason);
    record(store, &request);
}

/// What the issuance exchange of an approved request did.
enum Issue {
    /// The record ended (issued, or failed / denied / expired with why).
    Ended,
    /// The CA still answers pending: keep waiting.
    Pending,
    /// The CA could not be asked, or the PIB opened: ask again (why).
    Retry(String),
}

/// Run the issuance exchange for `request`, which the CA says is approved:
/// a fresh NEW → CHALLENGE exchange resuming it
/// ([`ndn_identity::poll_approval_via_engine`]); the certificate is
/// installed as `ndn-fwd enroll` would ([`install`]) and the record says
/// `issued`. A final refusal ends the record (the key is deleted).
async fn issue(admin: &TrustAdmin, store: &RequestStore, mut request: OutgoingRequest) -> Issue {
    let id = request.request_id.clone();
    let parsed = (
        request.namespace.parse::<Name>(),
        request.ca_prefix.parse::<Name>(),
        request.identity.parse::<Name>(),
        request.key_name.parse::<Name>(),
    );
    let (Ok(namespace), Ok(ca_prefix), Ok(identity), Ok(key)) = parsed else {
        request.state = OutgoingState::Failed {
            reason: "the request record names no valid namespace, CA, identity or key; ask \
                     again (`ndn-fwd enroll`)"
                .into(),
        };
        record(store, &request);
        return Issue::Ended;
    };
    let pib = match FilePib::open(&admin.pib_root) {
        Ok(pib) => pib,
        Err(e) => return Issue::Retry(format!("cannot open the PIB: {e}")),
    };
    let signer: Arc<dyn Signer> = match pib.get_signer(&key) {
        Ok(signer) => signer,
        Err(e) => {
            request.state = OutgoingState::Failed {
                reason: format!(
                    "the key {key} of this request is gone from the PIB ({e}); nothing can be \
                     certified for it: ask again (`ndn-fwd enroll`)"
                ),
            };
            record(store, &request);
            return Issue::Ended;
        }
    };
    let poll = ndn_identity::poll_approval_via_engine(
        &admin.engine,
        &admin.keyring,
        &namespace,
        &ca_prefix,
        Arc::clone(&signer),
        Some(&id),
        None,
    )
    .await;
    match poll {
        Ok(ApprovalPoll::Pending(_)) => Issue::Pending,
        Ok(ApprovalPoll::Issued(issued)) => {
            let _one_at_a_time = admin.enrolling.lock().await;
            let enrolling = Enrolling {
                namespace,
                identity,
                previous_identity: pib.get_default_identity().ok().flatten(),
                adopted_context: None,
                context_check: None,
            };
            request.state = match install(
                admin,
                &pib,
                &key,
                signer,
                &issued,
                enrolling,
                "The approval is used: fix the PIB directory, ask again (`ndn-fwd enroll`) and \
                 have an admin approve the new request",
            )
            .await
            {
                Ok(info) => {
                    tracing::info!(
                        target: "security",
                        request = %id,
                        certificate = %info.certificate,
                        signing_now = info.signing_now,
                        "an admin approved the request: enrolled"
                    );
                    OutgoingState::Issued {
                        certificate: info.certificate,
                    }
                }
                Err(e) => {
                    tracing::error!(target: "security", request = %id, error = %e.reason, "approved, but the certificate was not kept");
                    OutgoingState::Failed { reason: e.reason }
                }
            };
            record(store, &request);
            Issue::Ended
        }
        Err(e) if !e.is_final() => Issue::Retry(e.to_string()),
        Err(e) => {
            discard(&pib, &key);
            let reason = format!("{e}; the key {key} was deleted");
            tracing::warn!(target: "security", request = %id, error = %reason, "request for an admin's approval ended");
            request.state = OutgoingState::ended(&e, reason);
            record(store, &request);
            Issue::Ended
        }
    }
}

/// Save `request`'s new state (a failure is logged: the record stays as it
/// was, and is watched again at the next start).
fn record(store: &RequestStore, request: &OutgoingRequest) {
    if let Err(e) = store.save(request) {
        tracing::error!(
            target: "security",
            request = %request.request_id,
            state = request.state.as_str(),
            error = %e,
            "could not record a request's new state"
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use ndn_config::{ChallengeConfig, CaTomlConfig};
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_security::{Ed25519Signer, Keyring, SecurityManager};
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;
    use crate::active_identity::ActiveIdentity;

    pub(crate) struct Node {
        pub(crate) admin: TrustAdmin,
        pub(crate) startup_key: Name,
        pub(crate) fingerprint: [u8; 32],
        /// The signed trust context the node holds.
        pub(crate) context_data: ndn_packet::Data,
        /// The root device's CA, on the same engine.
        pub(crate) ca: Arc<ndn_cert::CaState>,
        /// The root device's CA's approval records (its local operator
        /// decides through them).
        pub(crate) approvals: ndn_cert::ApprovalStore,
        /// The root device's trust-context publisher, on the same engine: it
        /// answers the node's refreshes.
        pub(crate) root_contexts: crate::context_publisher::PublishedContexts,
        pub(crate) shutdown: ShutdownHandle,
    }

    /// One engine carrying the root device's CA (PIB `root_dev`, tokens `tokens`) and
    /// trust-context publisher, and the enrolling node's trust-admin backend (PIB
    /// `device`, holding the root device's trust context already, signing with an
    /// ephemeral key).
    pub(crate) async fn node(root_dev: &Path, device: &Path, tokens: &[&str]) -> Node {
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev).unwrap();
        let persisted =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let cfg = CaTomlConfig {
            enabled: true,
            prefix: "/home/bob".into(),
            identity: "/home/bob/CA".into(),
            challenges: vec![ChallengeConfig {
                kind: "token".into(),
                tokens: tokens.iter().map(|t| t.to_string()).collect(),
                pin: None,
                max_tries: None,
                ttl_secs: None,
                smtp: None,
            }],
            // Above the 90 days a device once asked for: the CA's setting,
            // not the request, decides the lifetime.
            cert_validity_days: ndn_config::CertValidityDays::uniform(200),
            ..CaTomlConfig::default()
        };
        let (faces, ca) = crate::ca::prepare(&cfg, root_dev).await.unwrap();
        let (context_face, publisher) = crate::context_publisher::prepare(root_dev);
        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(context_face);
        for face in faces {
            builder = builder.face(face);
        }
        let (engine, shutdown) = builder.build().await.unwrap();
        engine.fib().add_nexthop(&ca.prefix, ca.face_id, 0);
        let running = crate::ca::spawn(ca, &cfg, &engine).unwrap();
        let (ca, approvals) = (
            running.state,
            running.approvals.expect("a namespace CA offers device-approval"),
        );
        let root_contexts = publisher.spawn(&engine);

        let keyring = Arc::new(Keyring::new());
        let fingerprint = ndn_cert::anchor_fingerprint(&persisted.init.anchor);
        ndn_cert::adopt_with_tofu(&keyring, &persisted.init.context_data, &ns, &fingerprint)
            .unwrap();
        let startup: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[1; 32],
            "/ndn-fwd/test/KEY/e".parse().unwrap(),
        ));
        Node {
            startup_key: startup.key_name().clone(),
            admin: TrustAdmin {
                engine,
                keyring,
                pib_root: device.to_path_buf(),
                publisher: None,
                signing: Some(Arc::new(ActiveIdentity::new(startup, true))),
                own_certs: None,
                dv_keeps_startup_key: false,
                configured_identity: None,
                enrolling: tokio::sync::Mutex::new(()),
                keeping: std::sync::Mutex::new(()),
                ca: None,
                context_change: tokio::sync::Mutex::new(()),
                renewing: tokio::sync::Mutex::new(()),
                certificates_changed: tokio::sync::Notify::new(),
                requests_changed: tokio::sync::Notify::new(),
                context_sync: None,
            },
            fingerprint,
            context_data: ndn_packet::Data::decode(persisted.init.context_data.raw().clone())
                .unwrap(),
            ca,
            approvals,
            root_contexts,
            shutdown,
        }
    }

    pub(crate) fn request(
        node: &Node,
        role: &str,
        token: &str,
        device: &str,
        force: bool,
    ) -> EnrollRequest {
        EnrollRequest {
            link_uri: TrustEnvelope::Invite {
                ca_prefix: "/home/bob".into(),
                identity_namespace: format!("/home/bob/{role}"),
                token: token.into(),
                ttl_secs: None,
                anchor_fingerprint: Some(node.fingerprint),
            }
            .to_uri(),
            identity: format!("/home/bob/{role}/{device}").parse().unwrap(),
            force,
        }
    }

    /// Of two adoptions of one namespace, the one finishing last never
    /// stores (or publishes) an older version than the keyring holds.
    #[tokio::test]
    async fn an_older_adoption_never_overwrites_the_held_version() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-x"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let held = node.admin.keyring.contexts().pop().unwrap();
        let older = ndn_cert::LinkAdoption {
            context: Arc::clone(&held),
            data: ndn_packet::Data::decode(node.context_data.raw().clone()).unwrap(),
            fetched: false,
        };
        // Another command adopted a newer version meanwhile.
        node.admin.keyring.adopt(Arc::new(
            ndn_security::SignedTrustContext::hierarchical(ns.clone())
                .with_version(held.version() + 1),
        ));
        let refused = node.admin.keep_adopted(&older, &node.fingerprint);
        assert_eq!(refused.unwrap_err().status_code, 409);
        assert!(!ndn_cert::context_file_path(device.path(), &ns).exists());
        node.shutdown.shutdown().await;
    }

    /// What the node's state is: PIB keys, default identity, signing key.
    fn state(node: &Node) -> (Vec<Name>, Option<Name>, Name) {
        let pib = FilePib::new(&node.admin.pib_root).unwrap();
        let (signing, _) = node.admin.signing.as_ref().unwrap().current();
        (pib.list_keys().unwrap(), pib.get_default_identity().unwrap(), signing)
    }

    /// A successful enrollment generates the key in the node's PIB (it
    /// signs there; nothing in the answer carries it), stores the issued
    /// certificate, selects the identity and switches the node's signer.
    #[tokio::test]
    async fn enrolled_key_stays_in_the_pib_and_is_selected() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        assert_eq!(state(&node), (vec![], None, node.startup_key.clone()));

        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = info.key.parse().unwrap();
        let identity: Name = "/home/bob/member/laptop".parse().unwrap();
        assert!(key.has_prefix(&identity));
        assert_eq!(info.issuer, "/home/bob/CA/KEY/ca");
        let cert: Name = info.certificate.parse().unwrap();
        assert_eq!(
            cert.components()[..cert.len() - 1],
            key.clone().append("NDNCERT").components()[..],
            "the certificate is named <key>/NDNCERT/<version>"
        );
        assert!(cert.components().last().unwrap().as_version().is_some());
        assert!(info.signing_now);
        assert_eq!(info.validity_secs / 86_400, 200, "the CA's cert_validity_days decides");

        let pib = FilePib::open(device.path()).unwrap();
        assert_eq!(state(&node), (vec![key.clone()], Some(identity), key.clone()));
        assert!(pib.get_issued_cert(&key).unwrap().is_some());
        let secret = pib.export_pkcs8(&key).unwrap();
        let answer = serde_json::to_string(&EnrollOutcome::Enrolled(info)).unwrap();
        let hex_secret: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!answer.contains(&hex_secret));
        node.shutdown.shutdown().await;
    }

    /// Every refused enrollment — a spent token, a token rewritten into
    /// another role, a second enrollment without `force`, a forced one under
    /// the device name the node already holds — leaves the PIB, its default
    /// identity and the node's signer exactly as they were.
    #[tokio::test]
    async fn refused_enrollment_leaves_the_previous_identity_selected() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1", "member-m2", "guest-g1"]).await;
        enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
            .await
            .expect("first enrollment");
        let before = state(&node);

        let spent = enroll(&node.admin, request(&node, "member", "member-m1", "phone", true)).await;
        assert_eq!(spent.unwrap_err().status_code, status::UNAUTHORIZED);
        assert_eq!(state(&node), before);

        let forged = enroll(&node.admin, request(&node, "member", "guest-g1", "tab", true)).await;
        assert_eq!(forged.unwrap_err().status_code, status::BAD_PARAMS);
        assert_eq!(state(&node), before);

        let again = enroll(&node.admin, request(&node, "member", "member-m2", "tab", false)).await;
        assert_eq!(again.unwrap_err().status_code, 409);
        assert_eq!(state(&node), before);

        let wrong_device = enroll(&node.admin, request(&node, "member", "member-m2", "KEY", true)).await;
        assert_eq!(wrong_device.unwrap_err().status_code, status::BAD_PARAMS);
        assert_eq!(state(&node), before);

        // The CA keeps the device name to the key it certified.
        let same_name =
            enroll(&node.admin, request(&node, "member", "member-m2", "laptop", true)).await;
        assert_eq!(same_name.unwrap_err().status_code, 409);
        assert_eq!(state(&node), before);

        // With `force` the same (unspent) token enrolls a second key under
        // another name; the first stays.
        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m2", "tab", true))
                .await
                .expect("forced enrollment") else { panic!("an invite enrolls at once") };
        assert_eq!(info.still_valid.len(), 1);
        assert_eq!(state(&node).0.len(), 2);
        node.shutdown.shutdown().await;
    }

    /// A certificate whose chain the held trust context revokes — its CA
    /// key, or the root above it (a recovery after a compromise) — is not
    /// a held, valid certificate: it validates nowhere.
    #[tokio::test]
    async fn a_certificate_under_a_revoked_issuer_is_not_held() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::open(device.path()).unwrap();
        let held = certified_in(&node.admin, &pib, &ns);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].revoked, None, "nothing revokes a fresh certificate's chain");

        let version = node.admin.keyring.version_of(&ns).unwrap();
        for (bump, revoked) in [ndn_cert::namespace::ca_key_name(&ns), ndn_cert::namespace::root_key_name(&ns)]
            .into_iter()
            .enumerate()
        {
            node.admin.keyring.adopt(Arc::new(
                ndn_security::SignedTrustContext::hierarchical(ns.clone())
                    .with_version(version + 1 + bump as u64)
                    .with_revocation(revoked.clone()),
            ));
            let held = certified_in(&node.admin, &pib, &ns);
            assert_eq!(held[0].key.to_string(), info.key);
            assert_eq!(held[0].revoked.as_ref(), Some(&revoked), "revoking {revoked}");
        }
        node.shutdown.shutdown().await;
    }

    /// Enrollment judges the certificates the node holds against the
    /// namespace's newest trust context, not the stale one it holds: when a
    /// version the node has not fetched yet revokes its key, that key is
    /// listed as unusable (never "still valid") and does not block enrolling
    /// another — and the node holds the newer version afterwards.
    #[tokio::test]
    async fn held_certificates_are_judged_against_the_newest_context() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1", "member-m2"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let EnrollOutcome::Enrolled(first) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("first enrollment") else { panic!("an invite enrolls at once") };
        let laptop: Name = first.key.parse().unwrap();
        let held = node.admin.keyring.version_of(&ns).unwrap();

        // The root device revokes the laptop's key in a new version; the
        // node has not fetched it.
        let root = ndn_cert::RootStore::open(&FilePib::open(root_dev.path()).unwrap())
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap();
        let bump = ndn_cert::bump_context_revoking(
            root.as_ref(),
            &node.context_data,
            std::slice::from_ref(&laptop),
        )
        .await
        .unwrap()
        .unwrap();
        node.root_contexts.publish(&bump.context, &bump.data);
        assert_eq!(node.admin.keyring.version_of(&ns), Some(held));
        // The first enrollment's check left the publisher's metadata (v1) in
        // the shared engine's Content Store; publishing v2 purges it, so the
        // next check is answered by the publisher at once.

        let EnrollOutcome::Enrolled(second) =
            enroll(&node.admin, request(&node, "member", "member-m2", "tab", false))
                .await
                .expect("the only certificate held is revoked by the newest version") else {
                panic!("an invite enrolls at once")
            };
        assert!(second.still_valid.is_empty(), "{:?}", second.still_valid);
        assert_eq!(second.unusable.len(), 1, "{:?}", second.unusable);
        assert!(second.unusable[0].starts_with(&first.key));
        let check = second.context_check.expect("the held context was checked");
        assert_eq!(check.state, RefreshState::Updated, "{}", check.detail);
        assert_eq!(node.admin.keyring.version_of(&ns), Some(bump.context.version()));
        node.shutdown.shutdown().await;
    }

    /// `security/enroll` of `/home/bob/<role>/<device>` with the namespace's
    /// anchor link (its root's expected fingerprint `fingerprint`).
    fn approval_request(fingerprint: [u8; 32], role: &str, device: &str, force: bool) -> EnrollRequest {
        EnrollRequest {
            link_uri: TrustEnvelope::Anchor {
                namespace: Some("/home/bob".into()),
                fingerprint: Some(fingerprint),
                version: None,
                context_data: None,
                context_content: None,
            }
            .to_uri(),
            identity: format!("/home/bob/{role}/{device}").parse().unwrap(),
            force,
        }
    }

    /// The record of `request` once it left `pending`, which must happen
    /// within `within` — far shorter than a status Interest's lifetime, so
    /// only the held Interest's answer can have brought the decision.
    async fn resolved(admin: &TrustAdmin, request: &str, within: Duration) -> OutgoingRequest {
        assert!(within * 5 < ndn_cert::approval::STATUS_LIFETIME);
        tokio::time::timeout(within, async {
            loop {
                let records = enroll_status(admin).unwrap();
                let record = records.into_iter().find(|r| r.request_id == request).unwrap();
                if record.state != OutgoingState::Pending {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the decision reaches the waiting requester at once")
    }

    /// Enrollment on an admin's approval: `pending` with the code the CA
    /// shows (asking again answers the same request, no second key). The
    /// daemon waits on the CA with a held status Interest, resumed from its
    /// records after a restart; the moment the CA host's operator approves,
    /// the certificate is installed with no further request. A request made
    /// while the daemon runs is waited on at once; denied, it is recorded
    /// with its reason and its key deleted.
    #[tokio::test]
    async fn a_decision_reaches_the_waiting_requester_at_once_across_its_restart() {
        let settle = Duration::from_millis(500);
        let at_once = Duration::from_secs(3);
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &[]).await;
        let EnrollOutcome::Pending(pending) =
            enroll(&node.admin, approval_request(node.fingerprint, "admin", "tablet", false))
                .await
                .expect("the request is made")
        else {
            panic!("an admin certificate waits for an admin's approval")
        };
        let at_ca = node.approvals.pending();
        assert_eq!(at_ca.len(), 1);
        assert_eq!((&at_ca[0].request_id, &at_ca[0].code), (&pending.request, &pending.code));
        let EnrollOutcome::Pending(again) =
            enroll(&node.admin, approval_request(node.fingerprint, "admin", "tablet", false))
                .await
                .expect("asking again")
        else {
            panic!("still pending")
        };
        assert_eq!((again.request, again.key), (pending.request.clone(), pending.key.clone()));
        assert_eq!(state(&node).0.len(), 1, "one key for one request");

        let crate::enroll::tests::Node {
            admin,
            approvals,
            fingerprint,
            shutdown,
            ..
        } = node;
        let admin = Arc::new(admin);
        // The daemon that made the request stops while its status Interest
        // is held; the next start resumes from `<pib>/requests/`.
        let before_restart = CancellationToken::new();
        spawn_status_watch(Arc::clone(&admin), before_restart.clone());
        tokio::time::sleep(settle).await;
        before_restart.cancel();
        let cancel = CancellationToken::new();
        spawn_status_watch(Arc::clone(&admin), cancel.clone());
        tokio::time::sleep(settle).await;
        approvals
            .decide_locally(&pending.code, ndn_cert::Decision::Approve, "uid 1000 (alice)")
            .unwrap();
        let OutgoingState::Issued { certificate } =
            resolved(&admin, &pending.request, at_once).await.state
        else {
            panic!("approved: issued")
        };
        let key: Name = pending.key.parse().unwrap();
        let pib = FilePib::open(device.path()).unwrap();
        assert!(certificate.starts_with(&pending.key));
        assert!(pib.get_issued_cert(&key).unwrap().is_some());
        assert_eq!(
            pib.get_default_identity().unwrap(),
            Some("/home/bob/admin/tablet".parse().unwrap())
        );

        let EnrollOutcome::Pending(relay) =
            enroll(&admin, approval_request(fingerprint, "node", "relay", true))
                .await
                .expect("the request is made")
        else {
            panic!("a node certificate waits for an admin's approval")
        };
        tokio::time::sleep(settle).await;
        approvals
            .decide_locally(
                &relay.request,
                ndn_cert::Decision::Deny {
                    reason: "not my relay".into(),
                },
                "uid 1000 (alice)",
            )
            .unwrap();
        let OutgoingState::Denied { reason } = resolved(&admin, &relay.request, at_once).await.state
        else {
            panic!("denied")
        };
        assert!(reason.contains("not my relay"), "{reason}");
        let relay_key: Name = relay.key.parse().unwrap();
        assert!(!pib.list_keys().unwrap().contains(&relay_key), "the denied key is deleted");
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
