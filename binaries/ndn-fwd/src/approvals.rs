//! Deciding requests for an admin's approval: `ndn-fwd approvals list |
//! approve <id|code> | deny <id|code> [--reason <text>]`, and the daemon's
//! backend of the mgmt `ca list-approvals / approve / deny` verbs
//! ([`DaemonApprovals`]).
//!
//! The same command works on the CA host and on a remote admin device; the
//! daemon picks the path per namespace by whether it runs that namespace's
//! CA ([`ndn_cert::approval`]):
//!
//! - **this node runs the CA**: the CA's durable records are read and
//!   decided directly. The approver recorded is the local operator the
//!   kernel attests on the management socket (`uid 1000 (alice)`); the
//!   issued certificate's attestation names them and claims no signature.
//! - **this node is an admin device of a namespace whose CA runs
//!   elsewhere** (its PIB holds a current, unrevoked admin certificate of
//!   the namespace): the pending list is fetched from `<ca>/CA/PENDING`
//!   with an Interest signed by the admin key, and a decision is a Data
//!   `<requester key>/ndncert-approve|deny/<request id>` signed by the admin
//!   key — an approval carries the verification code shown, a denial its
//!   reason — pushed to `<ca>/CA/APPROVAL` with the admin certificate's
//!   chain. The CA validates it under the namespace's trust context and
//!   records the admin key with the signed Data as evidence.
//!
//! A request is named by its request id or its six-digit verification code,
//! which the requesting device shows too: comparing the two is the check
//! that it is the right device.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_cert::{ApprovalRecord, ApprovalStore, ApproverError, Decision, RefusalKind};
use ndn_mgmt::{ApprovalMgmtBackend, TrustRefusal, approval_refusal, approval_row};
use ndn_mgmt_wire::{ApprovalListing, PendingApproval};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, Signer};

use crate::context_adopt::{TrustAdmin, refusal};

/// The daemon's `ca` mgmt backend: its own CA's records (`local`, when it
/// runs a CA that takes approval requests) and, as an admin device, the
/// pending requests of the namespaces whose CA runs elsewhere.
pub(crate) struct DaemonApprovals {
    local: Option<ApprovalStore>,
    admin: Arc<TrustAdmin>,
}

impl DaemonApprovals {
    pub(crate) fn new(local: Option<ApprovalStore>, admin: Arc<TrustAdmin>) -> Self {
        Self { local, admin }
    }

    /// Nothing to approve on this node, and how to change that.
    fn nothing_here() -> TrustRefusal {
        refusal(
            status::NOT_FOUND,
            "this node neither runs a CA that takes approval requests nor holds a current admin \
             certificate of a namespace whose CA runs elsewhere: there is nothing to approve \
             here. Run `ndn-fwd approvals` on the namespace's root device (its CA host) or on \
             an admin device; a device becomes one with `ndn-fwd enroll <anchor link> --role \
             admin`, approved by an admin",
        )
    }

    /// The pending requests at `cred`'s CA.
    async fn fetch(&self, cred: &AdminCredential) -> Result<Vec<ApprovalRecord>, ApproverError> {
        ndn_identity::fetch_pending_via_engine(
            &self.admin.engine,
            &self.admin.keyring,
            &cred.namespace,
            &cred.ca_prefix,
            &cred.signer,
            &cred.chain,
        )
        .await
    }
}

/// A refused remote listing or decision, with what to do.
fn approver_refusal(cred: &AdminCredential, e: ApproverError) -> TrustRefusal {
    match e {
        ApproverError::Refused(r) => {
            let mut r = approval_refusal(r);
            r.reason = format!("the CA {} refused: {}", cred.ca_prefix, r.reason);
            r
        }
        ApproverError::CaUnreachable { .. } => refusal(504, e.to_string()),
        ApproverError::BadAnswer(_) => refusal(502, e.to_string()),
        ApproverError::Signing(_) => refusal(status::SERVER_ERROR, e.to_string()),
    }
}

/// The listing note for a namespace whose CA could not be asked: why, and
/// what to do. The refusal (status and reason) is what `list` answers when
/// no namespace at all could be listed.
fn unlisted(cred: &AdminCredential, e: ApproverError) -> (TrustRefusal, String) {
    let ns = &cred.namespace;
    let unreachable = match &e {
        ApproverError::CaUnreachable { detail, .. } => Some(detail.clone()),
        _ => None,
    };
    let r = approver_refusal(cred, e);
    let note = match unreachable {
        Some(detail) => format!(
            "{ns}: unreachable ({detail}); its requests are not shown — retry when it is up"
        ),
        None => format!("{ns}: not listed ({}); its requests are not shown", r.reason),
    };
    (r, note)
}

/// Merge this node's own CA's rows (`local`, `None` when it runs no CA) with
/// what each administered namespace's CA answered: the rows that could be
/// listed, and a note for each namespace that could not. Refused only when
/// nothing at all could be listed — a CA host keeps seeing its own queue
/// while another namespace's CA is down.
fn merge_listing(
    local: Option<Vec<PendingApproval>>,
    remote: Vec<Result<Vec<PendingApproval>, (TrustRefusal, String)>>,
) -> Result<ApprovalListing, TrustRefusal> {
    let mut listed = local.is_some();
    let mut listing = ApprovalListing { rows: local.unwrap_or_default(), notes: Vec::new() };
    let mut first_failure = None;
    for answer in remote {
        match answer {
            Ok(rows) => {
                listed = true;
                listing.rows.extend(rows);
            }
            Err((r, note)) => {
                first_failure.get_or_insert(r.status_code);
                listing.notes.push(note);
            }
        }
    }
    match first_failure {
        Some(code) if !listed => Err(refusal(
            code,
            format!(
                "could not list the pending requests of any namespace this node administers: {}",
                listing.notes.join("; ")
            ),
        )),
        _ => Ok(listing),
    }
}

#[async_trait::async_trait]
impl ApprovalMgmtBackend for DaemonApprovals {
    async fn list(&self) -> Result<ApprovalListing, TrustRefusal> {
        let creds = admin_credentials(&self.admin, self.local.as_ref().map(|s| s.ca_prefix()))?;
        if self.local.is_none() && creds.is_empty() {
            return Err(Self::nothing_here());
        }
        let local = self
            .local
            .as_ref()
            .map(|store| store.records().iter().map(approval_row).collect());
        let mut remote = Vec::with_capacity(creds.len());
        for cred in &creds {
            remote.push(match self.fetch(cred).await {
                Ok(records) => Ok(records.iter().map(approval_row).collect()),
                Err(e) => Err(unlisted(cred, e)),
            });
        }
        merge_listing(local, remote)
    }

    async fn decide(
        &self,
        target: String,
        decision: Decision,
        operator: String,
    ) -> Result<PendingApproval, TrustRefusal> {
        // This node's own CA first: its local operator decides.
        let mut local_miss = None;
        if let Some(store) = &self.local {
            match store.find_pending(&target) {
                Ok(_) => {
                    return store
                        .decide_locally(&target, decision, &operator)
                        .map(|r| approval_row(&r))
                        .map_err(approval_refusal);
                }
                Err(r) if r.kind == RefusalKind::NotFound => local_miss = Some(r),
                Err(r) => return Err(approval_refusal(r)),
            }
        }
        let creds = admin_credentials(&self.admin, self.local.as_ref().map(|s| s.ca_prefix()))?;
        if creds.is_empty() {
            return Err(match local_miss {
                Some(miss) => approval_refusal(miss),
                None => Self::nothing_here(),
            });
        }
        // The namespaces this node administers: ask each CA what is pending.
        let mut found: Vec<(&AdminCredential, ApprovalRecord)> = Vec::new();
        let mut failed = Vec::new();
        for cred in &creds {
            match self.fetch(cred).await {
                Ok(records) => match ndn_cert::approval::find_pending_in(&records, &target) {
                    Ok(record) => found.push((cred, record)),
                    Err(r) if r.kind == RefusalKind::NotFound => {}
                    Err(r) => return Err(approver_refusal(cred, ApproverError::Refused(r))),
                },
                Err(e) => failed.push(approver_refusal(cred, e)),
            }
        }
        let (cred, record) = match found.len() {
            1 => found.remove(0),
            0 => {
                let mut reason = format!(
                    "no pending request shows {target:?} at {}: check the code on the new \
                     device against `ndn-fwd approvals list` (a request that expired or was \
                     decided is not pending)",
                    if self.local.is_some() {
                        "this node's CA or at the CAs of the namespaces it administers"
                    } else {
                        "the CAs of the namespaces this node administers"
                    }
                );
                let mut code = status::NOT_FOUND;
                if let Some(first) = failed.first() {
                    code = first.status_code;
                    let reasons: Vec<&str> = failed.iter().map(|r| r.reason.as_str()).collect();
                    reason.push_str(&format!("; not every CA could be asked: {}", reasons.join("; ")));
                }
                return Err(refusal(code, reason));
            }
            _ => {
                let at: Vec<String> = found.iter().map(|(c, r)| format!("{} ({})", r.request_id, c.ca_prefix)).collect();
                return Err(refusal(
                    409,
                    format!(
                        "requests in several namespaces show {target:?}: {}; decide by request id",
                        at.join(", ")
                    ),
                ));
            }
        };
        tracing::info!(
            target: "security",
            operator = %operator,
            admin_key = %cred.key,
            request = %record.request_id,
            ca = %cred.ca_prefix,
            decision = ?decision,
            "deciding a request at the namespace's CA with this device's admin key"
        );
        ndn_identity::push_decision_via_engine(
            &self.admin.engine,
            &self.admin.keyring,
            &cred.namespace,
            &record,
            &decision,
            &cred.signer,
            &cred.chain,
        )
        .await
        .map(|r| approval_row(&r))
        .map_err(|e| approver_refusal(cred, e))
    }
}

/// An admin key of this node in a namespace whose CA runs elsewhere.
struct AdminCredential {
    namespace: Name,
    /// The CA that issued the admin certificate (`/<ns>` for `/<ns>/CA`).
    ca_prefix: Name,
    key: Name,
    signer: Arc<dyn Signer>,
    /// The admin certificate, then the issuer certificates kept for its
    /// chain (`<pib>/issuers`): what the CA walks to the namespace root.
    chain: Vec<Bytes>,
}

/// This node's admin keys, one per namespace (the newest valid
/// certificate): a device key `/<ns>/admin/<device>/KEY/…` of a namespace
/// whose trust context this node holds, with a current certificate the
/// context does not revoke, issued by a CA other than `local_ca` (this
/// node's own, decided locally).
fn admin_credentials(
    admin: &TrustAdmin,
    local_ca: Option<&Name>,
) -> Result<Vec<AdminCredential>, TrustRefusal> {
    let unreadable = |e: ndn_security::PibError| {
        refusal(
            status::SERVER_ERROR,
            format!(
                "cannot read the PIB {} for this node's admin keys: {e}",
                admin.pib_root.display()
            ),
        )
    };
    let pib = match FilePib::open(&admin.pib_root) {
        Ok(pib) => pib,
        Err(ndn_security::PibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(unreadable(e)),
    };
    let namespaces: Vec<Name> = admin
        .keyring
        .contexts()
        .iter()
        .map(|c| c.namespace().clone())
        .collect();
    let kept: Vec<Bytes> = ndn_cert::issuers::stored_issuer_certs(&admin.pib_root);
    let mut out: Vec<(u64, AdminCredential)> = Vec::new();
    for key in pib.list_keys().map_err(unreadable)? {
        let Some(namespace) = namespaces.iter().find(|ns| {
            parse_device_key(ns, &key).is_some_and(|d| d.role == Role::Admin)
        }) else {
            continue;
        };
        let Some(wire) = pib.get_issued_cert(&key).map_err(unreadable)? else {
            continue;
        };
        let Some((data, cert)) = Data::decode(wire)
            .ok()
            .and_then(|d| Certificate::decode(&d).ok().map(|c| (d, c)))
        else {
            continue;
        };
        if !cert.is_valid_now() {
            continue;
        }
        let context = admin.keyring.context_for(&cert.name);
        if context.is_revoked(&cert.name) {
            continue;
        }
        let Some(ca_prefix) = ndn_cert::issuing_ca_prefix(&cert) else {
            continue;
        };
        if local_ca == Some(&ca_prefix) {
            continue;
        }
        let signer: Arc<dyn Signer> = match pib.get_signer(&key) {
            Ok(signer) => signer,
            Err(e) => {
                tracing::warn!(target: "security", key = %key, error = %e, "an admin certificate's key cannot sign; it decides nothing");
                continue;
            }
        };
        let chain = ndn_cert::approval::admin_chain(&data, &cert, &kept);
        let candidate = AdminCredential {
            namespace: namespace.clone(),
            ca_prefix,
            key,
            signer,
            chain,
        };
        match out.iter_mut().find(|(_, c)| c.namespace == candidate.namespace) {
            Some(slot) if slot.0 < cert.valid_from => *slot = (cert.valid_from, candidate),
            Some(_) => {}
            None => out.push((cert.valid_from, candidate)),
        }
    }
    Ok(out.into_iter().map(|(_, c)| c).collect())
}

/// How long the CLI waits for the daemon: on an admin device it asks each
/// namespace's CA (an Interest, and the CA certificate's fetch to check the
/// answer) before it pushes a decision.
const DAEMON_APPROVALS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// `ndn-fwd approvals list | approve <id|code> | deny <id|code> [--reason
/// <text>] [-c <config>]`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let positional = crate::onboard::positionals(args);
    let usage = "usage: ndn-fwd approvals list | approve <request id or code> | deny <request \
                 id or code> [--reason <text>] [-c <config>]";
    match positional.first().copied() {
        Some("list") => list(args).await,
        Some(verb @ ("approve" | "deny")) => {
            let target = decision_target(&positional[1..]).with_context(|| {
                format!(
                    "`ndn-fwd approvals {verb}` needs one request id or the six-digit code as \
                     `ndn-fwd approvals list` shows it (`482 913` or `482913`); {usage}"
                )
            })?;
            decide(args, verb == "approve", &target).await
        }
        other => bail!("unknown `ndn-fwd approvals` command {other:?}; {usage}"),
    }
}

fn daemon_error(what: &str, socket: &str, e: ndn_ipc::ForwarderError) -> anyhow::Error {
    match e {
        ndn_ipc::ForwarderError::Command { code, text } => {
            anyhow::anyhow!("{what} refused by the daemon ({code}): {text}")
        }
        ndn_ipc::ForwarderError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            anyhow::anyhow!(
                "no answer from the daemon at {socket} within {}s: a CA it asks may be \
                 unreachable; check its log and retry",
                DAEMON_APPROVALS_TIMEOUT.as_secs()
            )
        }
        e => anyhow::anyhow!("ask the daemon at {socket} ({what}): {e}"),
    }
}

async fn list(args: &[String]) -> Result<()> {
    let (client, socket) = crate::onboard::daemon(args, "approvals list").await?;
    let listing = client
        .ca_list_approvals(DAEMON_APPROVALS_TIMEOUT)
        .await
        .map_err(|e| daemon_error("approvals list", &socket, e))?;
    println!("# ndn-fwd approvals (by the running daemon at {socket})");
    for note in &listing.notes {
        println!("# {note}");
    }
    let rows = &listing.rows;
    let pending = rows.iter().filter(|r| r.state == "pending").count();
    if rows.is_empty() {
        if listing.notes.is_empty() {
            println!("# no request for an admin's approval");
        } else {
            println!("# no request for an admin's approval in the namespaces that could be listed");
        }
    }
    for row in rows {
        println!();
        println!("request   = {}", row.request_id);
        println!("code      = {}", row.code);
        println!("state     = {}", row.state);
        println!("namespace = {}", row.namespace);
        if !row.role.is_empty() {
            println!("device    = {} {:?}", row.role, row.device);
        }
        println!("key       = {}", row.key_name);
        println!("created   = {}", ndn_cert::approval::iso_secs(row.created_secs));
        let until = ndn_cert::approval::iso_secs(row.expires_secs);
        if row.state == "pending" {
            println!("expires   = {until}");
            println!("approve   = ndn-fwd approvals approve {}", copyable(&row.code));
        } else {
            println!("kept_until = {until}");
        }
        if !row.approver.is_empty() {
            println!("decided_by = {}", row.approver);
        }
        if !row.reason.is_empty() {
            println!("reason    = {}", row.reason);
        }
    }
    if pending > 0 {
        println!();
        println!("# Compare the code with the one the new device shows (`ndn-fwd enroll --status`");
        println!("# there); approve only when they match, with the request's `approve` line");
        println!("# (`ndn-fwd approvals approve <code>`), or `ndn-fwd approvals deny <code>");
        println!("# --reason <why>`; the code may be typed with or without its space.");
    }
    Ok(())
}

/// The code as one shell word (`482913`): what the `approve` line prints.
fn copyable(code: &str) -> String {
    code.split_whitespace().collect()
}

/// The request a decision names, from its positional words: a request id
/// or a code, as one word (`482913`, or quoted `"482 913"`) or as the list
/// shows it pasted unquoted (`482 913`: two three-digit words).
fn decision_target(words: &[&str]) -> Option<String> {
    let three_digits = |w: &str| w.len() == 3 && w.bytes().all(|b| b.is_ascii_digit());
    match words {
        [one] => Some((*one).to_owned()),
        [a, b] if three_digits(a) && three_digits(b) => Some(format!("{a}{b}")),
        _ => None,
    }
}

async fn decide(args: &[String], approve: bool, target: &str) -> Result<()> {
    let what = if approve { "approvals approve" } else { "approvals deny" };
    let (client, socket) = crate::onboard::daemon(args, what).await?;
    let resp = if approve {
        client.ca_approve(target, DAEMON_APPROVALS_TIMEOUT).await
    } else {
        let reason = crate::onboard::flag(args, &["--reason"]).unwrap_or("");
        client.ca_deny(target, reason, DAEMON_APPROVALS_TIMEOUT).await
    }
    .map_err(|e| daemon_error(what, &socket, e))?;
    if !resp.is_ok() {
        bail!("{what} refused by the daemon ({}): {}", resp.status_code, resp.status_text);
    }
    println!("# ndn-fwd {what} (by the running daemon at {socket})");
    println!("{}", resp.status_text);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, namespace: &str) -> PendingApproval {
        PendingApproval {
            request_id: id.into(),
            key_name: format!("{namespace}/node/relay/KEY/k"),
            namespace: namespace.into(),
            code: "482 913".into(),
            state: "pending".into(),
            ..Default::default()
        }
    }

    fn unreachable(ns: &str) -> (TrustRefusal, String) {
        (
            refusal(504, "no answer"),
            format!("{ns}: unreachable (no answer); its requests are not shown — retry when it is up"),
        )
    }

    #[test]
    fn list_shows_local_rows_when_remote_unreachable() {
        // A CA host that also administers /work: /work's CA is down, its
        // own queue still lists, with a note naming what is missing.
        let listing = merge_listing(Some(vec![row("1a", "/home")]), vec![Err(unreachable("/work"))])
            .expect("the local CA's rows are listed");
        assert_eq!(listing.rows, vec![row("1a", "/home")]);
        assert_eq!(listing.notes, vec![unreachable("/work").1]);

        // An admin device: one CA answers, another is down.
        let listing = merge_listing(None, vec![Ok(vec![row("2b", "/home")]), Err(unreachable("/work"))])
            .expect("the reachable namespace's rows are listed");
        assert_eq!(listing.rows, vec![row("2b", "/home")]);
        assert_eq!(listing.notes.len(), 1);

        // Nothing could be listed: refused, saying which and why.
        let r = merge_listing(None, vec![Err(unreachable("/work"))]).unwrap_err();
        assert_eq!(r.status_code, 504);
        assert!(r.reason.contains("/work: unreachable"), "{}", r.reason);
    }

    #[test]
    fn approve_accepts_code_as_listed() {
        let code = "482 913";
        let want = ndn_cert::approval::normalize_code(code);
        assert!(want.is_some());
        // `code = 482 913` pasted unquoted: two shell words.
        let words: Vec<&str> = code.split_whitespace().collect();
        assert_eq!(decision_target(&words).as_deref().and_then(ndn_cert::approval::normalize_code), want);
        // The `approve` line's form, and the code quoted.
        assert_eq!(decision_target(&[&copyable(code)]).as_deref().and_then(ndn_cert::approval::normalize_code), want);
        assert_eq!(decision_target(&[code]).as_deref().and_then(ndn_cert::approval::normalize_code), want);
        // A request id passes through; anything else is refused, not guessed.
        assert_eq!(decision_target(&["1a2b3c4d"]).as_deref(), Some("1a2b3c4d"));
        assert_eq!(decision_target(&["1a2b", "913"]), None);
        assert_eq!(decision_target(&[]), None);
    }
}
