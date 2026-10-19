//! Deciding requests for an admin's approval: `ndn-fwd approvals list |
//! approve <id|code> | deny <id|code> [--reason <text>]`, and the daemon's
//! backend of the mgmt `ca list-approvals / approve / deny` verbs
//! ([`DaemonApprovals`]).
//!
//! The same command works on the CA host and on a remote admin device: the
//! daemon lists and decides with [`ndn_namespace::approver`] — its own CA's
//! records, decided by the local operator the kernel attests on the
//! management socket (`uid 1000 (alice)`), and the pending requests of the
//! namespaces whose CA runs elsewhere, decided with the admin keys its PIB
//! holds.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_cert::{ApprovalStore, Decision};
use ndn_mgmt::{ApprovalMgmtBackend, TrustRefusal, approval_row};
use ndn_mgmt_wire::{ApprovalListing, PendingApproval};
use ndn_namespace::approver::{self, AdminCredential};

use crate::context_adopt::TrustAdmin;

/// The daemon's `ca` mgmt backend: its own CAs' records (`local`, one store
/// per CA it runs that takes approval requests) and, as an admin device,
/// the pending requests of the namespaces whose CA runs elsewhere.
pub(crate) struct DaemonApprovals {
    local: Vec<ApprovalStore>,
    admin: Arc<TrustAdmin>,
}

impl DaemonApprovals {
    pub(crate) fn new(local: Vec<ApprovalStore>, admin: Arc<TrustAdmin>) -> Self {
        Self { local, admin }
    }

    /// The PIB's admin keys of namespaces whose CA is not one of this
    /// node's own.
    fn credentials(&self) -> Result<Vec<AdminCredential>, TrustRefusal> {
        let local_cas: Vec<ndn_packet::Name> =
            self.local.iter().map(|s| s.ca_prefix().clone()).collect();
        approver::admin_credentials(&self.admin.ns, self.admin.vault.as_ref(), &local_cas)
    }
}

#[async_trait::async_trait]
impl ApprovalMgmtBackend for DaemonApprovals {
    async fn list(&self) -> Result<ApprovalListing, TrustRefusal> {
        let listing = approver::list(&self.admin.ns, &self.local, || self.credentials()).await?;
        Ok(ApprovalListing {
            rows: listing.records.iter().map(approval_row).collect(),
            notes: listing.notes,
        })
    }

    async fn decide(
        &self,
        target: String,
        decision: Decision,
        operator: String,
    ) -> Result<PendingApproval, TrustRefusal> {
        approver::decide(
            &self.admin.ns,
            &self.local,
            || self.credentials(),
            &target,
            decision,
            &operator,
        )
        .await
        .map(|r| approval_row(&r))
    }
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
        println!(
            "created   = {}",
            ndn_cert::approval::iso_secs(row.created_secs)
        );
        let until = ndn_cert::approval::iso_secs(row.expires_secs);
        if row.state == "pending" {
            println!("expires   = {until}");
            println!(
                "approve   = ndn-fwd approvals approve {}",
                copyable(&row.code)
            );
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
    let what = if approve {
        "approvals approve"
    } else {
        "approvals deny"
    };
    let (client, socket) = crate::onboard::daemon(args, what).await?;
    let resp = if approve {
        client.ca_approve(target, DAEMON_APPROVALS_TIMEOUT).await
    } else {
        let reason = crate::onboard::flag(args, &["--reason"]).unwrap_or("");
        client
            .ca_deny(target, reason, DAEMON_APPROVALS_TIMEOUT)
            .await
    }
    .map_err(|e| daemon_error(what, &socket, e))?;
    if !resp.is_ok() {
        bail!(
            "{what} refused by the daemon ({}): {}",
            resp.status_code,
            resp.status_text
        );
    }
    println!("# ndn-fwd {what} (by the running daemon at {socket})");
    println!("{}", resp.status_text);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_accepts_code_as_listed() {
        let code = "482 913";
        let want = ndn_cert::approval::normalize_code(code);
        assert!(want.is_some());
        // `code = 482 913` pasted unquoted: two shell words.
        let words: Vec<&str> = code.split_whitespace().collect();
        assert_eq!(
            decision_target(&words)
                .as_deref()
                .and_then(ndn_cert::approval::normalize_code),
            want
        );
        // The `approve` line's form, and the code quoted.
        assert_eq!(
            decision_target(&[&copyable(code)])
                .as_deref()
                .and_then(ndn_cert::approval::normalize_code),
            want
        );
        assert_eq!(
            decision_target(&[code])
                .as_deref()
                .and_then(ndn_cert::approval::normalize_code),
            want
        );
        // A request id passes through; anything else is refused, not guessed.
        assert_eq!(decision_target(&["1a2b3c4d"]).as_deref(), Some("1a2b3c4d"));
        assert_eq!(decision_target(&["1a2b", "913"]), None);
        assert_eq!(decision_target(&[]), None);
    }
}
