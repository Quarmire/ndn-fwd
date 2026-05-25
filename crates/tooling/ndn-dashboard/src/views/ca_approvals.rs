//! §5.5 NDNCERT device-approval — pending-approval list surface.
//!
//! Reads `/localhost/nfd/ca/list-approvals` (mgmt verb landed in
//! `565e7e0`) and renders the pending requests inside the §4.4 CA
//! tab. Per the canonical device-approval design (`10c3b7d`),
//! resolution happens via signed-Data on the approval feed — *not*
//! via mgmt. v1 dashboard ships the **visibility** surface; the
//! sign-and-publish path (so the dashboard itself can approve) is
//! tracked as a v1.5 follow-up.

use crate::app::AppCtx;
use crate::edu_gloss::EduGloss;
use dioxus::prelude::*;

/// One pending request as the dashboard renders it. Shape mirrors
/// the `PendingApprovalInfo` DTO surfaced by `ca/list-approvals`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PendingApprovalRow {
    pub id: String,
    pub cert_name: String,
    pub description: String,
}

/// State of the approver list. Refresh is operator-driven; we don't
/// poll automatically because pending approvals are a low-frequency
/// surface and an extra poll on every Security view render would
/// noise the audit log on the CA side.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaApprovalsState {
    pub rows: Vec<PendingApprovalRow>,
    pub last_refresh_unix_s: Option<u64>,
    pub last_error: Option<String>,
}

#[component]
pub fn CaApprovalsPanel() -> Element {
    let ctx = use_context::<AppCtx>();
    let state = crate::app_shared::CA_APPROVALS_STATE.signal();
    let snapshot = state.read().clone();
    let row_count = snapshot.rows.len();

    rsx! {
        div { style: "margin-top:18px;padding:14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;",
            // Header
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--text);",
                        EduGloss { term: "Device approval" }
                        span { style: "color:var(--text-muted);margin-left:6px;font-weight:400;font-size:11px;",
                            "({row_count} pending)"
                        }
                    }
                    div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                        "§5.5 · ", span { class: "mono", "/localhost/nfd/ca/list-approvals" }
                    }
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| {
                        ctx.cmd.send(crate::app::DashCmd::CaListApprovals);
                    },
                    "Refresh"
                }
            }

            if let Some(err) = snapshot.last_error.as_ref() {
                div { style: "font-size:11px;color:var(--red,#f85149);margin-bottom:8px;padding:6px 8px;background:#22000033;border:1px solid var(--red,#f85149)33;border-radius:4px;",
                    "{err}"
                }
            }

            if snapshot.rows.is_empty() && snapshot.last_error.is_none() {
                div { class: "empty", style: "font-size:11px;padding:8px;",
                    if snapshot.last_refresh_unix_s.is_none() {
                        "Click Refresh to load pending approvals."
                    } else {
                        "No pending device-approval requests."
                    }
                }
            } else {
                for row in snapshot.rows.iter() {
                    PendingApprovalCard { row: row.clone() }
                }
            }

            // v1 callout: mgmt-mediated, v2 canonical signed-Data.
            div { style: "margin-top:10px;padding:8px 10px;border:1px dashed var(--border-subtle);border-radius:4px;font-size:10px;color:var(--text-muted);line-height:1.5;",
                "Approve / Deny are signed-command gated; v1 records the operator as "
                span { class: "mono", "approved-via-mgmt" }
                " (the SECURITY-module's signed-Interest auth boundary IS the cryptographic gate). v2 hardens this to a canonical "
                EduGloss { term: "ChallengeAttestation" }
                "-bearing signed Data on the CA's approval feed (ndn-identity)."
            }
        }
    }
}

#[component]
fn PendingApprovalCard(row: PendingApprovalRow) -> Element {
    let ctx = use_context::<AppCtx>();
    let approve_id = row.id.clone();
    let deny_id = row.id.clone();
    rsx! {
        div { style: "border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px;background:var(--surface);",
            div { style: "display:flex;justify-content:space-between;align-items:flex-start;gap:8px;",
                div { style: "flex:1;min-width:0;",
                    div { style: "font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                        "Request id"
                    }
                    div { class: "mono", style: "font-size:12px;color:var(--text);margin-top:2px;",
                        "{row.id}"
                    }
                    div { style: "font-size:11px;color:var(--text-muted);margin-top:8px;text-transform:uppercase;letter-spacing:.4px;",
                        "Cert name"
                    }
                    div { class: "mono", style: "font-size:11px;color:var(--purple);margin-top:2px;word-break:break-all;",
                        "{row.cert_name}"
                    }
                    if !row.description.is_empty() {
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:6px;font-style:italic;",
                            "“{row.description}”"
                        }
                    }
                }
                div { style: "display:flex;flex-direction:column;gap:4px;",
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: move |_| {
                            ctx.cmd.send(crate::app::DashCmd::CaApprove {
                                request_id: approve_id.clone(),
                            });
                        },
                        "Approve"
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| {
                            ctx.cmd.send(crate::app::DashCmd::CaDeny {
                                request_id: deny_id.clone(),
                                reason: String::new(),
                            });
                        },
                        "Deny"
                    }
                }
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_approval_row_clones_field_for_field() {
        let r = PendingApprovalRow {
            id: "req-7".into(),
            cert_name: "/lab/alice".into(),
            description: "alice's phone".into(),
        };
        let c = r.clone();
        assert_eq!(c.id, "req-7");
        assert_eq!(c.cert_name, "/lab/alice");
        assert_eq!(c.description, "alice's phone");
    }

    #[test]
    fn ca_approvals_state_defaults_empty_and_no_error() {
        let s = CaApprovalsState::default();
        assert!(s.rows.is_empty());
        assert!(s.last_error.is_none());
        assert!(s.last_refresh_unix_s.is_none());
    }
}
