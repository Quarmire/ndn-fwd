//! §5.3 Key rotation modal.
//!
//! Rotates an identity's signing key by **generating a new key**
//! under the same identity name and recording the rotation in the
//! §4.6 audit log. The old key is *not* deleted — in-flight Data
//! signed by the old key needs the old cert to verify until the
//! TTL clock runs out; deleting immediately would break consumers
//! that haven't refreshed yet. Operators can delete the old key
//! manually from the §4.1 identity inspector after the grace
//! window.
//!
//! v1 wraps the existing `security/identity-generate` mgmt verb —
//! this modal is the UX shell and audit-trail bridge.

use crate::app::{AppCtx, DashCmd, ToastLevel, push_toast};
use crate::edu_gloss::EduGloss;
use crate::security_chains::{AuditLogEntry, AuditOutcome, append_audit_entry};
use crate::types::SecurityKeyInfo;
use dioxus::prelude::*;

/// Modal open/close state. Holds the identity being rotated and the
/// list of its current keys so the modal can render without re-
/// reading the global signal.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeyRotationState {
    pub open: bool,
    pub identity_name: String,
    pub current_keys: Vec<SecurityKeyInfo>,
}

/// Suggest the next key-id given the keys this identity already has.
/// Picks the smallest `kN` (N a non-negative integer) that's not in
/// use. Falls back to `k1` when no numeric suffix is recognisable.
pub fn suggest_next_key_id(existing: &[SecurityKeyInfo]) -> String {
    let used: std::collections::BTreeSet<u64> = existing
        .iter()
        .filter_map(|k| {
            let id = k.key_id();
            id.strip_prefix('k').and_then(|s| s.parse::<u64>().ok())
        })
        .collect();
    if used.is_empty() {
        return "k1".to_owned();
    }
    let mut n = 1u64;
    while used.contains(&n) {
        n += 1;
    }
    format!("k{n}")
}

/// Build the audit-log entry for a rotation. Pure function so tests
/// can pin the subject/detail/outcome contract.
pub fn build_rotation_audit_entry(
    identity_name: &str,
    old_key_id: &str,
    new_key_id: &str,
    initiator: &str,
    ts_unix_ns: u64,
) -> AuditLogEntry {
    AuditLogEntry {
        ts_unix_ns,
        outcome: AuditOutcome::Info,
        subject: "security/key-rotation".to_owned(),
        detail: format!(
            "identity={identity_name} from=KEY/{old_key_id} to=KEY/{new_key_id} initiator={initiator}; old key retained for in-flight verification (manual delete after grace window)"
        ),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn unix_ns_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn unix_ns_now() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[component]
pub fn KeyRotationModal(state: Signal<KeyRotationState>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut state = state;

    let snapshot = state.read().clone();
    if !snapshot.open {
        return rsx! {};
    }

    let identity_name = snapshot.identity_name.clone();
    let identity_name_for_send = identity_name.clone();
    let current_keys = snapshot.current_keys.clone();
    let active_key_id = current_keys
        .iter()
        .find(|k| k.has_cert)
        .map(|k| k.key_id().to_owned())
        .or_else(|| current_keys.first().map(|k| k.key_id().to_owned()))
        .unwrap_or_default();
    let next_key_id = suggest_next_key_id(&current_keys);
    let identity_display = identity_name.clone();
    let next_key_display = next_key_id.clone();
    let active_key_display = active_key_id.clone();

    let mut close = move || {
        state.write().open = false;
    };

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:120;display:flex;align-items:center;justify-content:center;",
            onclick: move |_| close(),
            div {
                style: "background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;width:min(520px,95vw);max-height:90vh;overflow-y:auto;",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;",
                    div {
                        div { style: "font-size:14px;font-weight:600;color:var(--text);",
                            "Rotate key"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;",
                            EduGloss { term: "Key rotation" }
                            " · §5.3"
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| close(),
                        "Cancel"
                    }
                }

                // Identity row
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:12px;",
                    div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                        "Identity"
                    }
                    div { class: "mono", style: "font-size:12px;color:var(--text);margin-top:4px;word-break:break-all;",
                        "{identity_display}"
                    }
                }

                // From → to row
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:12px;",
                    div { style: "display:flex;gap:12px;align-items:center;justify-content:space-between;",
                        div {
                            div { style: "font-size:10px;color:var(--text-muted);", "Current active key" }
                            div { class: "mono", style: "font-size:12px;color:var(--text);margin-top:2px;",
                                if active_key_display.is_empty() {
                                    "(none)"
                                } else {
                                    "KEY/{active_key_display}"
                                }
                            }
                        }
                        div { style: "font-size:20px;color:var(--text-muted);", "→" }
                        div {
                            div { style: "font-size:10px;color:var(--text-muted);", "New key" }
                            div { class: "mono", style: "font-size:12px;color:var(--green,#3fb950);margin-top:2px;",
                                "KEY/{next_key_display}"
                            }
                        }
                    }
                }

                // Retention note
                div { style: "border:1px solid var(--yellow,#f5c518)55;background:#2a240022;border-radius:6px;padding:10px;margin-bottom:14px;font-size:11px;",
                    div { style: "font-weight:600;color:var(--yellow,#f5c518);margin-bottom:4px;",
                        "Old key retained"
                    }
                    div { style: "color:var(--text-muted);line-height:1.5;",
                        "The new key takes over as the dashboard's active signer. The old key stays in the PIB so in-flight Data signed under it continues to verify against the existing cert's KeyLocator. Delete the old key from the identity inspector after the grace window."
                    }
                }

                // Action row
                div { style: "display:flex;gap:8px;justify-content:flex-end;",
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| close(),
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: {
                            let identity = identity_name_for_send.clone();
                            let old_id = active_key_id.clone();
                            let new_id = next_key_id.clone();
                            move |_| {
                                if identity.is_empty() {
                                    push_toast(
                                        "Rotation needs a non-empty identity name.",
                                        ToastLevel::Error,
                                    );
                                    return;
                                }
                                ctx.cmd.send(DashCmd::SecurityGenerate(identity.clone()));
                                let initiator = ctx.identity_name.read().clone();
                                append_audit_entry(build_rotation_audit_entry(
                                    &identity,
                                    if old_id.is_empty() { "(none)" } else { old_id.as_str() },
                                    &new_id,
                                    if initiator.is_empty() { "(ephemeral)" } else { initiator.as_str() },
                                    unix_ns_now(),
                                ));
                                push_toast(
                                    format!("Generated KEY/{new_id}; old key retained for in-flight verification."),
                                    ToastLevel::Success,
                                );
                                close();
                            }
                        },
                        "Rotate"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(name: &str, has_cert: bool) -> SecurityKeyInfo {
        SecurityKeyInfo {
            name: name.to_owned(),
            has_cert,
            valid_until: "never".to_owned(),
            public_key_b64: String::new(),
        }
    }

    #[test]
    fn suggest_next_key_id_picks_k1_when_empty() {
        assert_eq!(suggest_next_key_id(&[]), "k1");
    }

    #[test]
    fn suggest_next_key_id_skips_used_numeric_suffixes() {
        let keys = vec![k("/lab/alice/KEY/k1", true), k("/lab/alice/KEY/k2", false)];
        assert_eq!(suggest_next_key_id(&keys), "k3");

        let keys = vec![k("/lab/alice/KEY/k1", true), k("/lab/alice/KEY/k3", false)];
        assert_eq!(suggest_next_key_id(&keys), "k2");
    }

    #[test]
    fn suggest_next_key_id_ignores_non_numeric_suffixes() {
        // Keys with non-`kN` ids don't count as used numeric slots.
        let keys = vec![
            k("/lab/alice/KEY/yubico1", true),
            k("/lab/alice/KEY/kabc", false),
        ];
        assert_eq!(suggest_next_key_id(&keys), "k1");
    }

    #[test]
    fn build_rotation_audit_entry_pins_subject_and_outcome() {
        let e = build_rotation_audit_entry("/lab/alice", "k1", "k2", "/admin", 42);
        assert_eq!(e.subject, "security/key-rotation");
        assert_eq!(e.outcome, AuditOutcome::Info);
        assert_eq!(e.ts_unix_ns, 42);
        assert!(e.detail.contains("/lab/alice"));
        assert!(e.detail.contains("KEY/k1"));
        assert!(e.detail.contains("KEY/k2"));
        assert!(e.detail.contains("/admin"));
        assert!(
            e.detail.to_lowercase().contains("retained"),
            "audit detail should note the retention policy: {:?}",
            e.detail
        );
    }
}
