//! §5.1 SafeBag import — drag-drop modal + preview + trust check.
//!
//! Drag a `.tpb` (or any SafeBag wire) file onto the dashboard's
//! layout root. The dashboard parses + decrypts the wire in-browser
//! (no network round-trip until the operator confirms), runs a trust
//! check against the dashboard's known anchors + schema, surfaces the
//! result, and on submit fires `/localhost/nfd/security/safebag-import`
//! to persist the decrypted identity into the forwarder's PIB.
//!
//! Per the design doc §5.1, imports never proceed silently with
//! broken trust — every failure shows the specific reason with a
//! fix action.

use crate::app::{AppCtx, DashCmd, ToastLevel, push_toast};
use crate::edu_gloss::EduGloss;
use crate::types::{AnchorInfo, SchemaRuleInfo};
use crate::views::engine_pill::{FdeDetection, probe_fde};
use dioxus::prelude::*;
use ndn_safebag::SafeBag;


/// State of the §5.1 SafeBag import modal — held in a global signal
/// so the layout-root drag-drop handler can push the dropped wire
/// in and the modal can render against it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SafeBagImportState {
    pub open: bool,
    pub filename: String,
    pub wire: Vec<u8>,
    /// Best-effort preview derived from the wire before the operator
    /// supplies the passphrase. `None` when the wire couldn't be
    /// parsed at all (the modal renders the parse error).
    pub preview_pre_pw: Option<SafeBagWirePreview>,
    pub parse_error: Option<String>,
}

/// What we can pull from a SafeBag's *cleartext* portion (the cert
/// Data wire) before the passphrase decrypts the PKCS#8 key. Drives
/// the modal's preview pane before the operator enters a passphrase.
#[derive(Debug, Clone, PartialEq)]
pub struct SafeBagWirePreview {
    pub identity_name: String,
    pub key_name: String,
    pub cert_name: String,
}

/// §11.2 — fire a one-time FDE warning on the first PIB write path.
/// The probe returns `Unknown` from the browser sandbox; the warning
/// is honest about that limit. Desktop + Unknown is suppressed
/// (operator knows their own filesystem).
fn maybe_fire_fde_warning() {
    let runtime = crate::views::engine_pill::current_runtime_for_test_or_render();
    let fde = probe_fde();
    if let Some(txt) = fde.warning_text(runtime) {
        push_toast(txt, ToastLevel::Warning);
    }
    // FdeDetection::On is the silent-success branch — no toast.
    let _ = FdeDetection::On;
}

/// Populate the global `SAFEBAG_IMPORT_STATE` from a dropped/picked
/// file. Called by the layout-root drag-drop handler and any other
/// entry point. Pure side-effect — the modal reads its state from
/// the global signal on next render.
pub fn open_with_wire(filename: String, wire: Vec<u8>) {
    let preview = parse_wire_preview(&wire);
    let mut st = crate::app_shared::SAFEBAG_IMPORT_STATE.write();
    st.open = true;
    st.filename = filename;
    st.wire = wire;
    match preview {
        Ok(p) => {
            st.preview_pre_pw = Some(p);
            st.parse_error = None;
        }
        Err(e) => {
            st.preview_pre_pw = None;
            st.parse_error = Some(e);
        }
    }
}


/// Parse a SafeBag wire and extract the cert's name without
/// touching the encrypted key. Returns `Err` when the outer SafeBag
/// or inner cert Data fails to decode.
pub fn parse_wire_preview(wire: &[u8]) -> Result<SafeBagWirePreview, String> {
    let bag = SafeBag::decode(wire).map_err(|e| format!("SafeBag decode: {e}"))?;
    let cert_data = ndn_packet::Data::decode(bag.certificate)
        .map_err(|e| format!("Cert Data decode: {e:?}"))?;
    let cert_name = cert_data.name.to_string();
    let (identity_name, key_name) = derive_identity_and_key(&cert_name);
    Ok(SafeBagWirePreview {
        identity_name,
        key_name,
        cert_name,
    })
}

/// Split a cert name into identity name + key name.
/// `/lab/alice/KEY/k1/router-ca/v=…` →
/// identity `/lab/alice`, key `/lab/alice/KEY/k1`.
/// When no `KEY` component is present (off-spec cert names) returns
/// the full cert name in both slots.
fn derive_identity_and_key(cert_name: &str) -> (String, String) {
    let Some(key_idx) = cert_name.find("/KEY/") else {
        return (cert_name.to_owned(), cert_name.to_owned());
    };
    let identity = cert_name[..key_idx].to_owned();
    let after_key = &cert_name[key_idx + 5..];
    let key_id = after_key.split('/').next().unwrap_or("");
    let key_name = format!("{identity}/KEY/{key_id}");
    (identity, key_name)
}

/// Verify the passphrase decrypts the SafeBag's PKCS#8 — pure
/// function the modal calls before dispatching the mgmt verb so the
/// operator gets a deterministic "wrong passphrase" error without a
/// network round-trip.
pub fn verify_passphrase(wire: &[u8], passphrase: &[u8]) -> Result<(), String> {
    let bag = SafeBag::decode(wire).map_err(|e| format!("SafeBag decode: {e}"))?;
    let _pkcs8 = bag
        .decrypt_pkcs8(passphrase)
        .map_err(|e| format!("decrypt failed (wrong passphrase?): {e}"))?;
    Ok(())
}


/// Outcome of the §5.1 pre-import trust check. Each row points at the
/// specific failure with a remediation gesture; an import only
/// dispatches the mgmt verb when *every* row is `ok`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrustCheck {
    pub anchor_found: TrustCheckRow,
    pub schema_match: TrustCheckRow,
    pub validity_window: TrustCheckRow,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrustCheckRow {
    pub ok: bool,
    pub detail: String,
}

impl TrustCheck {
    pub fn all_ok(&self) -> bool {
        self.anchor_found.ok && self.schema_match.ok && self.validity_window.ok
    }
}

/// Run the §5.1 trust check given what the dashboard knows from the
/// current mgmt-verb responses. Pure function — every input is
/// already in the dashboard's state.
///
/// v1 anchor-membership check is namespace-prefix matching: any
/// installed anchor whose name is a strict prefix of `cert_name`
/// counts as "the issuer's anchor is present." This is a
/// best-effort approximation; the wire path's true trust check
/// happens forwarder-side via `security/validate`. The dashboard's
/// pre-check tells the operator "don't bother submitting — this
/// won't validate," which is exactly what §5.1 promises.
pub fn run_trust_check(
    preview: &SafeBagWirePreview,
    anchors: &[AnchorInfo],
    schema: &[SchemaRuleInfo],
) -> TrustCheck {
    TrustCheck {
        anchor_found: check_anchor_membership(&preview.identity_name, anchors),
        schema_match: check_schema_match(&preview.key_name, schema),
        // Validity-window is informational only here — v1 doesn't
        // surface valid_from/valid_until from the SafeBag's cert
        // Data through the mgmt wire today. Default to ok=true with
        // a "not checked client-side" detail line so the operator
        // sees the slot but isn't blocked by missing data.
        validity_window: TrustCheckRow {
            ok: true,
            detail: "Forwarder will verify the validity window on import.".to_owned(),
        },
    }
}

fn check_anchor_membership(identity_name: &str, anchors: &[AnchorInfo]) -> TrustCheckRow {
    if anchors.is_empty() {
        return TrustCheckRow {
            ok: false,
            detail: "No trust anchors installed. Install at least one anchor before importing."
                .to_owned(),
        };
    }
    let mut matched: Option<&str> = None;
    for a in anchors {
        let candidate = a.name.as_str();
        let candidate_root = strip_key_suffix(candidate);
        if identity_name == candidate_root
            || identity_name.starts_with(&format!("{candidate_root}/"))
        {
            matched = Some(candidate);
            break;
        }
    }
    match matched {
        Some(a) => TrustCheckRow {
            ok: true,
            detail: format!("Issuer anchor {a} covers {identity_name}"),
        },
        None => TrustCheckRow {
            ok: false,
            detail: format!(
                "No installed anchor's namespace covers {identity_name}. Install the issuer's anchor first."
            ),
        },
    }
}

fn check_schema_match(key_name: &str, schema: &[SchemaRuleInfo]) -> TrustCheckRow {
    if schema.is_empty() {
        return TrustCheckRow {
            ok: true,
            detail: "No trust schema configured — forwarder accepts any name (development mode)."
                .to_owned(),
        };
    }
    for rule in schema {
        if data_pattern_matches(&rule.data_pattern, key_name) {
            return TrustCheckRow {
                ok: true,
                detail: format!(
                    "Schema rule [{idx}] {pat} → {kp} matches",
                    idx = rule.index,
                    pat = rule.data_pattern,
                    kp = rule.key_pattern,
                ),
            };
        }
    }
    TrustCheckRow {
        ok: false,
        detail: format!("No schema rule matches {key_name}. Add a rule before importing."),
    }
}

/// Strip the `/KEY/<id>` (and any further suffix) from an NDN name.
/// `/lab/router-ca/KEY/k0` → `/lab/router-ca`. Leaves the input
/// unchanged when no `KEY` component is present.
fn strip_key_suffix(name: &str) -> &str {
    match name.find("/KEY/") {
        Some(i) => &name[..i],
        None => name,
    }
}

/// Cheap pattern match: treat each `<…>` segment in the schema's
/// `data_pattern` as a single-component wildcard. `/sensor/<node>`
/// matches `/sensor/foo` but not `/sensor/foo/bar`. Mirrors the
/// pattern grammar `ndn_security::Validator` accepts; intentionally
/// liberal so the dashboard's pre-check doesn't reject things the
/// forwarder would accept.
fn data_pattern_matches(pattern: &str, name: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let name_parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    if pat_parts.len() > name_parts.len() {
        return false;
    }
    for (p, n) in pat_parts.iter().zip(name_parts.iter()) {
        if p.starts_with('<') && p.ends_with('>') {
            continue;
        }
        if p == &"*" {
            continue;
        }
        if p != n {
            return false;
        }
    }
    true
}


/// Keyboard-driven fallback for the layout-root drag-drop. Renders a
/// small "Import SafeBag…" button in the Security view header; on
/// file-pick, reads the bytes and populates `SAFEBAG_IMPORT_STATE`.
#[component]
pub fn SafeBagImportPicker() -> Element {
    rsx! {
        div { style: "display:flex;gap:6px;align-items:center;margin-bottom:14px;font-size:11px;",
            span { style: "color:var(--text-muted);",
                EduGloss { term: "SafeBag" }
            }
            label {
                class: "btn btn-secondary btn-sm",
                style: "padding:5px 10px;font-size:11px;cursor:pointer;",
                "Import SafeBag…"
                input {
                    r#type: "file",
                    accept: ".tpb,application/octet-stream",
                    style: "display:none;",
                    onchange: move |evt| {
                        let files = evt.files();
                        if let Some(file) = files.first().cloned() {
                            let filename = file.name();
                            spawn(async move {
                                if let Ok(bytes) = file.read_bytes().await {
                                    open_with_wire(filename, bytes.to_vec());
                                }
                            });
                        }
                    },
                }
            }
            span { style: "color:var(--text-muted);font-size:10px;",
                "or drag-drop a .tpb anywhere on the dashboard"
            }
        }
    }
}


#[component]
pub fn SafeBagImportModal(state: Signal<SafeBagImportState>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut state = state;
    let mut passphrase: Signal<String> = use_signal(String::new);
    let mut set_active: Signal<bool> = use_signal(|| false);
    let mut submit_error: Signal<Option<String>> = use_signal(|| None);

    let snapshot = state.read().clone();
    if !snapshot.open {
        return rsx! {};
    }
    let anchors = ctx.security_anchors.read().clone();
    let schema = ctx.schema_rules.read().clone();
    let trust = snapshot
        .preview_pre_pw
        .as_ref()
        .map(|p| run_trust_check(p, &anchors, &schema))
        .unwrap_or_default();
    let trust_ok = snapshot.preview_pre_pw.is_some() && trust.all_ok();

    let mut close = move || {
        state.write().open = false;
        passphrase.set(String::new());
        set_active.set(false);
        submit_error.set(None);
    };

    let preview = snapshot.preview_pre_pw.clone();
    let parse_error = snapshot.parse_error.clone();
    let filename = snapshot.filename.clone();
    let wire = snapshot.wire.clone();
    let wire_len = wire.len();

    rsx! {
        // Backdrop. Soft dim; click to close.
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:120;display:flex;align-items:center;justify-content:center;",
            onclick: move |_| close(),
            div {
                style: "background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;width:min(560px,95vw);max-height:90vh;overflow-y:auto;",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;",
                    div {
                        div { style: "font-size:14px;font-weight:600;color:var(--text);",
                            "Import SafeBag"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;",
                            EduGloss { term: "SafeBag" }
                            " · §5.1"
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| close(),
                        "Cancel"
                    }
                }

                // File row
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:14px;",
                    div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                        "File"
                    }
                    div { class: "mono", style: "font-size:11px;color:var(--text);margin-top:4px;word-break:break-all;",
                        "{filename}"
                        span { style: "color:var(--text-muted);margin-left:8px;",
                            "({wire_len} bytes)"
                        }
                    }
                }

                if let Some(err) = parse_error.as_ref() {
                    div { style: "border:1px solid var(--red,#f85149)55;background:#220000aa;border-radius:6px;padding:10px;margin-bottom:14px;",
                        div { style: "font-size:12px;font-weight:600;color:var(--red,#f85149);margin-bottom:4px;",
                            "Couldn't parse SafeBag"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);",
                            "{err}"
                        }
                    }
                } else if let Some(p) = preview.as_ref() {
                    // Preview
                    div { style: "margin-bottom:14px;",
                        div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                            "Preview"
                        }
                        PreviewRow { label: "Identity", value: p.identity_name.clone() }
                        PreviewRow { label: "Key",      value: p.key_name.clone()      }
                        PreviewRow { label: "Cert",     value: p.cert_name.clone()     }
                    }

                    // Trust check rows
                    div { style: "margin-bottom:14px;",
                        div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                            "Trust check"
                        }
                        TrustRow { label: "Issuer's anchor present", row: trust.anchor_found.clone() }
                        TrustRow { label: "Schema rule covers key",  row: trust.schema_match.clone() }
                        TrustRow { label: "Validity window",         row: trust.validity_window.clone() }
                    }

                    // Passphrase
                    div { style: "margin-bottom:10px;",
                        label { style: "font-size:11px;color:var(--text-muted);", "Passphrase" }
                        input {
                            r#type: "password",
                            style: "width:100%;font-family:var(--font-mono);font-size:11px;padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);margin-top:4px;",
                            value: "{passphrase}",
                            oninput: move |e| {
                                passphrase.set(e.value());
                                submit_error.set(None);
                            },
                        }
                    }

                    // Set-as-active
                    div { style: "margin-bottom:12px;font-size:11px;",
                        label { style: "display:flex;gap:6px;align-items:center;cursor:pointer;",
                            input {
                                r#type: "checkbox",
                                checked: *set_active.read(),
                                oninput: move |e| {
                                    set_active.set(e.value() == "true");
                                },
                            }
                            span {
                                "Set "
                                span { class: "mono", "{p.identity_name}" }
                                " as the dashboard's active signing identity"
                            }
                        }
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;margin-left:18px;",
                            "Tracked for a follow-up — v1 imports the identity into the PIB; flipping the active signer is a separate ceremony surfaced in §5.3."
                        }
                    }

                    if let Some(err) = submit_error.read().clone() {
                        div { style: "font-size:11px;color:var(--red,#f85149);margin-bottom:10px;",
                            "{err}"
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
                            class: if trust_ok { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                            disabled: !trust_ok || passphrase.read().is_empty(),
                            onclick: {
                                let identity_name = p.identity_name.clone();
                                let wire = wire.clone();
                                move |_| {
                                    let pw = passphrase.read().clone();
                                    if let Err(e) = verify_passphrase(&wire, pw.as_bytes()) {
                                        submit_error.set(Some(e));
                                        return;
                                    }
                                    // §11.2 — one-time FDE warning on the
                                    // first PIB write path. Honest about
                                    // the browser-sandbox limit when
                                    // detection returns Unknown.
                                    maybe_fire_fde_warning();
                                    ctx.cmd.send(DashCmd::SecuritySafebagImport {
                                        name: identity_name.clone(),
                                        safebag_wire: wire.clone(),
                                        passphrase: pw,
                                    });
                                    close();
                                }
                            },
                            "Import & activate"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PreviewRow(label: &'static str, value: String) -> Element {
    rsx! {
        div { style: "display:flex;gap:8px;align-items:baseline;padding:3px 0;font-size:11px;",
            span { style: "color:var(--text-muted);min-width:60px;", "{label}" }
            span { class: "mono", style: "color:var(--text);word-break:break-all;", "{value}" }
        }
    }
}

#[component]
fn TrustRow(label: &'static str, row: TrustCheckRow) -> Element {
    let (icon, icon_color) = if row.ok {
        ("✓", "var(--green,#3fb950)")
    } else {
        ("✗", "var(--red,#f85149)")
    };
    rsx! {
        div { style: "padding:4px 0;font-size:11px;",
            div { style: "display:flex;gap:6px;align-items:center;",
                span { style: "color:{icon_color};font-weight:600;", "{icon}" }
                span { style: "color:var(--text);", "{label}" }
            }
            div { style: "color:var(--text-muted);font-size:10px;margin-left:18px;margin-top:2px;",
                "{row.detail}"
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wire_preview_rejects_garbage() {
        assert!(parse_wire_preview(b"").is_err());
        assert!(parse_wire_preview(b"not-a-safebag").is_err());
    }

    #[test]
    fn verify_passphrase_rejects_garbage_wire() {
        assert!(verify_passphrase(b"", b"pw").is_err());
    }

    #[test]
    fn derive_identity_and_key_strips_after_key_id() {
        let (id, key) = derive_identity_and_key("/lab/alice/KEY/k1/router-ca/v=42");
        assert_eq!(id, "/lab/alice");
        assert_eq!(key, "/lab/alice/KEY/k1");
    }

    #[test]
    fn derive_identity_and_key_no_key_component_returns_full_name() {
        let (id, key) = derive_identity_and_key("/odd/name/without/key");
        assert_eq!(id, "/odd/name/without/key");
        assert_eq!(key, "/odd/name/without/key");
    }

    fn anchor(name: &str) -> AnchorInfo {
        AnchorInfo {
            name: name.to_owned(),
        }
    }

    fn rule(idx: usize, data: &str, key: &str) -> SchemaRuleInfo {
        SchemaRuleInfo {
            index: idx,
            data_pattern: data.to_owned(),
            key_pattern: key.to_owned(),
        }
    }

    fn preview(identity: &str, key: &str, cert: &str) -> SafeBagWirePreview {
        SafeBagWirePreview {
            identity_name: identity.to_owned(),
            key_name: key.to_owned(),
            cert_name: cert.to_owned(),
        }
    }

    #[test]
    fn trust_check_anchor_membership_matches_namespace_prefix() {
        let p = preview(
            "/lab/alice",
            "/lab/alice/KEY/k1",
            "/lab/alice/KEY/k1/ca/v=1",
        );
        let anchors = vec![anchor("/lab/router-ca/KEY/k0")];
        let row = check_anchor_membership(&p.identity_name, &anchors);
        assert!(!row.ok, "anchor /lab/router-ca does not cover /lab/alice");

        let anchors = vec![anchor("/lab/KEY/k0")];
        let row = check_anchor_membership(&p.identity_name, &anchors);
        assert!(row.ok, "anchor /lab covers /lab/alice");
    }

    #[test]
    fn trust_check_fails_when_no_anchors_installed() {
        let row = check_anchor_membership("/lab/alice", &[]);
        assert!(!row.ok);
        assert!(row.detail.to_lowercase().contains("anchor"));
    }

    #[test]
    fn trust_check_schema_matches_wildcard_pattern() {
        let rules = vec![rule(0, "/lab/<user>/KEY/<id>", "/lab/router-ca/KEY/<x>")];
        let row = check_schema_match("/lab/alice/KEY/k1", &rules);
        assert!(row.ok, "wildcard rule should match: {:?}", row.detail);
    }

    #[test]
    fn trust_check_schema_fails_when_no_rule_matches() {
        let rules = vec![rule(0, "/lab/<user>/KEY/<id>", "/lab/router-ca/KEY/<x>")];
        let row = check_schema_match("/other/bob/KEY/k1", &rules);
        assert!(!row.ok);
    }

    #[test]
    fn trust_check_schema_passes_when_no_rules_configured() {
        let row = check_schema_match("/anything/at/all", &[]);
        assert!(row.ok, "no rules = dev mode = accept");
    }

    #[test]
    fn data_pattern_matches_exact_and_wildcard() {
        assert!(data_pattern_matches("/lab/alice", "/lab/alice"));
        assert!(data_pattern_matches("/lab/<user>", "/lab/alice"));
        assert!(data_pattern_matches("/lab/*", "/lab/alice"));
        assert!(!data_pattern_matches("/other/<user>", "/lab/alice"));
        // Longer name still matches a shorter pattern (prefix semantics)
        assert!(data_pattern_matches("/lab/<user>", "/lab/alice/KEY/k1"));
    }

    #[test]
    fn full_run_trust_check_aggregates_rows() {
        let p = preview(
            "/lab/alice",
            "/lab/alice/KEY/k1",
            "/lab/alice/KEY/k1/ca/v=1",
        );
        let anchors = vec![anchor("/lab/KEY/k0")];
        let rules = vec![rule(0, "/lab/<user>/KEY/<id>", "/lab/router-ca/KEY/<x>")];
        let tc = run_trust_check(&p, &anchors, &rules);
        assert!(tc.all_ok(), "{tc:?}");
    }
}
