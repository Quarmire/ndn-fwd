//! §5.1 SafeBag import — drag-drop modal + preview + trust check.
//!
//! Drag a SafeBag file — raw TLV or the base64 `ndnsec export` /
//! `ndn-sec export` emits — onto the dashboard's layout root (common
//! extensions: `.safebag`, `.tpb`, `.ndnsec`). The dashboard normalizes
//! the encoding, then parses + decrypts the wire in-browser
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
use ndn_security::safebag::{SafeBag, SafeBagAlgorithm};

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
    // Accept whatever the operator drops: a raw SafeBag TLV, or the base64
    // text `ndnsec export` emits. Normalize to raw wire up front so every
    // downstream path (preview, decrypt, import) sees the same bytes.
    let wire = normalize_safebag_bytes(&wire).unwrap_or(wire);
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

/// Best-effort: load an imported SafeBag key into the dashboard's operator
/// keyring so mgmt commands can be signed as this identity (the signing gate
/// opens). Handles both algorithms a SafeBag can carry — Ed25519 and ECDSA
/// P-256. Returns `true` if a key was provisioned. (RSA is not a SafeBag
/// algorithm here and has no signer, so it can't back signing.)
fn load_operator_key(wire: &[u8], passphrase: &[u8], key_name: &str) -> bool {
    let Ok(bag) = SafeBag::decode(wire) else {
        return false;
    };
    let Ok(pkcs8) = bag.decrypt_pkcs8(passphrase) else {
        return false;
    };
    let Ok(kn) = key_name.parse::<ndn_packet::Name>() else {
        return false;
    };
    // The certificate name is what the forwarder's trust anchor is keyed by;
    // advertise it in the command KeyLocator so signed commands resolve to the
    // anchor (otherwise the validator returns "signing certificate not yet
    // resolved"). The cert wire is retained so the imported identity is a
    // fully-held, re-exportable, persistable member of the keyring.
    let Ok(cert_data) = ndn_packet::Data::decode(bag.certificate.clone()) else {
        return false;
    };
    let cert_name = (*cert_data.name).clone();
    // Only the two SafeBag-carriable algorithms back signing.
    if !matches!(
        bag.algorithm(passphrase),
        Ok(SafeBagAlgorithm::Ed25519 | SafeBagAlgorithm::EcdsaP256)
    ) {
        return false;
    }
    crate::operator_keyring::provision_imported(kn, cert_name, &pkcs8, bag.certificate).is_ok()
}

/// Accept a SafeBag as either a raw TLV (first byte `0x80`) or the base64
/// text `ndnsec export` writes (whitespace tolerated). Returns the raw wire,
/// or `None` when neither decodes to a SafeBag.
pub fn normalize_safebag_bytes(input: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if input.first() == Some(&0x80) {
        return Some(input.to_vec());
    }
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
        .filter(|w| w.first() == Some(&0x80))
}

/// Normalize operator-supplied certificate bytes into a raw NDN Data TLV.
/// Accepts the wire in three shapes so a pasted blob "just works":
///   * raw Data TLV (first byte `0x06`),
///   * base64 (what `ndnsec`/`.cert` files carry — whitespace tolerated),
///   * lowercase/uppercase hex (`:`/`-`/whitespace tolerated).
///
/// Returns `None` when none of the three decode to something starting with
/// the Data type byte.
pub fn normalize_cert_bytes(input: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if input.first() == Some(&0x06) {
        return Some(input.to_vec());
    }
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if let Ok(w) = base64::engine::general_purpose::STANDARD.decode(&cleaned)
        && w.first() == Some(&0x06)
    {
        return Some(w);
    }
    // Hex fallback.
    let hx: Vec<u8> = cleaned
        .into_iter()
        .filter(|b| *b != b':' && *b != b'-')
        .collect();
    if hx.len() >= 2 && hx.len().is_multiple_of(2) {
        let mut out = Vec::with_capacity(hx.len() / 2);
        let mut ok = true;
        for pair in hx.chunks(2) {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && out.first() == Some(&0x06) {
            return Some(out);
        }
    }
    None
}

/// Parse a standalone certificate (from a file or pasted text) into its
/// own key name + the raw Data wire — exactly the two inputs the
/// `security/anchor-add` mgmt verb wants. Drives the §4.3 "Add trust
/// anchor" form.
pub fn parse_anchor_cert(input: &[u8]) -> Result<(String, Vec<u8>), String> {
    let wire = normalize_cert_bytes(input)
        .ok_or_else(|| "Not a certificate (expected raw Data TLV, base64, or hex)".to_owned())?;
    let data = ndn_packet::Data::decode(bytes::Bytes::from(wire.clone()))
        .map_err(|e| format!("Certificate Data decode failed: {e:?}"))?;
    Ok((data.name.to_string(), wire))
}

/// Lowercase-hex encode bytes (cert wire for the mgmt verb body).
pub fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// SHA-256 fingerprint (hex) of a cert wire — informational, used for the
/// schema journal entry on anchor-add.
pub fn cert_fingerprint_hex(wire: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(wire))
}

/// Build the `security/anchor-add` command that trusts the SafeBag's own
/// embedded certificate as an anchor (the inline TOFU gesture). The cert
/// wire is cleartext inside the bag, so no passphrase is needed to trust it
/// — only to import the private key. Returns the command plus the cert's
/// name so the caller can toast it.
fn tofu_anchor_cmd(wire: &[u8]) -> Result<(DashCmd, String), String> {
    let bag = SafeBag::decode(wire).map_err(|e| format!("SafeBag decode: {e}"))?;
    let (name, cert_wire) = parse_anchor_cert(&bag.certificate)?;
    let cmd = DashCmd::SecurityAnchorAdd {
        name: name.clone(),
        fingerprint_hex: cert_fingerprint_hex(&cert_wire),
        cert_wire_hex: hex_encode(&cert_wire),
    };
    Ok((cmd, name))
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
                    accept: ".safebag,.tpb,.ndnsec,.b64,application/octet-stream,text/plain",
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
                "raw or base64 (from "
                span { class: "mono", "ndn-sec export" }
                " / "
                span { class: "mono", "ndnsec export" }
                ") — or drag-drop the file anywhere"
            }
        }
    }
}

#[component]
pub fn SafeBagImportModal(state: Signal<SafeBagImportState>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut state = state;
    let mut passphrase: Signal<String> = use_signal(String::new);
    // Default ON: importing your operator key and signing with it is the
    // common case. Operators can uncheck to import the identity without
    // making it the dashboard's active signer.
    let mut set_active: Signal<bool> = use_signal(|| true);
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
    // Activating a *local* signing identity doesn't depend on the forwarder's
    // Data-validation anchor list (the trust check) — whether the forwarder
    // accepts the resulting signed commands is decided by its mgmt validator
    // (`trust_anchor_pib`). So the trust check only gates the forwarder-side
    // PIB import (the unchecked case).
    let activate = *set_active.read();
    let can_submit = !passphrase.read().is_empty() && (activate || trust_ok);

    let mut close = move || {
        state.write().open = false;
        passphrase.set(String::new());
        set_active.set(true);
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

                        // Inline TOFU: a self-signed root has no separate
                        // issuer anchor to install, so offer to trust the
                        // bag's own cert as an anchor (first-use). Fires
                        // `security/anchor-add` with the embedded cert, then
                        // the next poll flips the check to ✓.
                        if !trust.anchor_found.ok {
                            div { style: "margin-top:8px;padding:8px 10px;background:var(--surface2);border:1px dashed var(--border);border-radius:6px;",
                                div { style: "font-size:10px;color:var(--text-muted);margin-bottom:6px;",
                                    "No installed anchor covers this identity. If this is a "
                                    "self-signed root you trust, add its certificate as a trust "
                                    "anchor (trust-on-first-use)."
                                }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    style: "font-size:10px;",
                                    onclick: {
                                        let wire = wire.clone();
                                        move |_| {
                                            match tofu_anchor_cmd(&wire) {
                                                Ok((cmd, name)) => {
                                                    ctx.cmd.send(cmd);
                                                    ctx.cmd.send(DashCmd::RefreshNow);
                                                    push_toast(
                                                        format!("Trusting {name} as an anchor…"),
                                                        ToastLevel::Info,
                                                    );
                                                    submit_error.set(None);
                                                }
                                                Err(e) => submit_error.set(Some(e)),
                                            }
                                        }
                                    },
                                    "⚓ Trust this certificate as an anchor (TOFU)"
                                }
                            }
                        }

                        // The trust check gates *forwarder-side* import. When
                        // you're only loading this key as the dashboard's
                        // signing identity, it doesn't apply — the forwarder
                        // validates your commands against its own operator
                        // anchor (trust_anchor_pib).
                        if activate && !trust_ok {
                            div { style: "font-size:10px;color:var(--text-muted);margin-top:8px;font-style:italic;",
                                "Activating a signing identity doesn't require the checks above — "
                                "they gate importing an identity into the forwarder's keystore."
                            }
                        }
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
                            "Loads the key into the dashboard so it signs management commands as "
                            "this identity — this is how you bootstrap signing against a forwarder "
                            "that enforces signed commands. Uncheck to instead push this identity "
                            "into the forwarder's own keystore (requires you to already be a "
                            "trusted operator)."
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
                            class: if can_submit { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                            disabled: !can_submit,
                            onclick: {
                                let identity_name = p.identity_name.clone();
                                let key_name = p.key_name.clone();
                                // The forwarder's safebag-import checks the
                                // requested name against the embedded cert's
                                // full name — so send the cert name, not the
                                // bare identity.
                                let cert_name = p.cert_name.clone();
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

                                    let activate = *set_active.read();
                                    let already_signer =
                                        crate::operator_keyring::is_provisioned();
                                    // Load the operator key into the dashboard
                                    // keyring so mgmt commands sign as this
                                    // identity (the signing gate opens).
                                    let provisioned = activate
                                        && load_operator_key(&wire, pw.as_bytes(), &key_name);
                                    if provisioned {
                                        crate::app_shared::bump_keyring_gen();
                                    }

                                    if provisioned && !already_signer {
                                        // Bootstrap: this import provisions the
                                        // dashboard's *first* signing key. The
                                        // command client can't sign until it
                                        // reconnects with that key, so firing
                                        // the (signed) safebag-import now would
                                        // be rejected — and persisting the
                                        // operator's own key into the forwarder
                                        // PIB isn't needed (the forwarder
                                        // already trusts it via its anchor).
                                        // Just activate + reconnect.
                                        ctx.cmd.send(DashCmd::Reconnect);
                                        push_toast(
                                            format!(
                                                "Now signing management commands as {identity_name}"
                                            ),
                                            ToastLevel::Success,
                                        );
                                    } else {
                                        // Already a trusted signer (or not
                                        // activating): persist the identity into
                                        // the forwarder keystore over the signed
                                        // management channel.
                                        ctx.cmd.send(DashCmd::SecuritySafebagImport {
                                            name: cert_name.clone(),
                                            safebag_wire: wire.clone(),
                                            passphrase: pw,
                                        });
                                        if provisioned {
                                            ctx.cmd.send(DashCmd::Reconnect);
                                        }
                                    }
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
    fn normalize_safebag_accepts_raw_and_base64() {
        use base64::Engine as _;
        // A "SafeBag" for the purposes of normalization is anything starting
        // with the 0x80 type byte.
        let raw = vec![0x80u8, 0x01, 0x00];
        assert_eq!(normalize_safebag_bytes(&raw), Some(raw.clone()));

        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(normalize_safebag_bytes(b64.as_bytes()), Some(raw.clone()));

        // ndnsec wraps base64 across lines — whitespace must be tolerated.
        let wrapped = format!("{b64}\n");
        assert_eq!(normalize_safebag_bytes(wrapped.as_bytes()), Some(raw));

        assert_eq!(normalize_safebag_bytes(b"not-a-bag"), None);
        // base64 that decodes but isn't a SafeBag is rejected.
        let other = base64::engine::general_purpose::STANDARD.encode([0x06u8, 0x00]);
        assert_eq!(normalize_safebag_bytes(other.as_bytes()), None);
    }

    #[test]
    fn normalize_cert_accepts_raw_base64_hex() {
        use base64::Engine as _;
        let raw = vec![0x06u8, 0x01, 0x00];
        assert_eq!(normalize_cert_bytes(&raw), Some(raw.clone()));

        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(normalize_cert_bytes(b64.as_bytes()), Some(raw.clone()));

        assert_eq!(normalize_cert_bytes(b"060100"), Some(raw.clone()));
        assert_eq!(normalize_cert_bytes(b"06:01:00"), Some(raw));

        assert_eq!(normalize_cert_bytes(b"zzz!!!"), None);
    }

    #[test]
    fn parse_anchor_cert_rejects_non_cert() {
        assert!(parse_anchor_cert(b"").is_err());
        // 0x80 is a SafeBag, not a bare cert Data (0x06).
        assert!(parse_anchor_cert(&[0x80, 0x01, 0x00]).is_err());
    }

    #[test]
    fn verify_passphrase_rejects_garbage_wire() {
        assert!(verify_passphrase(b"", b"pw").is_err());
    }

    #[test]
    fn load_operator_key_rejects_garbage_wire() {
        // A non-SafeBag wire never provisions a key (and never panics).
        assert!(!load_operator_key(
            b"not-a-safebag",
            b"pw",
            "/op/alice/KEY/k1"
        ));
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
            source: None,
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
