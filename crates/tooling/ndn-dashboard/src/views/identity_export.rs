//! In-dashboard operator identity **generation** and **SafeBag export** —
//! the dashboard-native replacement for `ndn-sec keygen` / `ndn-sec export`.
//!
//! Generation builds an Ed25519 or ECDSA-P256 key plus a self-signed
//! certificate entirely in-page, provisions it as the dashboard's active
//! signing identity (so it can immediately sign management commands), and
//! retains the material to re-emit it as a passphrase-encrypted SafeBag.
//! Nothing touches the forwarder until the operator chooses to act.

use bytes::Bytes;
use dioxus::prelude::*;
use ndn_packet::{Name, NameComponent};
use ndn_security::{EcdsaP256Signer, Ed25519Signer, Signer, encode_cert_data};
use std::sync::Arc;

use crate::app::{AppCtx, DashCmd, ToastLevel, push_toast};

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
#[cfg(target_arch = "wasm32")]
fn now_unix_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Key algorithm for a generated operator identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GenAlgo {
    Ed25519,
    Ecdsa,
}

impl GenAlgo {
    fn from_str(s: &str) -> Self {
        if s == "ecdsa" {
            Self::Ecdsa
        } else {
            Self::Ed25519
        }
    }
}

/// Generate an operator identity (key + self-signed cert) in-page and
/// provision it as the dashboard's active signing identity. Returns the
/// certificate name on success.
pub async fn generate_operator_identity(
    identity: &str,
    algo: GenAlgo,
    validity_days: u64,
) -> Result<String, String> {
    let identity: Name = identity
        .parse()
        .map_err(|e| format!("invalid identity name: {e:?}"))?;
    if identity.components().is_empty() {
        return Err("identity name must not be empty".into());
    }

    // Certificate-Format-v2 names: key `<id>/KEY/<keyid>`, cert appends
    // `<issuer=self>/<version>`.
    let mut keyid = [0u8; 8];
    getrandom::getrandom(&mut keyid).map_err(|_| "rng failure".to_string())?;
    let keyid_hex: String = keyid.iter().map(|b| format!("{b:02x}")).collect();
    let key_name = identity
        .clone()
        .append("KEY")
        .append_component(NameComponent::generic(Bytes::from(keyid_hex.into_bytes())));
    let cert_name = key_name
        .clone()
        .append_component(NameComponent::generic(Bytes::from_static(b"self")))
        .append_version(0);

    // Build the concrete signer, then extract its PKCS#8 + public key before
    // type-erasing to `dyn Signer`.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| "rng failure".to_string())?;
    let (signer, pkcs8, pubkey): (Arc<dyn Signer>, Vec<u8>, Bytes) = match algo {
        GenAlgo::Ed25519 => {
            let s = Ed25519Signer::from_seed(&seed, key_name.clone());
            let pkcs8 = s.to_pkcs8_der().map_err(|e| format!("pkcs8: {e}"))?;
            let pk = s.public_key().ok_or("no public key")?;
            (Arc::new(s), pkcs8, pk)
        }
        GenAlgo::Ecdsa => {
            let s = EcdsaP256Signer::from_seed(&seed, key_name.clone())
                .map_err(|e| format!("ecdsa key: {e}"))?;
            let pkcs8 = s.to_pkcs8_der().map_err(|e| format!("pkcs8: {e}"))?;
            let pk = s.public_key().ok_or("no public key")?;
            (Arc::new(s), pkcs8, pk)
        }
    };

    let now_ns = now_unix_ns();
    let valid_until = now_ns.saturating_add(
        validity_days
            .saturating_mul(86_400)
            .saturating_mul(1_000_000_000),
    );
    let cert_wire = encode_cert_data(&cert_name, &pubkey, signer.as_ref(), now_ns, valid_until)
        .await
        .map_err(|e| format!("self-sign certificate: {e}"))?;

    crate::operator_keyring::provision_generated(
        key_name,
        cert_name.clone(),
        signer,
        pkcs8,
        Bytes::from(cert_wire.to_vec()),
    );
    Ok(cert_name.to_string())
}

/// §5 — operator identity panel: generate an identity in the dashboard, then
/// export it (or any dashboard-generated identity) as a SafeBag. The
/// dashboard-native path that makes `ndn-sec keygen` / `ndn-sec export`
/// optional.
/// A merged "Your identities" row: a loaded (signing) identity and/or a
/// locked one persisted on this device.
#[derive(Clone)]
struct IdRow {
    identity: String,
    key_name: String,
    algorithm: String,
    fingerprint: String,
    loaded: bool,
    active: bool,
    exportable: bool,
    saved: bool,
    guard: crate::keyguard::GuardKind,
    safebag_b64: Option<String>,
}

fn merged_rows() -> Vec<IdRow> {
    use crate::keyguard::GuardKind;
    let loaded = crate::operator_keyring::list_identities();
    let saved = crate::operator_keyring_store::load_saved();
    let mut rows: Vec<IdRow> = loaded
        .iter()
        .map(|l| {
            let saved_entry = saved.iter().find(|s| s.fingerprint == l.fingerprint);
            IdRow {
                identity: l.identity.clone(),
                key_name: l.key_name.clone(),
                algorithm: l.algorithm.clone(),
                fingerprint: l.fingerprint.clone(),
                loaded: true,
                active: l.active,
                exportable: l.exportable,
                saved: saved_entry.is_some(),
                guard: saved_entry.map(|s| s.guard).unwrap_or(GuardKind::Passphrase),
                safebag_b64: None,
            }
        })
        .collect();
    for s in &saved {
        if !loaded.iter().any(|l| l.fingerprint == s.fingerprint) {
            rows.push(IdRow {
                identity: s.identity.clone(),
                key_name: s.key_name.clone(),
                algorithm: s.algorithm.clone(),
                fingerprint: s.fingerprint.clone(),
                loaded: false,
                active: false,
                exportable: false,
                saved: true,
                guard: s.guard,
                safebag_b64: Some(s.safebag_b64.clone()),
            });
        }
    }
    rows
}

/// Save a held identity to this device sealed by the OS keychain — no typed
/// passphrase (the OS gates release with login/biometric).
fn save_identity_os_keychain(row: &IdRow) -> Result<(), String> {
    use base64::Engine as _;
    let pass = crate::keyguard::os_keychain_seal(&row.fingerprint)?;
    let wire = match crate::operator_keyring::export_safebag_for(&row.key_name, pass.as_bytes()) {
        Some(Ok(w)) => w,
        Some(Err(e)) => return Err(e),
        None => return Err("identity is not exportable".into()),
    };
    let item = crate::operator_keyring_store::SavedIdentity {
        identity: row.identity.clone(),
        key_name: row.key_name.clone(),
        cert_name: String::new(),
        algorithm: row.algorithm.clone(),
        fingerprint: row.fingerprint.clone(),
        safebag_b64: base64::engine::general_purpose::STANDARD.encode(&wire),
        guard: crate::keyguard::GuardKind::OsKeychain,
    };
    crate::operator_keyring_store::upsert(item).map_err(|e| format!("save failed: {e}"))
}

/// A passphrase-requiring action awaiting confirmation, so the password input
/// appears in context (scoped to the identity + action) instead of sitting in
/// the middle of the panel.
#[derive(Clone, PartialEq)]
enum PendingKind {
    Save,
    Unlock,
    Export,
}

#[derive(Clone, PartialEq)]
struct PendingOp {
    kind: PendingKind,
    identity: String,
    key_name: String,
    fingerprint: String,
    algorithm: String,
    safebag_b64: Option<String>,
}

impl PendingOp {
    fn from_row(kind: PendingKind, row: &IdRow) -> Self {
        Self {
            kind,
            identity: row.identity.clone(),
            key_name: row.key_name.clone(),
            fingerprint: row.fingerprint.clone(),
            algorithm: row.algorithm.clone(),
            safebag_b64: row.safebag_b64.clone(),
        }
    }
    fn verb(&self) -> &'static str {
        match self.kind {
            PendingKind::Save => "save",
            PendingKind::Unlock => "unlock",
            PendingKind::Export => "export",
        }
    }
}

#[component]
pub fn OperatorIdentityPanel() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut gen_name: Signal<String> = use_signal(String::new);
    let mut gen_algo: Signal<String> = use_signal(|| "ed25519".to_string());
    let mut gen_busy: Signal<bool> = use_signal(|| false);
    // A passphrase prompt appears only when an action needs it (scoped to the
    // identity), instead of a password box sitting in the panel.
    let mut pending: Signal<Option<PendingOp>> = use_signal(|| None);
    let mut prompt_pw: Signal<String> = use_signal(String::new);
    let mut export_b64: Signal<Option<String>> = use_signal(|| None);
    let mut error: Signal<Option<String>> = use_signal(|| None);

    // Subscribe to keyring changes so the list reacts to
    // generate / import / switch / forget / save / unlock.
    let _ = crate::app_shared::KEYRING_GEN.read();
    let rows = merged_rows();
    let exportable = crate::operator_keyring::active_is_exportable();
    let active_id = crate::operator_keyring::active_identity_name();

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:4px;",
                "Your identities"
            }
            div { style: "font-size:10px;color:var(--text-muted);margin-bottom:12px;",
                "Signing identities the dashboard holds — portable, independent of any "
                "forwarder. Generate or import them, save them to this device (encrypted), "
                "and export as a SafeBag; no "
                span { class: "mono", "ndn-sec" }
                " needed. A forwarder accepts an identity's commands once its certificate "
                "is a trust anchor there."
            }

            // ── Held + saved identities ────────────────────────────────
            if rows.is_empty() {
                div { class: "empty", style: "margin-bottom:12px;",
                    "No identities yet. Generate one below, or import a SafeBag."
                }
            } else {
                div { style: "margin-bottom:12px;",
                    for id in rows.iter() {
                        div {
                            key: "{id.fingerprint}",
                            style: "display:flex;gap:10px;align-items:center;padding:8px 0;border-top:1px solid var(--border-subtle);font-size:12px;",
                            span { style: "font-size:14px;",
                                if id.active { "🔑" } else if !id.loaded { "🔒" } else { "•" }
                            }
                            div { style: "flex:1;min-width:0;",
                                div { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap;",
                                    span { class: "mono", style: "color:var(--text);word-break:break-all;", "{id.identity}" }
                                    if id.active {
                                        span { class: "badge badge-green", style: "font-size:9px;", "active signer" }
                                    }
                                    if !id.loaded {
                                        span { class: "badge badge-gray", style: "font-size:9px;", "locked" }
                                    }
                                    if id.saved {
                                        span { class: "badge badge-blue", style: "font-size:9px;",
                                            if id.guard == crate::keyguard::GuardKind::OsKeychain { "saved · 🔐 device" } else { "saved · passphrase" }
                                        }
                                    }
                                    if id.loaded && !id.exportable {
                                        span { class: "badge badge-gray", style: "font-size:9px;", "signing only" }
                                    }
                                }
                                div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                                    "{id.algorithm} · fp {id.fingerprint}"
                                }
                            }
                            // Unlock a locked (persisted) identity — OS-keychain
                            // releases via the OS (biometric/login, no prompt);
                            // passphrase guards raise the contextual prompt.
                            if !id.loaded {
                                button {
                                    class: "btn btn-primary btn-sm",
                                    style: "font-size:10px;",
                                    onclick: {
                                        let row = id.clone();
                                        move |_| {
                                            error.set(None);
                                            match row.guard {
                                                crate::keyguard::GuardKind::OsKeychain => {
                                                    use base64::Engine as _;
                                                    match crate::keyguard::os_keychain_release(&row.fingerprint) {
                                                        Ok(pass) => {
                                                            let wire = row.safebag_b64.as_deref()
                                                                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s.trim()).ok());
                                                            match wire {
                                                                Some(wire) => match crate::operator_keyring::provision_from_safebag(&wire, pass.as_bytes()) {
                                                                    Ok(name) => {
                                                                        crate::app_shared::bump_keyring_gen();
                                                                        ctx.cmd.send(DashCmd::Reconnect);
                                                                        push_toast(format!("Unlocked {name} (this device)"), ToastLevel::Success);
                                                                    }
                                                                    Err(e) => error.set(Some(e)),
                                                                },
                                                                None => error.set(Some("corrupt saved identity".into())),
                                                            }
                                                        }
                                                        Err(e) => error.set(Some(e)),
                                                    }
                                                }
                                                crate::keyguard::GuardKind::Passphrase => {
                                                    prompt_pw.set(String::new());
                                                    pending.set(Some(PendingOp::from_row(PendingKind::Unlock, &row)));
                                                }
                                                crate::keyguard::GuardKind::RemoteSigner => {
                                                    error.set(Some("Remote-signer unlock isn't wired yet — pairing and the signer app are the next step.".into()));
                                                }
                                            }
                                        }
                                    },
                                    if id.guard == crate::keyguard::GuardKind::OsKeychain { "Unlock (device)" } else { "Unlock" }
                                }
                            }
                            // Switch the active signer.
                            if id.loaded && !id.active {
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    style: "font-size:10px;",
                                    onclick: {
                                        let kn = id.key_name.clone();
                                        move |_| {
                                            if crate::operator_keyring::set_active(&kn) {
                                                crate::app_shared::bump_keyring_gen();
                                                ctx.cmd.send(DashCmd::Reconnect);
                                            }
                                        }
                                    },
                                    "Use"
                                }
                            }
                            // Save a loaded, exportable identity to this device.
                            // Primary: OS keychain (no password). Secondary:
                            // passphrase (portable).
                            if id.loaded && id.exportable && !id.saved {
                                if crate::keyguard::os_keychain_available() {
                                    button {
                                        class: "btn btn-primary btn-sm",
                                        style: "font-size:10px;",
                                        title: "Sealed by this device, no password. Per-use Touch ID needs a code-signed app build; an unsigned/dev build is device-bound but login-gated.",
                                        onclick: {
                                            let row = id.clone();
                                            move |_| {
                                                error.set(None);
                                                match save_identity_os_keychain(&row) {
                                                    Ok(()) => {
                                                        crate::app_shared::bump_keyring_gen();
                                                        push_toast(format!("Saved {} on this device (no password)", row.identity), ToastLevel::Success);
                                                    }
                                                    Err(e) => error.set(Some(format!("{e} — try Save (passphrase)"))),
                                                }
                                            }
                                        },
                                        "🔐 Save to device"
                                    }
                                }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    style: "font-size:10px;",
                                    onclick: {
                                        let row = id.clone();
                                        move |_| {
                                            prompt_pw.set(String::new());
                                            error.set(None);
                                            pending.set(Some(PendingOp::from_row(PendingKind::Save, &row)));
                                        }
                                    },
                                    "Save (passphrase)"
                                }
                            }
                            // Lock: sign out (unload the key) but keep it saved
                            // on this device, so it returns as a locked entry.
                            if id.loaded && id.saved {
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    style: "font-size:10px;",
                                    onclick: {
                                        let kn = id.key_name.clone();
                                        let identity = id.identity.clone();
                                        move |_| {
                                            crate::operator_keyring::remove_identity(&kn);
                                            crate::app_shared::bump_keyring_gen();
                                            push_toast(format!("Locked {identity}"), ToastLevel::Info);
                                        }
                                    },
                                    "Lock"
                                }
                            }
                            // Forget: drop from the keyring AND the device store
                            // (and any OS-keychain secret).
                            button {
                                class: "btn btn-secondary btn-sm",
                                style: "font-size:10px;color:var(--red,#f85149);",
                                onclick: {
                                    let kn = id.key_name.clone();
                                    let fp = id.fingerprint.clone();
                                    let guard = id.guard;
                                    move |_| {
                                        crate::operator_keyring::remove_identity(&kn);
                                        let _ = crate::operator_keyring_store::remove(&fp);
                                        if guard == crate::keyguard::GuardKind::OsKeychain {
                                            crate::keyguard::os_keychain_forget(&fp);
                                        }
                                        crate::app_shared::bump_keyring_gen();
                                    }
                                },
                                "Forget"
                            }
                        }
                    }
                }
            }

            // ── Contextual passphrase prompt (save / unlock / export) ───
            if let Some(op) = pending.read().clone() {
                div { style: "margin:4px 0 14px;padding:10px;background:var(--surface);border:1px solid var(--accent,#58a6ff)66;border-radius:6px;",
                    div { style: "font-size:11px;color:var(--text);margin-bottom:6px;",
                        "Passphrase to {op.verb()} "
                        span { class: "mono", "{op.identity}" }
                        if op.kind == PendingKind::Save {
                            span { style: "color:var(--text-muted);", " (encrypts it on this device)" }
                        }
                    }
                    div { style: "display:flex;gap:8px;align-items:center;",
                        input {
                            r#type: "password",
                            autofocus: true,
                            value: "{prompt_pw}",
                            style: "width:240px;",
                            oninput: move |e| { prompt_pw.set(e.value()); error.set(None); },
                        }
                        button {
                            class: "btn btn-primary btn-sm",
                            disabled: prompt_pw.read().is_empty(),
                            onclick: {
                                let op = op.clone();
                                move |_| {
                                    use base64::Engine as _;
                                    let b64 = base64::engine::general_purpose::STANDARD;
                                    let pass = prompt_pw.peek().clone();
                                    let outcome: Result<(), String> = match op.kind {
                                        PendingKind::Unlock => {
                                            match op.safebag_b64.as_deref().and_then(|s| b64.decode(s.trim()).ok()) {
                                                Some(wire) => crate::operator_keyring::provision_from_safebag(&wire, pass.as_bytes())
                                                    .map(|name| {
                                                        crate::app_shared::bump_keyring_gen();
                                                        ctx.cmd.send(DashCmd::Reconnect);
                                                        push_toast(format!("Unlocked and now signing as {name}"), ToastLevel::Success);
                                                    }),
                                                None => Err("corrupt saved identity".into()),
                                            }
                                        }
                                        PendingKind::Save => {
                                            match crate::operator_keyring::export_safebag_for(&op.key_name, pass.as_bytes()) {
                                                Some(Ok(wire)) => {
                                                    let item = crate::operator_keyring_store::SavedIdentity {
                                                        identity: op.identity.clone(),
                                                        key_name: op.key_name.clone(),
                                                        cert_name: String::new(),
                                                        algorithm: op.algorithm.clone(),
                                                        fingerprint: op.fingerprint.clone(),
                                                        safebag_b64: b64.encode(&wire),
                                                        guard: crate::keyguard::GuardKind::Passphrase,
                                                    };
                                                    crate::operator_keyring_store::upsert(item)
                                                        .map(|()| {
                                                            crate::app_shared::bump_keyring_gen();
                                                            push_toast(format!("Saved {} to this device", op.identity), ToastLevel::Success);
                                                        })
                                                        .map_err(|e| format!("save failed: {e}"))
                                                }
                                                Some(Err(e)) => Err(e),
                                                None => Err("identity is not exportable".into()),
                                            }
                                        }
                                        PendingKind::Export => {
                                            match crate::operator_keyring::export_active_safebag(pass.as_bytes()) {
                                                Some(Ok(wire)) => { export_b64.set(Some(b64.encode(&wire))); Ok(()) }
                                                Some(Err(e)) => Err(e),
                                                None => Err("active identity is not exportable".into()),
                                            }
                                        }
                                    };
                                    match outcome {
                                        Ok(()) => { pending.set(None); prompt_pw.set(String::new()); error.set(None); }
                                        Err(e) => error.set(Some(e)),
                                    }
                                }
                            },
                            "Confirm"
                        }
                        button {
                            class: "btn btn-secondary btn-sm",
                            onclick: move |_| { pending.set(None); prompt_pw.set(String::new()); error.set(None); },
                            "Cancel"
                        }
                    }
                }
            }

            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:8px;padding-top:6px;border-top:1px solid var(--border-subtle);",
                "Generate a new identity"
            }

            // ── Generate ────────────────────────────────────────────────
            div { style: "display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;",
                div { class: "form-group",
                    label { style: "font-size:11px;color:var(--text-muted);", "Identity name" }
                    input {
                        r#type: "text",
                        placeholder: "/op/alice",
                        value: "{gen_name}",
                        style: "width:240px;",
                        oninput: move |e| { gen_name.set(e.value()); error.set(None); },
                    }
                }
                div { class: "form-group",
                    label { style: "font-size:11px;color:var(--text-muted);", "Algorithm" }
                    select {
                        value: "{gen_algo}",
                        oninput: move |e| gen_algo.set(e.value()),
                        option { value: "ed25519", "Ed25519" }
                        option { value: "ecdsa", "ECDSA P-256 (ndn-cxx interop)" }
                    }
                }
                button {
                    class: "btn btn-primary btn-sm",
                    disabled: gen_name.read().trim().is_empty() || *gen_busy.read(),
                    onclick: move |_| {
                        let name = gen_name.peek().trim().to_string();
                        let algo = GenAlgo::from_str(&gen_algo.peek());
                        if name.is_empty() { return; }
                        gen_busy.set(true);
                        error.set(None);
                        spawn(async move {
                            match generate_operator_identity(&name, algo, 365).await {
                                Ok(cert) => {
                                    crate::app_shared::bump_keyring_gen();
                                    push_toast(
                                        format!("Generated and now signing as {name} (cert {cert})"),
                                        ToastLevel::Success,
                                    );
                                    gen_name.set(String::new());
                                }
                                Err(e) => error.set(Some(e)),
                            }
                            gen_busy.set(false);
                        });
                    },
                    if *gen_busy.read() { "Generating…" } else { "Generate & activate" }
                }
            }

            if let Some(id) = active_id.as_ref() {
                div { style: "font-size:11px;color:var(--text-muted);margin-top:10px;",
                    "Active signing identity: "
                    span { class: "mono", style: "color:var(--text);", "{id}" }
                    if !exportable {
                        span { style: "margin-left:8px;", "(imported — already have its SafeBag)" }
                    }
                }
            }

            // ── Export ──────────────────────────────────────────────────
            if exportable {
                div { style: "margin-top:12px;padding-top:12px;border-top:1px solid var(--border-subtle);",
                    div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                        "Export the active identity as a SafeBag"
                    }
                    div { style: "display:flex;gap:8px;align-items:flex-end;",
                        button {
                            class: "btn btn-secondary btn-sm",
                            onclick: {
                                let identity = active_id.clone().unwrap_or_default();
                                move |_| {
                                    prompt_pw.set(String::new());
                                    error.set(None);
                                    pending.set(Some(PendingOp {
                                        kind: PendingKind::Export,
                                        identity: identity.clone(),
                                        key_name: String::new(),
                                        fingerprint: String::new(),
                                        algorithm: String::new(),
                                        safebag_b64: None,
                                    }));
                                }
                            },
                            "Export SafeBag…"
                        }
                    }
                    if let Some(b64) = export_b64.read().clone() {
                        div { style: "margin-top:8px;",
                            div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;",
                                "Base64 SafeBag — save as "
                                span { class: "mono", "<identity>.safebag" }
                                ". Import it elsewhere with this dashboard or "
                                span { class: "mono", "ndnsec import" }
                                "."
                            }
                            textarea {
                                readonly: true,
                                style: "width:100%;min-height:90px;font-family:var(--font-mono);font-size:10px;padding:6px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);word-break:break-all;",
                                "{b64}"
                            }
                        }
                    }
                }
            }

            if let Some(err) = error.read().clone() {
                div { style: "font-size:11px;color:var(--red,#f85149);margin-top:8px;", "{err}" }
            }
        }
    }
}

/// "Set up forwarder trust" — turn the active operator identity into the
/// artifacts a forwarder needs to trust it (anchor PIB + config snippet), so
/// the only manual step is "set the config and restart" — no CLI. Opens from
/// the trust banner's "Set up forwarder trust →" CTA.
#[component]
pub fn PreprovisionPanel() -> Element {
    let _ = crate::app_shared::KEYRING_GEN.read();
    let mut open: Signal<bool> = use_signal(|| false);
    // Consume the one-shot open flag (mirrors ACTIVE_SECURITY_TAB).
    if *crate::app_shared::PREPROVISION_OPEN.read() {
        open.set(true);
        *crate::app_shared::PREPROVISION_OPEN.write() = false;
    }
    // (path, config_snippet, cert_b64)
    let mut result: Signal<Option<(Option<String>, String, String)>> = use_signal(|| None);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let active = crate::operator_keyring::active_identity_name();

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div {
                style: "display:flex;justify-content:space-between;align-items:center;cursor:pointer;",
                onclick: move |_| { let v = *open.read(); open.set(!v); },
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    "Set up forwarder trust"
                }
                span { style: "color:var(--text-muted);", if *open.read() { "▾" } else { "▸" } }
            }

            if *open.read() {
                div { style: "font-size:10px;color:var(--text-muted);margin:8px 0 12px;",
                    "Make the attached forwarder accept commands signed by your active "
                    "identity. The dashboard writes a trust-anchor store and the exact "
                    "config — you set it and restart the forwarder. (Establishing trust is "
                    "out-of-band by design; this just removes the CLI from it.)"
                }
                if let Some(id) = active.as_ref() {
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: {
                            let id = id.clone();
                            move |_| {
                                error.set(None);
                                match crate::operator_keyring::active_cert_wire() {
                                    Some(wire) => match crate::preprovision::build(&id, &wire) {
                                        Ok(a) => result.set(Some((a.anchor_pib_path, a.config_snippet, a.cert_b64))),
                                        Err(e) => error.set(Some(e)),
                                    },
                                    None => error.set(Some(
                                        "The active identity has no certificate to anchor — generate or import a full identity first.".into())),
                                }
                            }
                        },
                        "Generate trust files for {id}"
                    }
                } else {
                    div { class: "empty", "Activate a signing identity first (under Your identities)." }
                }

                if let Some((path, config, cert)) = result.read().clone() {
                    div { style: "margin-top:12px;",
                        if let Some(p) = path.as_ref() {
                            div { style: "font-size:11px;color:var(--green,#3fb950);margin-bottom:6px;",
                                "✓ Wrote trust-anchor store to "
                                span { class: "mono", style: "word-break:break-all;", "{p}" }
                            }
                        } else {
                            div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                                "On this platform the dashboard can't write files. Create the "
                                "anchor store with "
                                span { class: "mono", "ndn-sec import --anchor <file>" }
                                " from the certificate below, then use the config:"
                            }
                        }
                        div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;", "Forwarder config — add and restart:" }
                        textarea {
                            readonly: true,
                            style: "width:100%;min-height:64px;font-family:var(--font-mono);font-size:10px;padding:6px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);",
                            "{config}"
                        }
                        if path.is_none() {
                            div { style: "font-size:10px;color:var(--text-muted);margin:6px 0 4px;", "Certificate (base64):" }
                            textarea {
                                readonly: true,
                                style: "width:100%;min-height:64px;font-family:var(--font-mono);font-size:10px;padding:6px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);word-break:break-all;",
                                "{cert}"
                            }
                        }
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:6px;",
                            "Read-only datasets work immediately; signed commands work after the forwarder restarts with this config."
                        }
                    }
                }

                if let Some(err) = error.read().clone() {
                    div { style: "font-size:11px;color:var(--red,#f85149);margin-top:8px;", "{err}" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror `generate_operator_identity`'s crypto (without the process-
    /// global keyring) and prove the resulting SafeBag round-trips: a valid
    /// self-signed cert + a passphrase-encrypted key that decrypts.
    #[tokio::test]
    async fn generated_identity_safebag_roundtrips() {
        let key_name: Name = "/op/test/KEY/k0".parse().unwrap();
        let cert_name: Name = "/op/test/KEY/k0/self/v=0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[3u8; 32], key_name.clone());
        let pkcs8 = signer.to_pkcs8_der().unwrap();
        let pubkey = signer.public_key().unwrap();
        let cert_wire = encode_cert_data(&cert_name, &pubkey, &signer, 0, u64::MAX)
            .await
            .unwrap();

        let bag = ndn_security::safebag::SafeBag::encrypt(Bytes::from(cert_wire.to_vec()), &pkcs8, b"pw")
            .expect("encrypt");
        let wire = bag.encode();

        let parsed = ndn_security::safebag::SafeBag::decode(&wire).expect("decode");
        let cert_data = ndn_packet::Data::decode(parsed.certificate.clone()).expect("cert data");
        assert_eq!(cert_data.name.to_string(), "/op/test/KEY/k0/self/v=0");
        assert!(parsed.decrypt_pkcs8(b"pw").is_ok());
        assert!(parsed.decrypt_pkcs8(b"wrong").is_err());
    }
}
