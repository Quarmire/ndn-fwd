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
#[component]
pub fn OperatorIdentityPanel() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut gen_name: Signal<String> = use_signal(String::new);
    let mut gen_algo: Signal<String> = use_signal(|| "ed25519".to_string());
    let mut gen_busy: Signal<bool> = use_signal(|| false);
    let mut export_pw: Signal<String> = use_signal(String::new);
    let mut export_b64: Signal<Option<String>> = use_signal(|| None);
    let mut error: Signal<Option<String>> = use_signal(|| None);

    // Subscribe to keyring changes so the held-identity list reacts to
    // generate / import / switch / forget.
    let _ = crate::app_shared::KEYRING_GEN.read();
    let identities = crate::operator_keyring::list_identities();
    let exportable = crate::operator_keyring::active_is_exportable();
    let active_id = crate::operator_keyring::active_identity_name();

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:4px;",
                "Your identities"
            }
            div { style: "font-size:10px;color:var(--text-muted);margin-bottom:12px;",
                "Signing identities the dashboard holds — portable, independent of any "
                "forwarder. Generate or import them here and export as a SafeBag; no "
                span { class: "mono", "ndn-sec" }
                " needed. A forwarder accepts an identity's commands once its certificate "
                "is a trust anchor there."
            }

            // ── Held identities ────────────────────────────────────────
            if identities.is_empty() {
                div { class: "empty", style: "margin-bottom:12px;",
                    "No identities yet. Generate one below, or import a SafeBag."
                }
            } else {
                div { style: "margin-bottom:12px;",
                    for id in identities.iter() {
                        div {
                            key: "{id.key_name}",
                            style: "display:flex;gap:10px;align-items:center;padding:8px 0;border-top:1px solid var(--border-subtle);font-size:12px;",
                            span { style: "font-size:14px;", if id.active { "🔑" } else { "•" } }
                            div { style: "flex:1;min-width:0;",
                                div { style: "display:flex;gap:8px;align-items:center;",
                                    span { class: "mono", style: "color:var(--text);word-break:break-all;", "{id.identity}" }
                                    if id.active {
                                        span { class: "badge badge-green", style: "font-size:9px;", "active signer" }
                                    }
                                    if !id.exportable {
                                        span { class: "badge badge-gray", style: "font-size:9px;", "signing only" }
                                    }
                                }
                                div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                                    "{id.algorithm} · fp {id.fingerprint}"
                                }
                            }
                            if !id.active {
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
                            button {
                                class: "btn btn-secondary btn-sm",
                                style: "font-size:10px;",
                                onclick: {
                                    let kn = id.key_name.clone();
                                    move |_| {
                                        if crate::operator_keyring::remove_identity(&kn) {
                                            crate::app_shared::bump_keyring_gen();
                                        }
                                    }
                                },
                                "Forget"
                            }
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
                        div { class: "form-group",
                            label { style: "font-size:11px;color:var(--text-muted);", "Passphrase" }
                            input {
                                r#type: "password",
                                value: "{export_pw}",
                                style: "width:240px;",
                                oninput: move |e| { export_pw.set(e.value()); error.set(None); },
                            }
                        }
                        button {
                            class: "btn btn-secondary btn-sm",
                            disabled: export_pw.read().is_empty(),
                            onclick: move |_| {
                                let pw = export_pw.peek().clone();
                                match crate::operator_keyring::export_active_safebag(pw.as_bytes()) {
                                    Some(Ok(wire)) => {
                                        use base64::Engine as _;
                                        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
                                        export_b64.set(Some(b64));
                                        error.set(None);
                                    }
                                    Some(Err(e)) => error.set(Some(e)),
                                    None => error.set(Some("active identity is not exportable".into())),
                                }
                            },
                            "Export SafeBag"
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

        let bag = ndn_safebag::SafeBag::encrypt(Bytes::from(cert_wire.to_vec()), &pkcs8, b"pw")
            .expect("encrypt");
        let wire = bag.encode();

        let parsed = ndn_safebag::SafeBag::decode(&wire).expect("decode");
        let cert_data = ndn_packet::Data::decode(parsed.certificate.clone()).expect("cert data");
        assert_eq!(cert_data.name.to_string(), "/op/test/KEY/k0/self/v=0");
        assert!(parsed.decrypt_pkcs8(b"pw").is_ok());
        assert!(parsed.decrypt_pkcs8(b"wrong").is_err());
    }
}
