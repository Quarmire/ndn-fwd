//! Pairing — bind a phone (or any key-holding device) as this console's
//! **remote signer**. The phone keeps its key; the dashboard only ever receives
//! individual signatures, on demand, within the scope and time window the
//! operator consents to on the phone. Nothing is typed: the phone's camera
//! scans the request, and its grant comes back over the shared forwarder.
//!
//! The two halves mirror the `capability` kind of the shared `ndn-trust://`
//! envelope (see `ndn-trust-envelope`):
//!
//!   1. **Request** — the dashboard shows a `Capability{Request}` QR naming the
//!      scope it wants and for how long. The phone scans it (proven against a
//!      real camera) and the operator approves a scope on the device.
//!   2. **Grant** — the phone returns a `Capability{Grant}` carrying its
//!      operator public key, plus its operator certificate. The dashboard
//!      provisions a remote signer from those, and from then on every
//!      `/localhost/nfd/…` command is signed by the phone over NDN.
//!
//! Phase A wires the request QR and the live grant preview; the signing channel
//! (an NDN consumer to the phone's `…/signer` responder) and the provision step
//! land in the following slices.

use dioxus::prelude::*;
use sha2::{Digest, Sha256};

use ndn_trust_envelope::{CapDirection, Capability, TrustEnvelope};

/// Build a fresh `Capability{Request}` URI for the given scope + lifetime.
/// A new random nonce binds each request (anti-replay).
fn build_request_uri(namespace: &str, ttl_secs: u64) -> Result<String, String> {
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("nonce: {e}"))?;
    let env = TrustEnvelope::Capability(Capability {
        direction: CapDirection::Request,
        namespace: namespace.trim().to_string(),
        scope_patterns: Vec::new(),
        ttl_secs,
        nonce: bytes::Bytes::copy_from_slice(&nonce),
        grant: None,
    });
    Ok(env.to_uri())
}

/// Render a `ndn-trust://` URI as an inline SVG QR (pure Rust, no JS).
fn render_qr_svg(uri: &str) -> Option<String> {
    use qrcode::QrCode;
    use qrcode::render::svg;
    let code = QrCode::new(uri.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .build(),
    )
}

/// What a pasted `Capability{Grant}` resolves to, for the live preview.
struct GrantPreview {
    /// The operator identity carried in the certificate (e.g. `/demo/phone/dev1`).
    identity: String,
    namespace: String,
    ttl_secs: u64,
    /// SHA-256 fingerprint of the operator public key (first 8 bytes, hex).
    key_fp: String,
}

/// Parse + validate a pasted grant URI into its preview, or an error string.
/// The grant carries the operator's certificate (name + public key + algorithm).
fn parse_grant(uri: &str) -> Result<GrantPreview, String> {
    let (namespace, ttl_secs, cert_wire) =
        match TrustEnvelope::from_uri(uri.trim()).map_err(|e| format!("{e}"))? {
            TrustEnvelope::Capability(Capability {
                direction: CapDirection::Grant,
                namespace,
                ttl_secs,
                grant: Some(cert),
                ..
            }) => (namespace, ttl_secs, cert),
            TrustEnvelope::Capability(Capability {
                direction: CapDirection::Grant,
                grant: None,
                ..
            }) => return Err("grant carries no operator certificate".into()),
            TrustEnvelope::Capability(Capability {
                direction: CapDirection::Request,
                ..
            }) => return Err("that's a request, not a grant — scan it with the phone instead".into()),
            _ => return Err("not a capability grant".into()),
        };
    let cert = ndn_packet::Data::decode(cert_wire).map_err(|e| format!("certificate: {e:?}"))?;
    let identity = cert.name.to_string();
    let pk = cert.content().ok_or("certificate has no public key")?;
    let digest = Sha256::digest(pk);
    let key_fp = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    Ok(GrantPreview {
        identity,
        namespace,
        ttl_secs,
        key_fp,
    })
}

#[component]
pub fn Pairing() -> Element {
    let mut namespace = use_signal(|| "/localhost/nfd/rib".to_string());
    let mut ttl_mins = use_signal(|| 15u64);
    let mut grant_input = use_signal(String::new);
    // Result of the last "Pair" attempt: Ok(identity) once provisioned.
    let mut pair_status = use_signal(|| Option::<Result<String, String>>::None);

    // The request URI is regenerated only when the scope or lifetime changes,
    // so the QR stays still long enough for the phone to lock onto it.
    let request = use_memo(move || build_request_uri(&namespace.read(), *ttl_mins.read() * 60));
    let request_uri = request.read().clone();
    let qr = request_uri.as_ref().ok().and_then(|u| render_qr_svg(u));

    let grant_raw = grant_input.read().clone();
    let grant_trimmed = grant_raw.trim();
    let grant_preview = (!grant_trimmed.is_empty()).then(|| parse_grant(grant_trimmed));

    let op_identity = crate::operator_keyring::active_identity_name();

    rsx! {
        div { class: "section",
            div { class: "section-title", "Pairing" }
            p { class: "muted", style: "margin:0;font-size:13px;",
                "Sign this console's commands with a key that never leaves your phone. "
                "The phone scans the request below, you approve a scope on the device, "
                "and its grant comes back here — no key, password, or certificate is typed."
            }
        }

        // ── 1. Request: the QR the phone scans ─────────────────────────────
        div { class: "section",
            div { class: "section-title", "1 · Request signing from a phone" }
            div { style: "display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start;",
                div { style: "flex:0 0 auto;",
                    if let Some(svg) = qr.as_ref() {
                        div {
                            style: "background:#fff;padding:12px;border:1px solid var(--border);width:max-content;",
                            dangerous_inner_html: "{svg}",
                        }
                    } else {
                        div { class: "readonly-banner",
                            span { class: "readonly-banner-icon", "⚠" }
                            span {
                                if let Err(e) = request_uri.as_ref() {
                                    "Couldn't build the request: {e}"
                                } else {
                                    "Couldn't render the QR."
                                }
                            }
                        }
                    }
                }
                div { style: "flex:1 1 260px;min-width:260px;",
                    dl { class: "inspector-kv",
                        dt { "Scope" }
                        dd {
                            input {
                                style: "width:100%;",
                                value: "{namespace}",
                                oninput: move |e| namespace.set(e.value()),
                            }
                        }
                        dt { "Window (minutes)" }
                        dd {
                            input {
                                r#type: "number",
                                style: "width:96px;",
                                min: "1",
                                value: "{ttl_mins}",
                                oninput: move |e| {
                                    if let Ok(v) = e.value().parse::<u64>() {
                                        if v >= 1 { ttl_mins.set(v); }
                                    }
                                },
                            }
                        }
                    }
                    p { class: "muted", style: "margin:10px 0 0;font-size:12px;",
                        "On the phone: tap Scan, point it at this code, and approve the scope. "
                        "The phone auto-signs in-scope commands for the window; sensitive "
                        "commands (security/CA) always re-prompt."
                    }
                }
            }
        }

        // ── 2. Grant: paste / receive the phone's reply ────────────────────
        div { class: "section",
            div { class: "section-title", "2 · Complete pairing" }
            p { class: "muted", style: "margin:0 0 8px;font-size:12px;",
                "Paste the grant the phone shows after you approve "
                "(an "
                code { "ndn-trust://capability/…" }
                " string)."
            }
            textarea {
                style: "width:100%;height:72px;font-family:var(--mono);font-size:11px;",
                placeholder: "ndn-trust://capability/…",
                value: "{grant_raw}",
                oninput: move |e| grant_input.set(e.value()),
            }
            match grant_preview {
                Some(Ok(p)) => rsx! {
                    dl { class: "inspector-kv", style: "margin-top:10px;",
                        dt { "Operator" }
                        dd { style: "font-family:var(--mono);font-size:11px;", "{p.identity}" }
                        dt { "Granted scope" }
                        dd { "{p.namespace}" }
                        dt { "Window" }
                        dd { "{p.ttl_secs / 60} min" }
                        dt { "Operator key" }
                        dd {
                            span { class: "badge badge-green", style: "font-size:9px;", "valid" }
                            span { style: "margin-left:8px;font-family:var(--mono);font-size:11px;",
                                "{p.key_fp}…"
                            }
                        }
                    }
                    div { style: "margin-top:12px;",
                        button {
                            class: "btn btn-primary",
                            onclick: move |_| {
                                let uri = grant_input.read().trim().to_string();
                                let socket = crate::forwarder_profile::selected().1;
                                let outcome = crate::remote_signer::pair_from_grant(&uri, socket);
                                if outcome.is_ok() {
                                    crate::app_shared::bump_keyring_gen();
                                }
                                pair_status.set(Some(outcome));
                            },
                            "Pair this console"
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "readonly-banner", style: "margin-top:10px;",
                        span { class: "readonly-banner-icon", "⚠" }
                        span { "Not a usable grant: {e}" }
                    }
                },
                None => rsx! {},
            }

            match pair_status.read().as_ref() {
                Some(Ok(identity)) => rsx! {
                    div { class: "readonly-banner", style: "margin-top:12px;border-color:var(--green);",
                        span { class: "readonly-banner-icon", "✓" }
                        span {
                            "Paired. This console now signs its commands with "
                            b { "{identity}" }
                            " on the phone — within the granted scope and window."
                        }
                    }
                },
                Some(Err(e)) => rsx! {
                    div { class: "readonly-banner", style: "margin-top:12px;",
                        span { class: "readonly-banner-icon", "⚠" }
                        span { "Pairing failed: {e}" }
                    }
                },
                None => rsx! {},
            }
        }

        if op_identity.is_none() {
            div { class: "section",
                div { class: "readonly-banner",
                    span { class: "readonly-banner-icon", "⚠" }
                    span {
                        "This console has no operator identity yet. Pairing makes the phone the "
                        "signer regardless, but you can also provision a local key under Security."
                    }
                }
            }
        }
    }
}
