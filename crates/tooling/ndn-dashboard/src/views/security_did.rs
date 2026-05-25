//! §4.7 DID lens — identity-level framing over the packet-level §4.1 view.
//!
//! Three v1 surfaces, per (internal) §4.7:
//!   * `DidLensToggle` + `DidDocumentPanel` — toggle on the §4.1 identity
//!     inspector that flips its right pane between Keys&Certs and DID Document.
//!   * `ResolveAnyDidBox` — search input in the Security view header that
//!     accepts `did:ndn:/...` (or a raw NDN name) and fires the existing
//!     `SecurityValidateTrace` cert-chain trace, framed in DID terms.
//!   * `DidResolutionL2Frame` — wraps the §4.2 cert-layer failure diagnosis
//!     in DID-layer prose ("DID Document not fetchable" / "controller
//!     missing" / "signature invalid") with a fix action.
//!
//! No new `ndn-did` work is needed for v1; the dashboard renders a view
//! of the DID Document constructed from the keys+certs the mgmt verbs
//! already expose. The full `ndn_security::did::DidDocument` shape is
//! out-of-process — keeping a small view-only mirror here avoids pulling
//! the full crypto stack into the wasm bundle.

use crate::app::{AppCtx, DashCmd};
use crate::edu_gloss::EduGloss;
use crate::types::{FailureDiagnosis, SecurityKeyInfo, TrustValidationResult, TrustVerdict};
use crate::views::onboarding::encode_did_ndn;
use crate::views::security_did_ext::DidExtensionPanel;
use dioxus::prelude::*;
use std::collections::BTreeMap;

/// Decode a `did:ndn:` DID into the underlying NDN name. Inverse of
/// [`encode_did_ndn`]. Returns `None` when the input lacks the
/// `did:ndn:` scheme prefix.
///
/// Accepts both percent-encoded suffixes (`did:ndn:%2Flab%2Falice`)
/// and raw NDN-name suffixes (`did:ndn:/lab/alice`); either form is
/// what operators paste in practice.
pub fn decode_did_ndn(did: &str) -> Option<String> {
    let suffix = did.strip_prefix("did:ndn:")?;
    Some(percent_decode(suffix))
}

/// Best-effort percent decoding restricted to the `%2F` → `/` case
/// produced by [`encode_did_ndn`]. Leaves other percent sequences
/// alone so a slightly-malformed paste still renders something
/// recognisable.
fn percent_decode(s: &str) -> String {
    s.replace("%2F", "/").replace("%2f", "/")
}

/// Parse what an operator typed into the resolve-DID box into the
/// NDN name to validate. Accepts:
///   * `did:ndn:/lab/alice` — preferred display form
///   * `did:ndn:%2Flab%2Falice` — percent-encoded form
///   * `/lab/alice` — raw NDN name (operator was thinking L1)
///
/// Returns `None` when the input doesn't yield an NDN name beginning
/// with `/`. The empty string is rejected. `did:key:` and other
/// methods are rejected with `None`; v1 only resolves `did:ndn`.
pub fn parse_resolve_input(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if let Some(name) = decode_did_ndn(trimmed) {
        name
    } else if trimmed.starts_with("/") {
        trimmed.to_owned()
    } else if trimmed.starts_with("did:") {
        // Some other DID method (did:key, did:web, …). v1 doesn't
        // resolve those; the caller renders an explanation.
        return None;
    } else {
        return None;
    };
    if candidate.starts_with('/') && candidate.len() > 1 {
        Some(candidate)
    } else {
        None
    }
}

/// Display-only mirror of the rendered fields of a W3C DID Document.
/// Constructed from the dashboard's `SecurityKeyInfo` list so the
/// inspector renders even when no live resolver call has happened.
/// The shape parallels `ndn_security::did::DidDocument` but omits
/// fields the dashboard cannot populate from mgmt-verb data (public
/// key bytes are not on the wire today; they are a small v1.5
/// extension to `security/identity-list`).
#[derive(Debug, Clone, PartialEq)]
pub struct DidDocumentView {
    pub id: String,
    pub verification_methods: Vec<DidVerificationMethodView>,
    pub controllers: Vec<String>,
    pub services: Vec<DidServiceView>,
    /// Extension fields beyond the W3C-canonical core. Each entry is
    /// rendered through the §4.8 `DidExtensionRegistry`; unregistered
    /// keys fall back to the "no renderer" affordance. Empty in v1
    /// because `security/identity-list` doesn't carry extension data
    /// yet — populates once a future mgmt verb surfaces full DID
    /// Documents.
    pub extensions: BTreeMap<String, serde_json::Value>,
    /// True when no public-key bytes are available yet — the panel
    /// renders a "verification methods carry no `publicKey*` material
    /// until a v1.5 wire extension lands" note in that case.
    pub publickey_unavailable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DidVerificationMethodView {
    pub id: String,
    pub key_id: String,
    /// Cert presence; mirrors `SecurityKeyInfo::has_cert`.
    pub has_cert: bool,
    /// Human label for the validity window (`"valid · 89d left"`,
    /// `"expired"`, `"permanent"`, …).
    pub validity_label: String,
    /// W3C-compliant `publicKeyMultibase` value (base64url-prefix `u`
    /// per multibase RFC) derived from the cert's `public_key`
    /// bytes. Empty when the wire didn't carry public-key bytes
    /// (cert absent, or pre-extension forwarder).
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DidServiceView {
    pub id: String,
    pub typ: String,
    pub endpoint: String,
}

/// Build the view-DidDocument for an identity from the dashboard's
/// existing per-identity key list. v1 surfaces only what the
/// `security/identity-list` mgmt verb returns — keys+cert presence+
/// validity — plus the controller derivation from the NDN name's
/// parent prefix (controller of `did:ndn:/lab/alice` is
/// `did:ndn:/lab`, per §4.7.1's example).
pub fn did_doc_view_for_identity(identity_name: &str, keys: &[SecurityKeyInfo]) -> DidDocumentView {
    let did = format!("did:ndn:{}", encode_did_ndn(identity_name));
    let vms: Vec<DidVerificationMethodView> = keys
        .iter()
        .map(|k| DidVerificationMethodView {
            id: format!("{did}#{kid}", kid = k.key_id()),
            key_id: k.key_id().to_owned(),
            has_cert: k.has_cert,
            validity_label: validity_label(k),
            public_key_multibase: to_multibase_b64(&k.public_key_b64),
        })
        .collect();
    // The "no publicKey bytes yet" caveat fires when at least one
    // verification method has a cert but the wire didn't carry
    // bytes — distinguishes "this forwarder predates the wire
    // extension" from "this identity legitimately has no certs."
    let publickey_unavailable = vms
        .iter()
        .any(|vm| vm.has_cert && vm.public_key_multibase.is_empty());
    let controllers = parent_controllers(identity_name);
    DidDocumentView {
        id: did,
        verification_methods: vms,
        controllers,
        services: Vec::new(),
        extensions: BTreeMap::new(),
        publickey_unavailable,
    }
}

/// Convert a base64url-no-pad string (as emitted by the mgmt wire's
/// `public_key=` field) into a W3C-compliant `publicKeyMultibase`
/// value. The multibase prefix `u` denotes base64url-no-pad per
/// the multibase RFC; the dashboard renders the result inside the
/// DID Document panel verbatim. Empty input → empty output (the
/// caller treats absence as "no public-key bytes available").
fn to_multibase_b64(b64: &str) -> String {
    if b64.is_empty() {
        return String::new();
    }
    format!("u{b64}")
}

fn validity_label(k: &SecurityKeyInfo) -> String {
    let (_, label) = k.expiry_badge();
    label
}

/// Controllers derived from the NDN name's parent prefix. `/lab/alice`
/// → `["did:ndn:/lab"]`. Top-level names (e.g. `/lab`) return an
/// empty list — the subject is its own controller in that case (per
/// W3C DID Core §5.1.2's "absent controller" rule).
fn parent_controllers(identity_name: &str) -> Vec<String> {
    let trimmed = identity_name.trim_end_matches('/');
    let Some(slash) = trimmed.rfind('/') else {
        return Vec::new();
    };
    if slash == 0 {
        return Vec::new();
    }
    let parent = &trimmed[..slash];
    vec![format!("did:ndn:{}", encode_did_ndn(parent))]
}

/// Translate a §4.2 cert-layer `FailureDiagnosis` into DID-layer
/// prose. The translation is best-effort and degrades to a generic
/// "DID resolution failed" line when the cert-layer `kind` field
/// doesn't have a known mapping. The translation is intentionally
/// narrow — every branch documents WHY the L2 framing is what it is.
pub fn did_layer_failure_text(diagnosis: &FailureDiagnosis) -> (&'static str, String) {
    let (l2_kind, hint) = match diagnosis.kind.as_str() {
        // Cert chain didn't reach an installed anchor — the DID
        // Document fetch's verification step failed.
        "NoTrustAnchor" | "TrustAnchorMissing" => (
            "Controller missing",
            "Resolved DID Document was signed by a cert whose chain doesn't reach any installed trust anchor — the DID's controller chain is broken.".to_owned(),
        ),
        // KeyLocator → cert not retrievable. The L1 failure says
        // the cert isn't on the network; at L2 the DID Document is
        // not fetchable.
        "CertNotFetchable" | "KeyLocatorUnreachable" | "CertFetchTimeout" => (
            "DID Document not fetchable",
            "The DID's verification method points at a cert that couldn't be retrieved over NDN. The DID Document cannot be resolved until the cert publishes.".to_owned(),
        ),
        // Signature didn't verify — the verification method's
        // claimed key didn't actually sign the Data.
        "SignatureInvalid" | "BadSignature" => (
            "Signature invalid",
            "The DID Document was retrieved, but its signature didn't verify against the verification method it points at — DID has been tampered with or you're talking to a different DID with a name collision.".to_owned(),
        ),
        // Schema rule violated the cert chain — the DID's
        // verification relationships don't match the trust schema.
        "SchemaViolation" | "SchemaRuleMismatch" => (
            "Verification relationship rejected",
            "The DID Document's verification relationship doesn't satisfy the trust schema's rule for this namespace.".to_owned(),
        ),
        // Cert's validity window has elapsed.
        "CertExpired" | "Expired" => (
            "Verification method expired",
            "The DID's active verification method has expired. The DID still exists, but no live key can sign as it until rotation publishes a new cert.".to_owned(),
        ),
        // Revocation indicator surfaced.
        "Revoked" | "RevocationIndicatorSet" => (
            "DID revoked",
            "A revocation indicator is set for this DID. The subject explicitly disowned this DID Document.".to_owned(),
        ),
        _ => (
            "DID resolution failed",
            format!("Cert-layer diagnosis: {} ({})", diagnosis.kind, diagnosis.hint),
        ),
    };
    (l2_kind, hint)
}

/// Enum-as-segmented-toggle state for `IdentityInspector`'s right pane.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IdentityInspectorLens {
    KeysCerts,
    DidDocument,
}

#[component]
pub fn DidLensToggle(lens: Signal<IdentityInspectorLens>) -> Element {
    let mut lens = lens;
    let active = *lens.read();
    let btn = |label: &'static str, target: IdentityInspectorLens| {
        let is_on = active == target;
        let cls = if is_on {
            "btn btn-primary btn-sm"
        } else {
            "btn btn-secondary btn-sm"
        };
        rsx! {
            button {
                class: "{cls}",
                style: "padding:3px 10px;font-size:11px;",
                onclick: move |_| lens.set(target),
                "{label}"
            }
        }
    };
    rsx! {
        div {
            style: "display:inline-flex;gap:4px;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:2px;",
            { btn("Keys & Certs", IdentityInspectorLens::KeysCerts) }
            { btn("DID Document", IdentityInspectorLens::DidDocument) }
        }
    }
}

#[component]
pub fn DidDocumentPanel(doc: DidDocumentView) -> Element {
    rsx! {
        div { style: "margin-top:12px;",
            // DID id row
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:12px;",
                div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                    "DID"
                }
                div { class: "mono", style: "font-size:12px;color:var(--purple);word-break:break-all;",
                    "{doc.id}"
                }
            }

            // Verification methods
            div { style: "margin-bottom:12px;",
                div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    EduGloss { term: "Verification method" }
                    span { style: "color:var(--text-muted);margin-left:6px;",
                        "{doc.verification_methods.len()}"
                    }
                }
                if doc.verification_methods.is_empty() {
                    div { class: "empty", style: "font-size:11px;padding:8px;",
                        "No verification methods — this identity has no keys."
                    }
                } else {
                    for vm in doc.verification_methods.iter() {
                        VerificationMethodRow { vm: vm.clone() }
                    }
                }
                if doc.publickey_unavailable && !doc.verification_methods.is_empty() {
                    div {
                        style: "font-size:10px;color:var(--text-muted);font-style:italic;margin-top:6px;padding:4px 8px;background:var(--surface);border:1px dashed var(--border);border-radius:4px;",
                        "Note: ", span { class: "mono", "publicKeyMultibase" }, " bytes are not on the wire yet. The verification method id resolves to the cert at the matching name."
                    }
                }
            }

            // Controllers
            div { style: "margin-bottom:12px;",
                div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    EduGloss { term: "Controller" }
                    span { style: "color:var(--text-muted);margin-left:6px;",
                        "{doc.controllers.len()}"
                    }
                }
                if doc.controllers.is_empty() {
                    div { class: "empty", style: "font-size:11px;padding:8px;",
                        "Subject is its own controller (root namespace)."
                    }
                } else {
                    for c in doc.controllers.iter() {
                        div { class: "mono", style: "font-size:11px;color:var(--purple);padding:4px 0;word-break:break-all;",
                            "{c}"
                        }
                    }
                }
            }

            // Service endpoints
            div { style: "margin-bottom:12px;",
                div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    EduGloss { term: "Service endpoint" }
                    span { style: "color:var(--text-muted);margin-left:6px;",
                        "{doc.services.len()}"
                    }
                }
                if doc.services.is_empty() {
                    div { class: "empty", style: "font-size:11px;padding:8px;",
                        "No service endpoints declared. Extension renderers (§4.8) populate this when registered."
                    }
                } else {
                    for s in doc.services.iter() {
                        div { style: "padding:4px 0;font-size:11px;",
                            span { class: "mono", style: "color:var(--text);", "{s.id}" }
                            span { style: "color:var(--text-muted);margin:0 6px;", "·" }
                            span { class: "mono", style: "color:var(--accent);", "{s.typ}" }
                            div { class: "mono", style: "color:var(--text-muted);font-size:10px;word-break:break-all;margin-top:2px;",
                                "→ {s.endpoint}"
                            }
                        }
                    }
                }
            }

            // §4.8 extension fields — renders via the global
            // `DidExtensionRegistry`; unknown keys fall back to the
            // "no renderer for X" affordance. Renders nothing when
            // the document carries no extensions (the v1 default).
            DidExtensionPanel { extensions: doc.extensions.clone() }
        }
    }
}

#[component]
fn VerificationMethodRow(vm: DidVerificationMethodView) -> Element {
    let badge_class = if vm.has_cert {
        "badge badge-green"
    } else {
        "badge badge-gray"
    };
    let badge_label = if vm.has_cert { "cert" } else { "no cert" };
    rsx! {
        div { style: "display:flex;flex-direction:column;gap:6px;padding:6px 8px;border:1px solid var(--border-subtle);border-radius:4px;margin-bottom:4px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;gap:8px;",
                div { style: "flex:1;min-width:0;",
                    div { class: "mono", style: "font-size:11px;color:var(--text);word-break:break-all;",
                        "{vm.id}"
                    }
                    div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                        "KEY/", span { class: "mono", "{vm.key_id}" },
                        span { style: "margin-left:8px;", "{vm.validity_label}" }
                    }
                }
                span { class: "{badge_class}", "{badge_label}" }
            }
            if !vm.public_key_multibase.is_empty() {
                div { style: "font-size:10px;color:var(--text-muted);",
                    span { class: "mono", "publicKeyMultibase: " }
                    span { class: "mono",
                           style: "color:var(--text);word-break:break-all;",
                           "{vm.public_key_multibase}" }
                }
            }
        }
    }
}

#[component]
pub fn ResolveAnyDidBox() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut input: Signal<String> = use_signal(String::new);
    let mut parse_error: Signal<Option<&'static str>> = use_signal(|| None);

    let mut do_submit = move || {
        let raw = input.read().clone();
        match parse_resolve_input(&raw) {
            Some(name) => {
                parse_error.set(None);
                ctx.cmd.send(DashCmd::SecurityValidateTrace(name));
                let mut open = ctx.trust_inspector_open;
                open.set(true);
            }
            None if raw.trim().starts_with("did:") => {
                parse_error.set(Some(
                    "Only did:ndn is resolvable in v1. did:key / did:web / etc. ship in v1.5.",
                ));
            }
            None => {
                parse_error.set(Some("Type a did:ndn:/... URI or a raw /ndn/name."));
            }
        }
    };

    rsx! {
        div { style: "display:flex;flex-direction:column;gap:4px;margin-bottom:14px;",
            div { style: "display:flex;gap:6px;align-items:center;",
                span { style: "font-size:11px;color:var(--text-muted);",
                    EduGloss { term: "Resolve DID" }
                }
                input {
                    style: "flex:1;font-family:var(--font-mono);font-size:11px;padding:5px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);",
                    placeholder: "did:ndn:/lab/alice",
                    value: "{input}",
                    oninput: move |e| input.set(e.value()),
                    onkeydown: move |e| {
                        if e.key() == Key::Enter {
                            do_submit();
                        }
                    },
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    style: "padding:5px 10px;font-size:11px;",
                    onclick: move |_| do_submit(),
                    "Resolve →"
                }
            }
            if let Some(err) = *parse_error.read() {
                div { style: "font-size:10px;color:var(--yellow,#f5c518);padding-left:8px;",
                    "{err}"
                }
            }
        }
    }
}

/// Wraps the §4.2 TrustPathInspector's cert-layer failure with a
/// DID-layer headline. Renders only when the validation result is
/// `Invalid` AND a `failure_diagnosis` is present. Pure render —
/// reads the same `TrustValidationResult` the cert-layer panel does;
/// no extra wire calls.
#[component]
pub fn DidResolutionL2Frame(result: TrustValidationResult) -> Element {
    if matches!(result.verdict, TrustVerdict::Valid) {
        return rsx! {};
    }
    let Some(diag) = result.failure_diagnosis.as_ref() else {
        return rsx! {};
    };
    let (l2_kind, l2_hint) = did_layer_failure_text(diag);
    rsx! {
        div { style: "border:1px solid var(--purple,#a371f7)55;background:#1a002a22;border-radius:6px;padding:10px 12px;margin-bottom:14px;",
            div { style: "font-size:10px;color:var(--purple);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                "DID layer"
            }
            div { style: "font-size:12px;font-weight:600;color:var(--purple);margin-bottom:4px;",
                "{l2_kind}"
            }
            div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;",
                "{l2_hint}"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FailureDiagnosis;

    #[test]
    fn decode_did_ndn_strips_scheme_and_decodes_percent_slash() {
        assert_eq!(
            decode_did_ndn("did:ndn:%2Flab%2Falice").as_deref(),
            Some("/lab/alice")
        );
        assert_eq!(
            decode_did_ndn("did:ndn:/lab/alice").as_deref(),
            Some("/lab/alice")
        );
        assert_eq!(decode_did_ndn("did:key:zABC").as_deref(), None);
        assert_eq!(decode_did_ndn("/lab/alice").as_deref(), None);
    }

    #[test]
    fn decode_did_ndn_round_trips_encode() {
        let name = "/lab/alice";
        let did = format!("did:ndn:{}", encode_did_ndn(name));
        assert_eq!(decode_did_ndn(&did).as_deref(), Some(name));
    }

    #[test]
    fn parse_resolve_input_accepts_did_and_raw_name() {
        assert_eq!(
            parse_resolve_input("did:ndn:/lab/alice"),
            Some("/lab/alice".to_owned())
        );
        assert_eq!(
            parse_resolve_input("did:ndn:%2Flab%2Falice"),
            Some("/lab/alice".to_owned())
        );
        assert_eq!(
            parse_resolve_input("/lab/alice"),
            Some("/lab/alice".to_owned())
        );
        assert_eq!(
            parse_resolve_input("  /lab/alice  "),
            Some("/lab/alice".to_owned())
        );
    }

    #[test]
    fn parse_resolve_input_rejects_empty_and_unsupported_methods() {
        assert_eq!(parse_resolve_input(""), None);
        assert_eq!(parse_resolve_input("   "), None);
        assert_eq!(parse_resolve_input("did:key:zABC"), None);
        assert_eq!(parse_resolve_input("did:web:example.org"), None);
        assert_eq!(parse_resolve_input("lab/alice"), None);
        assert_eq!(parse_resolve_input("/"), None);
    }

    fn keyinfo(name: &str, has_cert: bool, valid_until: &str) -> SecurityKeyInfo {
        SecurityKeyInfo {
            name: name.to_owned(),
            has_cert,
            valid_until: valid_until.to_owned(),
            public_key_b64: String::new(),
        }
    }

    #[test]
    fn did_doc_view_for_identity_lists_keys_as_verification_methods() {
        let keys = vec![
            keyinfo("/lab/alice/KEY/k1", true, "never"),
            keyinfo("/lab/alice/KEY/k2", false, "-"),
        ];
        let doc = did_doc_view_for_identity("/lab/alice", &keys);
        assert_eq!(doc.id, "did:ndn:%2Flab%2Falice");
        assert_eq!(doc.verification_methods.len(), 2);
        assert_eq!(doc.verification_methods[0].id, "did:ndn:%2Flab%2Falice#k1");
        assert_eq!(doc.verification_methods[0].key_id, "k1");
        assert!(doc.verification_methods[0].has_cert);
        assert!(!doc.verification_methods[1].has_cert);
        assert!(doc.publickey_unavailable);
        assert!(
            doc.extensions.is_empty(),
            "v1 view-DidDocument carries no extensions until a mgmt verb surfaces them"
        );
    }

    #[test]
    fn did_doc_view_emits_multibase_when_wire_carries_public_key() {
        let mut k1 = keyinfo("/lab/alice/KEY/k1", true, "never");
        k1.public_key_b64 = "ABCDef-_123".to_owned(); // base64url-no-pad sample
        let doc = did_doc_view_for_identity("/lab/alice", &[k1]);
        assert_eq!(
            doc.verification_methods[0].public_key_multibase,
            "uABCDef-_123"
        );
        assert!(
            !doc.publickey_unavailable,
            "caveat must suppress once at least one cert carries bytes"
        );
    }

    #[test]
    fn did_doc_view_caveat_fires_only_when_certed_key_lacks_bytes() {
        // Mixed: one certed key with bytes, one certed key without — the
        // panel still warns because at least one identity is unbacked.
        let mut k1 = keyinfo("/lab/alice/KEY/k1", true, "never");
        k1.public_key_b64 = "QQ".to_owned();
        let k2 = keyinfo("/lab/alice/KEY/k2", true, "never");
        let doc = did_doc_view_for_identity("/lab/alice", &[k1, k2]);
        assert!(doc.publickey_unavailable);
        // No certs at all → no caveat (legit "this identity has no keys" state)
        let kless = keyinfo("/lab/alice/KEY/k3", false, "-");
        let doc2 = did_doc_view_for_identity("/lab/alice", &[kless]);
        assert!(!doc2.publickey_unavailable);
    }

    #[test]
    fn to_multibase_b64_prefixes_u_or_returns_empty() {
        assert_eq!(to_multibase_b64(""), "");
        assert_eq!(to_multibase_b64("xyz"), "uxyz");
    }

    #[test]
    fn did_doc_view_derives_parent_as_controller() {
        let keys = vec![keyinfo("/lab/alice/KEY/k1", true, "never")];
        let doc = did_doc_view_for_identity("/lab/alice", &keys);
        assert_eq!(doc.controllers, vec!["did:ndn:%2Flab".to_owned()]);

        let root_doc = did_doc_view_for_identity("/lab", &[]);
        assert!(root_doc.controllers.is_empty());

        let deep = did_doc_view_for_identity("/lab/dept/alice", &[]);
        assert_eq!(deep.controllers, vec!["did:ndn:%2Flab%2Fdept".to_owned()]);
    }

    #[test]
    fn did_layer_failure_text_translates_known_kinds() {
        let cases = [
            ("NoTrustAnchor", "Controller missing"),
            ("CertNotFetchable", "DID Document not fetchable"),
            ("KeyLocatorUnreachable", "DID Document not fetchable"),
            ("SignatureInvalid", "Signature invalid"),
            ("SchemaViolation", "Verification relationship rejected"),
            ("CertExpired", "Verification method expired"),
            ("Revoked", "DID revoked"),
        ];
        for (cert_kind, expected_l2) in cases {
            let diag = FailureDiagnosis {
                kind: cert_kind.to_owned(),
                hint: String::new(),
            };
            let (l2_kind, _) = did_layer_failure_text(&diag);
            assert_eq!(l2_kind, expected_l2, "kind {cert_kind} mapped wrong");
        }
    }

    #[test]
    fn did_layer_failure_text_falls_back_for_unknown_kinds() {
        let diag = FailureDiagnosis {
            kind: "FutureDiagnosisKind".to_owned(),
            hint: "details here".to_owned(),
        };
        let (l2_kind, hint) = did_layer_failure_text(&diag);
        assert_eq!(l2_kind, "DID resolution failed");
        assert!(hint.contains("FutureDiagnosisKind"));
        assert!(hint.contains("details here"));
    }
}
