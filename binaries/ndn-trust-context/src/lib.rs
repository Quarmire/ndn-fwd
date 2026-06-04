//! Author a [`SignedTrustContext`] and pack it as a QR/NFC **join payload** —
//! the bytes a participant scans to adopt a context (`NdnEngine::join_context`
//! over FFI, or `Keyring::adopt` natively).
//!
//! A context binds a `namespace` to a set of trust anchors and a schema
//! (LVS or the built-in hierarchical/accept-all defaults), plus optional CA
//! endpoints and revocations. [`build_context`] assembles one from a
//! [`ContextSpec`]; [`encode_envelope`] / [`parse_envelope`] move it as a
//! single self-describing text string that carries the version out-of-band
//! (the value `decode_content` needs).

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, SchemaBlob, SignedTrustContext};

/// What to put in a trust context. Anchors are raw certificate Data wires;
/// `schema_lvs` is a python-lvs-compiled binary schema (validated on build).
#[derive(Debug, Clone)]
pub struct ContextSpec {
    pub namespace: Name,
    pub version: u64,
    /// `true` = any cert under an adopted anchor may sign any name in the
    /// namespace (`accept_all`); `false` = the hierarchical floor.
    pub accept_all: bool,
    pub anchor_wires: Vec<Vec<u8>>,
    pub schema_lvs: Option<Vec<u8>>,
    pub ca_endpoints: Vec<Name>,
    pub revocations: Vec<Name>,
}

impl Default for ContextSpec {
    fn default() -> Self {
        Self {
            namespace: Name::root(),
            version: 0,
            accept_all: false,
            anchor_wires: Vec::new(),
            schema_lvs: None,
            ca_endpoints: Vec::new(),
            revocations: Vec::new(),
        }
    }
}

/// Assemble a [`SignedTrustContext`] from a [`ContextSpec`]. Fails on an
/// unparseable anchor cert or an invalid LVS schema.
pub fn build_context(spec: &ContextSpec) -> Result<SignedTrustContext> {
    let mut ctx = if spec.accept_all {
        SignedTrustContext::accept_all(spec.namespace.clone())
    } else {
        SignedTrustContext::hierarchical(spec.namespace.clone())
    };
    ctx = ctx.with_version(spec.version);
    for ca in &spec.ca_endpoints {
        ctx = ctx.with_ca_endpoint(ca.clone());
    }
    for rev in &spec.revocations {
        ctx = ctx.with_revocation(rev.clone());
    }
    if let Some(lvs) = &spec.schema_lvs {
        ctx = ctx
            .with_schema_blob(SchemaBlob::lvs(lvs.clone()))
            .map_err(|e| anyhow!("invalid LVS schema: {e}"))?;
    }
    for wire in &spec.anchor_wires {
        let data = Data::decode(bytes::Bytes::copy_from_slice(wire))
            .map_err(|e| anyhow!("anchor is not a decodable Data packet: {e:?}"))?;
        let cert =
            Certificate::decode(&data).map_err(|e| anyhow!("anchor is not a certificate: {e}"))?;
        ctx.add_anchor(cert);
    }
    Ok(ctx)
}

/// The join-payload envelope tag: a versioned text format so a scanner can
/// recognise and evolve it. `ndn-ctx:1:<context-version>:<base64url(content)>`.
const ENVELOPE_TAG: &str = "ndn-ctx:1";

/// Pack a context's `encode_content()` bytes + its version into a scannable
/// text string.
pub fn encode_envelope(version: u64, content: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(content);
    format!("{ENVELOPE_TAG}:{version}:{b64}")
}

/// Parse an envelope back into `(version, content)` — exactly the two arguments
/// `SignedTrustContext::decode_content` / `NdnEngine::join_context` take.
pub fn parse_envelope(s: &str) -> Result<(u64, Vec<u8>)> {
    let rest = s
        .trim()
        .strip_prefix(&format!("{ENVELOPE_TAG}:"))
        .ok_or_else(|| anyhow!("not an `{ENVELOPE_TAG}` join payload"))?;
    let (ver, b64) = rest
        .split_once(':')
        .ok_or_else(|| anyhow!("missing version/content separator"))?;
    let version: u64 = ver.parse().context("context version")?;
    let content = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim())
        .context("base64 content")?;
    Ok((version, content))
}

/// One-shot: build the context and return its scannable join payload.
pub fn build_join_payload(spec: &ContextSpec) -> Result<String> {
    let ctx = build_context(spec)?;
    Ok(encode_envelope(spec.version, &ctx.encode_content()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_context_round_trips_to_a_join_payload() {
        let spec = ContextSpec {
            namespace: "/home/bob".parse().unwrap(),
            version: 3,
            accept_all: false,
            anchor_wires: vec![],
            schema_lvs: None,
            ca_endpoints: vec!["/home/bob/CA".parse().unwrap()],
            revocations: vec!["/home/bob/KEY/old".parse().unwrap()],
        };

        // Author → envelope → parse (what a scanner does) → decode_content
        // (what join_context does).
        let payload = build_join_payload(&spec).unwrap();
        let (version, content) = parse_envelope(&payload).unwrap();
        assert_eq!(version, 3);

        let adopted = SignedTrustContext::decode_content(&content, version).unwrap();
        assert_eq!(adopted.namespace().to_string(), "/home/bob");
        assert_eq!(adopted.version(), 3);
        assert!(adopted.enforces_hierarchy());
        assert!(adopted.is_revoked(&"/home/bob/KEY/old".parse().unwrap()));
        assert_eq!(adopted.ca_endpoints().len(), 1);
    }

    #[test]
    fn adoption_re_imposes_the_hierarchy_floor() {
        // Authoring `accept_all` does not let an adopter run with the floor
        // off: decode_content always re-imposes the hierarchy floor (the N1
        // safety default), so a scanned context can't weaken it.
        let spec = ContextSpec {
            namespace: "/work/acme".parse().unwrap(),
            version: 1,
            accept_all: true,
            ..Default::default()
        };
        let (v, content) = parse_envelope(&build_join_payload(&spec).unwrap()).unwrap();
        let adopted = SignedTrustContext::decode_content(&content, v).unwrap();
        assert!(
            adopted.enforces_hierarchy(),
            "adoption must re-impose the hierarchy floor"
        );
    }

    #[test]
    fn malformed_envelope_is_rejected() {
        assert!(parse_envelope("not-a-context").is_err());
        assert!(parse_envelope("ndn-ctx:1:notanumber:xxx").is_err());
    }

    #[test]
    fn malformed_anchor_is_rejected() {
        let spec = ContextSpec {
            namespace: "/x".parse().unwrap(),
            anchor_wires: vec![vec![0xff, 0x00, 0x01]],
            ..Default::default()
        };
        assert!(build_context(&spec).is_err());
    }
}
