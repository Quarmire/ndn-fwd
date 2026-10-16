//! Author a [`SignedTrustContext`] and pack it as an `ndn-trust://anchor`
//! QR/NFC payload — what a participant scans to adopt a context
//! (`ndn-fwd adopt`, `NdnEngine::join_context` over FFI, or
//! `ndn_cert::adopt_anchor_envelope` natively).
//!
//! A context binds a `namespace` to a set of trust anchors and a schema
//! (LVS or the built-in hierarchical/accept-all defaults), plus optional CA
//! endpoints and revocations. [`build_context`] assembles one from a
//! [`ContextSpec`].
//!
//! - [`build_signed_anchor_envelope`] signs the context into its NDN Data with
//!   an anchor's key and pins that anchor's TOFU fingerprint — the form
//!   adopters verify and accept.
//! - [`build_anchor_envelope`] emits the **unsigned legacy** form (bare
//!   context content). Adopters refuse it by default (its schema could have
//!   been altered in transit); it exists only for tooling that cannot reach
//!   the anchor's signing key.

// Documentation ratchet: this crate's public API is fully documented; keep it so.
#![deny(missing_docs)]

use anyhow::{Result, anyhow};
use ndn_cert::{anchor_fingerprint, open_signed_context};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, SchemaBlob, SignedTrustContext, Signer};
use ndn_trust_envelope::TrustEnvelope;

/// What to put in a trust context. Anchors are raw certificate Data wires;
/// `schema_lvs` is a python-lvs-compiled binary schema (validated on build).
#[derive(Debug, Clone)]
pub struct ContextSpec {
    /// The name prefix this context governs; adopted anchors are trusted to
    /// sign names under it.
    pub namespace: Name,
    /// Monotonic context version — a higher version supersedes a lower one on
    /// re-adoption.
    pub version: u64,
    /// `true` = any cert under an adopted anchor may sign any name in the
    /// namespace (`accept_all`); `false` = the hierarchical floor.
    pub accept_all: bool,
    /// Trust anchors, each a raw certificate `Data` wire.
    pub anchor_wires: Vec<Vec<u8>>,
    /// Optional python-lvs-compiled binary schema (validated on build); when
    /// absent, the built-in hierarchical / accept-all default applies.
    pub schema_lvs: Option<Vec<u8>>,
    /// CA endpoints participants may enroll against under this context.
    pub ca_endpoints: Vec<Name>,
    /// Names of revoked certificates or keys to reject.
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

/// Build the context, sign it into Data with `signer` (whose key must be one
/// of the context's anchors), and wrap it as an inline anchor envelope pinning
/// that anchor's fingerprint (render with [`TrustEnvelope::to_uri`]).
pub fn build_signed_anchor_envelope(
    spec: &ContextSpec,
    signer: &dyn Signer,
) -> Result<TrustEnvelope> {
    let ctx = build_context(spec)?;
    let data = ctx
        .sign_into_data(signer)
        .map_err(|e| anyhow!("sign context: {e}"))?;
    // Self-check: the result must verify under one of its own anchors, which
    // also identifies the anchor to pin.
    let (_, anchor) = open_signed_context(&data).map_err(|e| {
        anyhow!(
            "signing key {} does not sign as one of the context's anchors: {e}",
            signer.key_name()
        )
    })?;
    Ok(TrustEnvelope::Anchor {
        namespace: Some(spec.namespace.to_string()),
        fingerprint: Some(anchor_fingerprint(&anchor)),
        version: Some(spec.version),
        context_data: Some(data.raw().clone()),
        context_content: None,
    })
}

/// **Unsigned legacy form.** Build the context and wrap its bare content as an
/// inline anchor envelope pinning the fingerprint of the context's first
/// anchor, when it has one. Nothing signs the content, so adopters refuse it
/// unless they explicitly opt in to unverified legacy adoption; prefer
/// [`build_signed_anchor_envelope`].
pub fn build_anchor_envelope(spec: &ContextSpec) -> Result<TrustEnvelope> {
    let ctx = build_context(spec)?;
    let fingerprint = ctx
        .anchors()
        .iter()
        .next()
        .map(|r| anchor_fingerprint(r.value()));
    Ok(TrustEnvelope::Anchor {
        namespace: Some(spec.namespace.to_string()),
        fingerprint,
        version: Some(spec.version),
        context_data: None,
        context_content: Some(ctx.encode_content()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Author → `ndn-trust://` URI → parse (what a scanner does), returning the
    /// `(version, content)` pair `decode_content` / `join_context` take.
    fn scan(spec: &ContextSpec) -> (u64, bytes::Bytes) {
        let uri = build_anchor_envelope(spec).unwrap().to_uri();
        assert!(uri.starts_with("ndn-trust://anchor/"));
        match TrustEnvelope::from_uri(&uri).unwrap() {
            TrustEnvelope::Anchor {
                version: Some(v),
                context_content: Some(c),
                ..
            } => (v, c),
            other => panic!("expected an inline anchor envelope, got {other:?}"),
        }
    }

    #[test]
    fn authored_context_round_trips_through_an_anchor_envelope() {
        let spec = ContextSpec {
            namespace: "/home/bob".parse().unwrap(),
            version: 3,
            accept_all: false,
            anchor_wires: vec![],
            schema_lvs: None,
            ca_endpoints: vec!["/home/bob/CA".parse().unwrap()],
            revocations: vec!["/home/bob/KEY/old".parse().unwrap()],
        };

        // Author → envelope → parse → decode_content (what join_context does).
        let (version, content) = scan(&spec);
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
        let (v, content) = scan(&spec);
        let adopted = SignedTrustContext::decode_content(&content, v).unwrap();
        assert!(
            adopted.enforces_hierarchy(),
            "adoption must re-impose the hierarchy floor"
        );
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

    /// Cross-impl interop substrate: a context's *wrapper* is an ndn-rs
    /// extension, but its **anchors** are plain NDN certificates — encoded as
    /// standard Data (0x06) packets, named per the
    /// `/<identity>/KEY/<keyid>/<issuerid>/<version>` convention
    /// (ndn-cxx `security/certificate.hpp`, lines ~37/151). A reference impl
    /// (ndn-cxx / ndnd) consumes them with ordinary cert-chain validation, so
    /// Data signed under a context's anchors validates cross-impl (the existing
    /// `testbed/tests/interop/fwd_cxx_*` already prove ndn-rs↔ndn-cxx Data).
    #[tokio::test]
    async fn context_anchors_survive_as_spec_compliant_certs() {
        use ndn_security::{Ed25519Signer, encode_cert_data};

        // A self-signed anchor certificate (standard NDN Certificate).
        let key_name: Name = "/home/bob/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[7u8; 32], key_name.clone());
        let pubkey = signer.public_key().unwrap();
        let cert_name: Name = "/home/bob/KEY/k0/self/v=1".parse().unwrap();
        let cert_wire = encode_cert_data(&cert_name, &pubkey, &signer, 0, u64::MAX)
            .await
            .expect("encode cert");

        // Author a context carrying it, then round-trip the anchor envelope.
        let spec = ContextSpec {
            namespace: "/home/bob".parse().unwrap(),
            version: 1,
            anchor_wires: vec![cert_wire.to_vec()],
            ..Default::default()
        };
        // The envelope pins that anchor's fingerprint for TOFU adoption.
        let TrustEnvelope::Anchor { fingerprint, .. } = build_anchor_envelope(&spec).unwrap()
        else {
            panic!("expected an anchor envelope");
        };
        assert!(fingerprint.is_some(), "an anchored context pins its root");

        let (v, content) = scan(&spec);
        // decode_content Data-decodes each anchor from the AnchorSet — i.e. the
        // anchors are on the wire as ordinary NDN Data certs an external impl
        // can parse. Success here *is* the wire-compat proof.
        let adopted = SignedTrustContext::decode_content(&content, v).unwrap();

        assert_eq!(adopted.anchors().len(), 1);
        let anchor = adopted.anchors().iter().next().unwrap();
        assert_eq!(fingerprint, Some(anchor_fingerprint(anchor.value())));
        assert!(
            anchor.name.to_string().contains("/KEY/"),
            "anchor cert follows the /KEY/ naming convention: {}",
            anchor.name
        );
        assert!(anchor.valid_until >= anchor.valid_from);
        assert!(!anchor.public_key.is_empty());
    }

    /// `build --pib … --sign-key …`: the signed envelope is adopted by the
    /// verified path; the unsigned legacy form of the same context is not.
    #[tokio::test]
    async fn signed_envelope_adopts_and_legacy_is_refused() {
        use ndn_security::{Ed25519Signer, Keyring, encode_cert_data};

        let key_name: Name = "/home/bob/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[7u8; 32], key_name.clone());
        let cert_name: Name = "/home/bob/KEY/k0/self/v=1".parse().unwrap();
        let cert_wire = encode_cert_data(
            &cert_name,
            &signer.public_key().unwrap(),
            &signer,
            0,
            u64::MAX,
        )
        .await
        .unwrap();
        let spec = ContextSpec {
            namespace: "/home/bob".parse().unwrap(),
            version: 2,
            anchor_wires: vec![cert_wire.to_vec()],
            ..Default::default()
        };

        let signed = build_signed_anchor_envelope(&spec, &signer).unwrap();
        let scanned = TrustEnvelope::from_uri(&signed.to_uri()).unwrap();
        let keyring = Keyring::new();
        let (ctx, _) = ndn_cert::adopt_anchor_envelope(&keyring, &scanned).unwrap();
        assert_eq!(ctx.version(), 2);

        let legacy = build_anchor_envelope(&spec).unwrap();
        assert!(matches!(
            ndn_cert::adopt_anchor_envelope(&Keyring::new(), &legacy),
            Err(ndn_cert::AdoptError::UnsignedLegacyContext)
        ));

        // A key that is not one of the context's anchors cannot sign it.
        let stranger = Ed25519Signer::from_seed(&[8u8; 32], "/home/eve/KEY/k".parse().unwrap());
        assert!(build_signed_anchor_envelope(&spec, &stranger).is_err());
    }

    proptest::proptest! {
        /// Any `(version, content)` survives the anchor envelope's
        /// `to_uri` -> `from_uri` unchanged — the payload is a lossless round-trip.
        #[test]
        fn envelope_round_trips(version: u64, content: Vec<u8>) {
            let env = TrustEnvelope::Anchor {
                namespace: None,
                fingerprint: None,
                version: Some(version),
                context_data: None,
                context_content: Some(bytes::Bytes::from(content)),
            };
            proptest::prop_assert_eq!(TrustEnvelope::from_uri(&env.to_uri()).unwrap(), env);
        }
    }
}
