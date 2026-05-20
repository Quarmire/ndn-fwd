//! Strict-trust management-response validation witness.
//!
//! Audit gate for finding N.12: mgmt response Data must be verifiable
//! under a real trust schema, not just decoded as a `ControlResponse`.
//! This binary takes a running `ndn-fwd`'s management socket + its
//! PIB directory, fetches `/localhost/nfd/status/general` over the
//! socket, then validates the response Data against a freshly-built
//! [`Validator`] pinned to **only** the daemon's persisted trust
//! anchor — the same contract `ndn-cxx`'s `ValidatorConfig` (and any
//! `nfdc` configured with a trust schema) would enforce.
//!
//! Why this is the right witness rather than "literally run nfdc":
//!
//! - `nfdc` (ndn-cxx) signs with whatever's in the operator's
//!   `client.conf` and validates with whatever's in
//!   `validator-config-file`, neither of which it ships defaults
//!   for.  Forcing it into strict mode requires writing a `client.conf`
//!   plus a `validator.conf` per test run, which only proves the
//!   wrapping config does what we already know it should.
//! - ndn-cxx's actual signature verifier is OpenSSL's
//!   `EVP_DigestVerify` over ECDSA-P256 + SHA-256 — bit-for-bit
//!   identical math to the `p256` crate's verifier our `Validator`
//!   uses.  If ours says `Valid`, so will ndn-cxx's.
//! - We control both the signer and the verifier path through
//!   `ndn-security`'s `Validator`, which is the same code the engine
//!   uses for inbound Data — making this a real "the deployed
//!   verifier accepts the deployed signer" gate.
//!
//! What the witness pins:
//!
//!  1. ndn-fwd's `mount_management` returns Data with a real
//!     `SignatureInfo` carrying a non-zero `SignatureType` and a
//!     `KeyLocator` pointing at the daemon's identity key.
//!  2. The signed region of that Data, verified against the
//!     persisted anchor's public key, produces a cryptographically
//!     valid signature.
//!  3. The `KeyLocator` resolves to a cert that chains to a
//!     trust anchor stored in the daemon's PIB.
//!
//! Exits 0 on `ValidationResult::Valid`, 1 otherwise.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ndn_faces::local::{IpcFace, ipc_face_connect};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp;
use ndn_packet::{Data, Name};
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_security::{FilePib, ValidationResult, Validator};
use ndn_transport::{FaceId, Transport};
use tracing::{info, warn};

fn arg(name: &str) -> Result<String> {
    let key = format!("--{name}=");
    for a in std::env::args().skip(1) {
        if let Some(v) = a.strip_prefix(&key) {
            return Ok(v.to_string());
        }
    }
    let mut prev: Option<String> = None;
    for a in std::env::args().skip(1) {
        if let Some(p) = prev.take()
            && p == format!("--{name}")
        {
            return Ok(a);
        }
        prev = Some(a);
    }
    Err(anyhow!("missing --{name} <value>"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();

    let socket: String = arg("socket").context("--socket <path-to-ndn-fwd-mgmt-socket>")?;
    let pib_path: PathBuf = PathBuf::from(arg("pib").context("--pib <ndn-fwd-pib-dir>")?);

    info!(socket = %socket, pib = %pib_path.display(), "strict-mgmt-validation: starting");

    // ── 1. Load the daemon's trust anchor from its PIB ────────────────────
    let pib = FilePib::open(&pib_path)
        .with_context(|| format!("opening PIB at {}", pib_path.display()))?;
    let anchors = pib
        .trust_anchors()
        .context("reading trust anchors from PIB")?;
    if anchors.is_empty() {
        bail!(
            "daemon PIB at {} has no trust anchors — ndn-fwd's auto-init should \
             register its self-signed cert as an anchor; refusing to run a witness \
             that would silently accept anything",
            pib_path.display()
        );
    }
    info!(count = anchors.len(), "loaded trust anchors from PIB");

    // Build a Validator with the daemon's anchors plus a single
    // permissive name-matching rule.  An empty TrustSchema rejects
    // *every* Data via the `allows(name, key)` gate that runs before
    // the chain walk — even Data signed directly by an anchor.  The
    // rule below ("any Data, any signer") makes the schema defer all
    // authorisation to the chain walk: the cert chain still has to
    // terminate at an anchor cert we trust, so the security gate is
    // anchor pinning, not schema rules.  This matches the
    // ValidatorConfig pattern an operator would write for a daemon
    // serving its own self-signed mgmt namespace.
    let mut schema = TrustSchema::new();
    schema.add_rule(SchemaRule {
        data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
    });
    let validator = Validator::new(schema);
    for cert in &anchors {
        info!(anchor = %cert.name, "installing trust anchor");
        validator.add_trust_anchor(cert.clone());
    }

    // ── 2. Connect over the management Unix socket ────────────────────────
    let face: IpcFace = ipc_face_connect(FaceId(1), &socket)
        .await
        .with_context(|| format!("connecting to mgmt socket {socket}"))?;
    info!("connected to ndn-fwd mgmt socket");

    // ── 3. Issue `/localhost/nfd/status/general` ──────────────────────────
    let name: Name = "/localhost/nfd/status/general"
        .parse()
        .map_err(|e| anyhow!("parse name: {e:?}"))?;
    let interest_wire = InterestBuilder::new(name.clone())
        .can_be_prefix()
        .sign_digest_sha256();
    let lp_wire = lp::encode_lp_packet(&interest_wire);
    Transport::send_bytes(&face, lp_wire)
        .await
        .context("sending mgmt Interest")?;

    // ── 4. Receive the response Data wire ─────────────────────────────────
    let raw = match tokio::time::timeout(Duration::from_secs(3), Transport::recv_bytes(&face)).await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => bail!("face recv error: {e:?}"),
        Err(_) => bail!("timed out waiting for Data response"),
    };
    // Strip NDNLPv2 envelope if present.
    let data_wire = lp::LpPacket::decode(raw.clone())
        .ok()
        .and_then(|p| p.fragment)
        .unwrap_or(raw);
    let data = Data::decode(data_wire).map_err(|e| anyhow!("decode Data: {e:?}"))?;
    info!(name = %data.name, "received response Data");

    // ── 5. Validate against the daemon's anchor — the actual N.12 gate ───
    match validator.validate_chain(&data).await {
        ValidationResult::Valid(_safe) => {
            info!(
                name = %data.name,
                sig_type = ?data.sig_info().map(|s| s.sig_type),
                "VALID — signature verifies under the daemon's trust anchor"
            );
            println!(
                "PASS: mgmt response /localhost/nfd/status/general validates against \
                 trust anchor {} (sig_type={:?})",
                anchors[0].name,
                data.sig_info().map(|s| s.sig_type),
            );
            Ok(())
        }
        ValidationResult::Invalid(reason) => {
            warn!(?reason, "INVALID");
            bail!(
                "mgmt response did NOT validate under strict trust schema: {:?}",
                reason
            );
        }
        ValidationResult::Pending => {
            // Pending means the validator wants a cert it doesn't have.
            // For a self-signed daemon the KeyLocator should resolve
            // directly to the anchor — Pending here is a real bug.
            bail!(
                "validator returned Pending — KeyLocator on the response \
                 didn't resolve to an installed trust anchor"
            );
        }
    }
}
