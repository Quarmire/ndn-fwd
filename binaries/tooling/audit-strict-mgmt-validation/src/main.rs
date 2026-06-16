//! Strict-trust management-response validation witness. Connects to a
//! running `ndn-fwd` over its mgmt socket, fetches
//! `/localhost/nfd/status/general`, and validates the response Data with a
//! [`Validator`] pinned only to the daemon's persisted trust anchors. Exits
//! 0 on [`ValidationResult::Valid`], 1 otherwise.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ndn_face::local::{IpcFace, ipc_face_connect};
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

    // An empty schema rejects all Data via the pre-chain `allows(name, key)`
    // gate, even Data signed directly by an anchor. Use a permissive "any
    // Data, any signer" rule so authorisation defers to the chain walk; the
    // cert chain must still terminate at a trusted anchor, so the gate is
    // anchor pinning.
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

    let face: IpcFace = ipc_face_connect(FaceId(1), &socket)
        .await
        .with_context(|| format!("connecting to mgmt socket {socket}"))?;
    info!("connected to ndn-fwd mgmt socket");

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

    let raw = match tokio::time::timeout(Duration::from_secs(3), Transport::recv_bytes(&face)).await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => bail!("face recv error: {e:?}"),
        Err(_) => bail!("timed out waiting for Data response"),
    };
    let data_wire = lp::LpPacket::decode(raw.clone())
        .ok()
        .and_then(|p| p.fragment)
        .unwrap_or(raw);
    let data = Data::decode(data_wire).map_err(|e| anyhow!("decode Data: {e:?}"))?;
    info!(name = %data.name, "received response Data");

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
            // For a self-signed daemon the KeyLocator should resolve
            // directly to the anchor; `Pending` here is a real bug.
            bail!(
                "validator returned Pending — KeyLocator on the response \
                 didn't resolve to an installed trust anchor"
            );
        }
    }
}
