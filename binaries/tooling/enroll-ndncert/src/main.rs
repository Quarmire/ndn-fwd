//! NDNCERT 0.3 enrollment helper. Runs NEW → CHALLENGE (pin, 2 rounds) →
//! cert-fetch against `ndncert-ca-server`, via the shared
//! [`ndn_cert::client::enroll`] driver. Without `--pin` the helper sends the
//! trigger round, prints `WAITING_FOR_PIN <request_id>` on stderr, and reads
//! the PIN from stdin.

use std::io::BufRead as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use ndn_app::Consumer;
use ndn_cert::{CaExchange, CertError};
use ndn_packet::{Data, Name};
use ndn_security::{EcdsaP256Signer, Signer};

const INTEREST_LIFETIME: Duration = Duration::from_secs(10);

/// [`CaExchange`] over the NFD consumer connection.
struct ConsumerExchange(Consumer);

impl CaExchange for ConsumerExchange {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        self.0
            .fetch_wire(interest, INTEREST_LIFETIME + Duration::from_millis(500))
            .await
            .map_err(|e| CertError::Transport(format!("{e:#}")))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("enroll_ndncert=info".parse()?),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let (face_socket, ca_prefix_str, name_str, pin_opt) = parse_args(&args)?;

    let ca_prefix: Name = ca_prefix_str.parse().context("invalid ca-prefix")?;
    let requester_name: Name = name_str.parse().context("invalid name")?;

    // Use ECDSA-P256: ndn-cxx (and so `ndncert-ca-server`) cannot verify
    // Ed25519 — its VerifierFilter forces EVP_DigestVerifyInit with SHA256,
    // which fails for Ed25519 EVP_PKEYs.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let key_name: Name = format!("{requester_name}/KEY/v={ts_ms}").parse()?;
    let ec_signer =
        EcdsaP256Signer::from_seed(&seed, key_name.clone()).context("ecdsa key init")?;
    let signer: Arc<dyn Signer> = Arc::new(ec_signer);

    let consumer = Consumer::connect(&face_socket)
        .await
        .with_context(|| format!("cannot connect to NFD at {face_socket}"))?;
    let mut exchange = ConsumerExchange(consumer);

    let mut pin_opt = pin_opt;
    let cert_name = ndn_cert::client::enroll(
        &mut exchange,
        &ca_prefix,
        signer,
        86400,
        "pin",
        |round| {
            let next = match round.round {
                // CHALLENGE trigger round — selects "pin", no code yet.
                0 => {
                    eprintln!("NEW complete — request_id={}", round.request_id);
                    Ok(Some(serde_json::Map::new()))
                }
                // CHALLENGE submit round — the PIN code.
                1 => {
                    eprintln!(
                        "CHALLENGE trigger sent — challenge_status={:?}",
                        round.status_message
                    );
                    read_pin(pin_opt.take(), &round.request_id).map(|pin| {
                        let mut code = serde_json::Map::new();
                        code.insert("code".to_string(), serde_json::Value::String(pin));
                        Some(code)
                    })
                }
                _ => Ok(None),
            };
            std::future::ready(next)
        },
    )
    .await
    .map_err(|e| match e {
        CertError::ChallengePending(_) => {
            anyhow::anyhow!("enrollment did not complete after PIN submission")
        }
        e => anyhow::Error::new(e).context("NDNCERT enrollment failed"),
    })?;

    eprintln!("enrollment complete — issued cert name: {cert_name}");

    // Fetch and decode the issued certificate. The fetched Data packet is
    // itself the Certificate v2 object; its Content is the SPKI public key,
    // not another nested Data packet.
    let ca_prefix_str = ca_prefix.to_string();
    let (issuer_str, fetched) =
        match ndn_cert::client::fetch_issued_cert(&mut exchange, &cert_name).await {
            Ok(cert_data) => {
                let cert = ndn_security::Certificate::decode(&cert_data)
                    .context("issued cert does not decode as NDN Certificate v2")?;
                let issuer_str = cert
                    .issuer
                    .as_deref()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                if !issuer_str.starts_with(ca_prefix_str.as_str()) {
                    bail!("cert issuer {issuer_str} does not chain to CA prefix {ca_prefix_str}");
                }
                (issuer_str, true)
            }
            Err(e) => {
                eprintln!("cert fetch skipped (no repo): {e:#}");
                (ca_prefix_str.clone(), false)
            }
        };

    println!("CERT_NAME={cert_name}");
    println!("ISSUER={issuer_str}");
    println!("CERT_FETCHED={fetched}");
    println!("ENROLL_OK");

    Ok(())
}

/// The PIN from `--pin`, or (printing `WAITING_FOR_PIN`) read from stdin.
fn read_pin(pin_arg: Option<String>, request_id: &str) -> Result<String, CertError> {
    let pin = match pin_arg {
        Some(p) => p,
        None => {
            eprintln!("WAITING_FOR_PIN request_id={request_id}");
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| CertError::InvalidRequest(format!("reading PIN from stdin: {e}")))?;
            line.trim().to_string()
        }
    };
    if pin.is_empty() {
        return Err(CertError::InvalidRequest("PIN is empty".into()));
    }
    Ok(pin)
}

fn parse_args(args: &[String]) -> anyhow::Result<(String, String, String, Option<String>)> {
    let mut face_socket = String::new();
    let mut ca_prefix = String::new();
    let mut name = String::new();
    let mut pin = None;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--face-socket" => {
                i += 1;
                face_socket = args
                    .get(i)
                    .context("--face-socket requires a value")?
                    .clone();
            }
            "--ca-prefix" => {
                i += 1;
                ca_prefix = args.get(i).context("--ca-prefix requires a value")?.clone();
            }
            "--name" => {
                i += 1;
                name = args.get(i).context("--name requires a value")?.clone();
            }
            "--pin" => {
                i += 1;
                pin = Some(args.get(i).context("--pin requires a value")?.clone());
            }
            other => bail!("unknown argument: {other}"),
        }
        i += 1;
    }
    if face_socket.is_empty() {
        bail!("--face-socket is required");
    }
    if ca_prefix.is_empty() {
        bail!("--ca-prefix is required");
    }
    if name.is_empty() {
        bail!("--name is required");
    }
    Ok((face_socket, ca_prefix, name, pin))
}
