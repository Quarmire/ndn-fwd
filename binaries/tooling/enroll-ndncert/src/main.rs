//! NDNCERT 0.3 enrollment helper — C.13 live CA interop witness tool.
//!
//! Performs a full NEW → CHALLENGE (pin, 2 rounds) → cert-fetch enrollment
//! against a running `ndncert-ca-server`.
//!
//! Usage:
//!   enroll-ndncert \
//!     --face-socket /run/nfd-ndncert/nfd.sock \
//!     --ca-prefix /test/ndncert/CA \
//!     --name /test/requester \
//!     [--pin CODE]
//!
//! If --pin is omitted the binary performs NEW + round-1 CHALLENGE (trigger),
//! prints "WAITING_FOR_PIN" and the request_id to stderr, then reads one line
//! from stdin as the PIN.  The witness script feeds the PIN by parsing the CA
//! container logs after the trigger round.

use std::io::BufRead as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use ndn_app::Consumer;
use ndn_cert::EnrollmentSession;
use ndn_packet::Name;
use ndn_packet::SignatureType;
use ndn_packet::encode::InterestBuilder;
use ndn_security::{EcdsaP256Signer, Signer};

const INTEREST_LIFETIME: Duration = Duration::from_secs(10);

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

    // Generate a fresh ephemeral ECDSA P-256 key. Upstream ndn-cxx (and thus
    // ndncert-ca-server) cannot verify Ed25519 signatures: its TLV decoder
    // recognizes SignatureEd25519 as a constant but VerifierFilter forces
    // EVP_DigestVerifyInit with SHA256, which fails for Ed25519 EVP_PKEYs.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let key_name: Name = format!("{requester_name}/KEY/v={ts_ms}").parse()?;
    let ec_signer = EcdsaP256Signer::from_seed(&seed, key_name.clone())
        .context("ecdsa key init")?;
    let signer: Arc<dyn Signer> = Arc::new(ec_signer);

    let mut consumer = Consumer::connect(&face_socket)
        .await
        .with_context(|| format!("cannot connect to NFD at {face_socket}"))?;

    let mut session = EnrollmentSession::new(key_name.clone(), Arc::clone(&signer), 86400);

    // ── Step 1: NEW ──────────────────────────────────────────────────────────
    let new_params = session.new_request_body().await?;
    let new_name = ca_prefix.clone().append("CA").append("NEW");

    let new_wire = sign_interest(
        InterestBuilder::new(new_name).app_parameters(new_params),
        SignatureType::SignatureSha256WithEcdsa,
        &key_name,
        &signer,
    )
    .await?;

    let new_data = consumer
        .fetch_wire(new_wire, INTEREST_LIFETIME + Duration::from_millis(500))
        .await
        .context("NEW request failed")?;

    let new_content = new_data
        .content()
        .context("NEW response has no content")?;
    session.handle_new_response(new_content)?;

    let request_id_bytes = session
        .request_id_bytes()
        .context("no request_id from CA after NEW")?
        .to_vec();

    eprintln!("NEW complete — request_id={}", hex_encode(&request_id_bytes));

    // ── Step 2a: CHALLENGE round 1 (trigger — no code, selects "pin") ────────
    let trigger_params = session.challenge_request_body("pin", serde_json::Map::new())?;
    let challenge_name = ca_prefix
        .clone()
        .append("CA")
        .append("CHALLENGE")
        .append(&request_id_bytes);

    let trigger_wire = sign_interest(
        InterestBuilder::new(challenge_name.clone()).app_parameters(trigger_params),
        SignatureType::SignatureSha256WithEcdsa,
        &key_name,
        &signer,
    )
    .await?;

    let trigger_data = consumer
        .fetch_wire(trigger_wire, INTEREST_LIFETIME + Duration::from_millis(500))
        .await
        .context("CHALLENGE trigger request failed")?;

    let trigger_content = trigger_data
        .content()
        .context("CHALLENGE trigger response has no content")?;
    session.handle_challenge_response(trigger_content)?;

    if session.is_complete() {
        // CA accepted without a PIN (nop-equivalent; not expected with real pin).
        return finish(&mut consumer, &session, &ca_prefix).await;
    }

    eprintln!(
        "CHALLENGE trigger sent — challenge_status={:?}",
        session.challenge_status_message()
    );

    // ── Step 2b: Obtain PIN ───────────────────────────────────────────────────
    let pin = if let Some(p) = pin_opt {
        p
    } else {
        eprintln!(
            "WAITING_FOR_PIN request_id={}",
            hex_encode(&request_id_bytes)
        );
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading PIN from stdin")?;
        line.trim().to_string()
    };

    if pin.is_empty() {
        bail!("PIN is empty");
    }

    // ── Step 2c: CHALLENGE round 2 (submit PIN code) ─────────────────────────
    let mut code_params = serde_json::Map::new();
    code_params.insert("code".to_string(), serde_json::Value::String(pin));
    let submit_params = session.challenge_request_body("pin", code_params)?;

    let submit_wire = sign_interest(
        InterestBuilder::new(challenge_name).app_parameters(submit_params),
        SignatureType::SignatureSha256WithEcdsa,
        &key_name,
        &signer,
    )
    .await?;

    let submit_data = consumer
        .fetch_wire(submit_wire, INTEREST_LIFETIME + Duration::from_millis(500))
        .await
        .context("CHALLENGE submit request failed")?;

    let submit_content = submit_data
        .content()
        .context("CHALLENGE submit response has no content")?;
    session.handle_challenge_response(submit_content)?;

    if !session.is_complete() {
        bail!("enrollment did not complete after PIN submission");
    }

    finish(&mut consumer, &session, &ca_prefix).await
}

async fn sign_interest(
    builder: InterestBuilder,
    sig_type: SignatureType,
    key_name: &Name,
    signer: &Arc<dyn Signer>,
) -> anyhow::Result<bytes::Bytes> {
    let s = Arc::clone(signer);
    let kn = key_name.clone();
    builder
        .sign_fallible(sig_type, Some(&kn), move |region| {
            let s = Arc::clone(&s);
            let owned = region.to_vec();
            async move { s.sign(&owned).await }
        })
        .await
        .map_err(|e: ndn_security::TrustError| anyhow::anyhow!("Interest signing failed: {e}"))
}

async fn finish(
    consumer: &mut Consumer,
    session: &EnrollmentSession,
    ca_prefix: &Name,
) -> anyhow::Result<()> {
    let cert_name = session
        .issued_cert_name()
        .context("no issued cert name after enrollment")?
        .clone();

    eprintln!("enrollment complete — issued cert name: {cert_name}");

    // ── Step 3: Fetch and decode the issued certificate (best-effort) ─────────
    // Upstream ndncert-ca-server registers only `<ca-prefix>/CA` for the
    // protocol endpoints; the issued cert lives at `<requester-id>/KEY/...`
    // which the CA does not serve from its own face — production deployments
    // pair the CA with an external NDN repo. The witness passes when the CA
    // returns IssuedCertName; cert fetch is best-effort.
    let ca_prefix_str = ca_prefix.to_string();
    let (issuer_str, fetched) = match consumer.fetch(cert_name.clone()).await {
        Ok(cert_data) => {
            let cert_bytes = cert_data
                .content()
                .context("cert fetch response has no content")?;
            let cert = ndn_cert::ca::deserialize_cert(cert_bytes)
                .context("issued cert does not decode as NDN Certificate v2")?;
            let issuer_str = cert
                .issuer
                .as_deref()
                .map(|n| n.to_string())
                .unwrap_or_default();
            if !issuer_str.starts_with(ca_prefix_str.as_str()) {
                bail!(
                    "cert issuer {issuer_str} does not chain to CA prefix {ca_prefix_str}"
                );
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
                face_socket = args.get(i).context("--face-socket requires a value")?.clone();
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
