//! `ndn-pair-kiosk` — a minimal stand-in for an untrusted peer (a kiosk /
//! dashboard) pairing with the phone via the **remote-signer** model. The phone
//! keeps its key; this peer only ever gets individual signatures, on demand,
//! within the time window the operator granted.
//!
//! ```text
//! ndn-pair-kiosk request <namespace> <ttl-secs>
//!     → an ndn-trust://capability/ REQUEST URI for the phone to scan
//! ndn-pair-kiosk pubkey <grant-uri>
//!     → the operator public key (base64) from the certificate a GRANT carries
//! ndn-pair-kiosk signreq <name>
//!     → a base64 WireSignRequest to hand the phone (its Approve tab)
//! ndn-pair-kiosk verify <name> <response-b64> <operator-pubkey-b64>
//!     → verify the returned signature over the request's region
//! ```
//!
//! The phone's `Capability{Grant}` envelope carries the operator's certificate
//! (signed NDN Data wire) in `grant`; `<operator-pubkey-b64>` is that
//! certificate's public key (what `pubkey` prints). The signature it verifies
//! is what `respond_to_sign_request` produced.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_security::Certificate;
use ndn_security::custodian::{WireSignRequest, WireSignResponse};
use ndn_security::verifier::{EcdsaSha256Verifier, Verifier, VerifyOutcome};
use ndn_trust_envelope::{CAPABILITY_NONCE_LEN, CapDirection, Capability, TrustEnvelope};

/// The operator public key from a `Capability{Grant}` URI: `grant` is the
/// operator's certificate as signed NDN Data wire.
fn operator_pubkey(grant_uri: &str) -> Vec<u8> {
    match TrustEnvelope::from_uri(grant_uri.trim())
        .unwrap_or_else(|e| die(&format!("parse grant: {e}")))
    {
        TrustEnvelope::Capability(Capability {
            grant: Some(cert_wire),
            ..
        }) => {
            let data = ndn_packet::Data::decode(cert_wire)
                .unwrap_or_else(|e| die(&format!("grant is not a Data packet: {e:?}")));
            Certificate::decode(&data)
                .unwrap_or_else(|e| die(&format!("grant is not a certificate: {e}")))
                .public_key
                .to_vec()
        }
        _ => die("not a capability grant (no operator certificate)"),
    }
}

/// The to-be-signed region for a command named `name` — its TLV-encoded Name
/// (the leading Name the phone scope-checks and signs).
fn region_for(name: &str) -> Vec<u8> {
    let n: Name = name
        .parse()
        .unwrap_or_else(|_| die(&format!("invalid NDN name: {name}")));
    n.encode_to_tlv().to_vec()
}

/// A capability request for `namespace` lasting `ttl_secs`, with a fresh
/// random nonce (`CAPABILITY_NONCE_LEN` bytes) so no two requests are alike
/// and a granting device can tell a replayed request from a new one. The
/// namespace is written in its canonical URI form.
fn request_envelope(namespace: &str, ttl_secs: u64) -> TrustEnvelope {
    let namespace: Name = namespace
        .parse()
        .unwrap_or_else(|_| die(&format!("invalid NDN name: {namespace}")));
    let mut nonce = [0u8; CAPABILITY_NONCE_LEN];
    getrandom::getrandom(&mut nonce).unwrap_or_else(|_| die("system RNG unavailable"));
    TrustEnvelope::Capability(Capability {
        direction: CapDirection::Request,
        namespace: namespace.to_string(),
        scope_patterns: vec![],
        ttl_secs,
        nonce: Bytes::copy_from_slice(&nonce),
        grant: None,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("request") if args.len() == 3 => {
            let ttl: u64 = args[2]
                .parse()
                .unwrap_or_else(|_| die("ttl must be a number"));
            println!("{}", request_envelope(&args[1], ttl).to_uri());
        }
        Some("pubkey") if args.len() == 2 => {
            println!("{}", B64.encode(operator_pubkey(&args[1])));
        }
        Some("signreq") if args.len() == 2 => {
            let req = WireSignRequest {
                req_id: 1,
                region: Bytes::from(region_for(&args[1])),
            };
            println!("{}", B64.encode(req.encode()));
        }
        Some("verify") if args.len() == 4 => {
            let region = region_for(&args[1]);
            let resp_wire = B64
                .decode(args[2].trim())
                .unwrap_or_else(|_| die("bad response base64"));
            let pubkey = B64
                .decode(args[3].trim())
                .unwrap_or_else(|_| die("bad pubkey base64"));
            match WireSignResponse::decode(&resp_wire)
                .unwrap_or_else(|e| die(&format!("decode response: {e:?}")))
            {
                WireSignResponse::Approved { signature, .. } => {
                    let outcome = futures::executor::block_on(
                        EcdsaSha256Verifier.verify(&region, &signature, &pubkey),
                    );
                    match outcome {
                        Ok(VerifyOutcome::Valid) => {
                            println!(
                                "VALID — operator signed {} ({}-byte signature)",
                                args[1],
                                signature.len()
                            );
                        }
                        other => die(&format!("INVALID signature: {other:?}")),
                    }
                }
                WireSignResponse::Denied { .. } => die("DENIED by operator"),
            }
        }
        // Send a sign request to the phone's `…/signer` responder over a real
        // forwarder — the same NDN path the dashboard's transport uses.
        //   signnet <socket> <signer-prefix> <name> [operator-pubkey-b64]
        Some("signnet") if args.len() == 4 || args.len() == 5 => {
            let socket = args[1].clone();
            let signer_prefix: Name = args[2]
                .parse()
                .unwrap_or_else(|_| die(&format!("invalid signer prefix: {}", args[2])));
            let name = args[3].clone();
            let pubkey_b64 = args.get(4).cloned();
            let region = region_for(&name);
            let wire = WireSignRequest {
                req_id: 1,
                region: Bytes::from(region.clone()),
            }
            .encode();
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let mut consumer = Consumer::connect(&socket)
                    .await
                    .unwrap_or_else(|e| die(&format!("connect {socket}: {e}")));
                let builder = InterestBuilder::new(signer_prefix)
                    .app_parameters(wire.to_vec())
                    .must_be_fresh()
                    .lifetime(Duration::from_secs(20));
                let data = consumer
                    .fetch_with(builder)
                    .await
                    .unwrap_or_else(|e| die(&format!("no response from signer: {e}")));
                let content = data
                    .content()
                    .unwrap_or_else(|| die("empty signer response"));
                match WireSignResponse::decode(content)
                    .unwrap_or_else(|e| die(&format!("decode response: {e:?}")))
                {
                    WireSignResponse::Approved { signature, .. } => {
                        println!(
                            "APPROVED over NDN — {}-byte signature for {name}",
                            signature.len()
                        );
                        if let Some(arg) = pubkey_b64 {
                            // Accept either a raw pubkey (base64) or the grant URI
                            // (extract the operator key from the certificate it carries).
                            let pk = if arg.starts_with("ndn-trust://") {
                                operator_pubkey(&arg)
                            } else {
                                B64.decode(arg.trim())
                                    .unwrap_or_else(|_| die("bad pubkey base64"))
                            };
                            match EcdsaSha256Verifier.verify(&region, &signature, &pk).await {
                                Ok(VerifyOutcome::Valid) => {
                                    println!("VALID — the phone signed {name}")
                                }
                                other => die(&format!("INVALID signature: {other:?}")),
                            }
                        }
                    }
                    WireSignResponse::Denied { .. } => {
                        println!(
                            "DENIED over NDN (channel works end-to-end; no in-scope grant open)"
                        )
                    }
                }
            });
        }
        _ => die(
            "usage: ndn-pair-kiosk (request <ns> <ttl> | pubkey <grant-uri> | signreq <name> | verify <name> <resp-b64> <pubkey-b64> | signnet <socket> <signer-prefix> <name> [pubkey-b64|grant-uri])",
        ),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_of(envelope: TrustEnvelope) -> Bytes {
        match TrustEnvelope::from_uri(&envelope.to_uri()).unwrap() {
            TrustEnvelope::Capability(c) => c.nonce,
            other => panic!("not a capability: {other:?}"),
        }
    }

    /// Each request carries its own random nonce, never a constant.
    #[test]
    fn every_request_gets_a_fresh_nonce() {
        let a = nonce_of(request_envelope("/work/acme/dashboard", 300));
        let b = nonce_of(request_envelope("/work/acme/dashboard", 300));
        assert_eq!(a.len(), CAPABILITY_NONCE_LEN);
        assert_eq!(b.len(), CAPABILITY_NONCE_LEN);
        assert_ne!(a, b);
    }
}
