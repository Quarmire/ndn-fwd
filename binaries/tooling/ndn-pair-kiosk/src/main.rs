//! `ndn-pair-kiosk` — a minimal stand-in for an untrusted peer (a kiosk /
//! dashboard) pairing with the phone via the **remote-signer** model. The phone
//! keeps its key; this peer only ever gets individual signatures, on demand,
//! within the time window the operator granted.
//!
//! ```text
//! ndn-pair-kiosk request <namespace> <ttl-secs>
//!     → an ndn-trust://capability/ REQUEST URI for the phone to scan
//! ndn-pair-kiosk signreq <name>
//!     → a base64 WireSignRequest to hand the phone (its Approve tab)
//! ndn-pair-kiosk verify <name> <response-b64> <operator-pubkey-b64>
//!     → verify the returned signature over the request's region
//! ```
//!
//! `<operator-pubkey-b64>` is the key the phone returns in the `Capability{Grant}`
//! envelope; the signature it verifies is what `respond_to_sign_request` produced.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use ndn_custodian::{WireSignRequest, WireSignResponse};
use ndn_packet::Name;
use ndn_security::verifier::{EcdsaSha256Verifier, VerifyOutcome, Verifier};
use ndn_trust_envelope::{CapDirection, Capability, TrustEnvelope};

/// The to-be-signed region for a command named `name` — its TLV-encoded Name
/// (the leading Name the phone scope-checks and signs).
fn region_for(name: &str) -> Vec<u8> {
    let n: Name = name.parse().unwrap_or_else(|_| die(&format!("invalid NDN name: {name}")));
    n.encode_to_tlv().to_vec()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("request") if args.len() == 3 => {
            let ttl: u64 = args[2].parse().unwrap_or_else(|_| die("ttl must be a number"));
            let env = TrustEnvelope::Capability(Capability {
                direction: CapDirection::Request,
                namespace: args[1].clone(),
                scope_patterns: vec![],
                ttl_secs: ttl,
                nonce: Bytes::from_static(b"kiosk-nonce-1"),
                grant: None,
            });
            println!("{}", env.to_uri());
        }
        Some("pubkey") if args.len() == 2 => {
            // Extract the operator's public key from a Capability{Grant} envelope.
            match TrustEnvelope::from_uri(&args[1]).unwrap_or_else(|e| die(&format!("parse grant: {e}"))) {
                TrustEnvelope::Capability(Capability { grant: Some(pk), .. }) => {
                    println!("{}", B64.encode(&pk));
                }
                _ => die("not a capability grant (no operator key)"),
            }
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
            let resp_wire = B64.decode(args[2].trim()).unwrap_or_else(|_| die("bad response base64"));
            let pubkey = B64.decode(args[3].trim()).unwrap_or_else(|_| die("bad pubkey base64"));
            match WireSignResponse::decode(&resp_wire).unwrap_or_else(|e| die(&format!("decode response: {e:?}"))) {
                WireSignResponse::Approved { signature, .. } => {
                    let outcome = futures::executor::block_on(
                        EcdsaSha256Verifier.verify(&region, &signature, &pubkey),
                    );
                    match outcome {
                        Ok(VerifyOutcome::Valid) => {
                            println!("VALID — operator signed {} ({}-byte signature)", args[1], signature.len());
                        }
                        other => die(&format!("INVALID signature: {other:?}")),
                    }
                }
                WireSignResponse::Denied { .. } => die("DENIED by operator"),
            }
        }
        _ => die("usage: ndn-pair-kiosk (request <ns> <ttl> | signreq <name> | verify <name> <resp-b64> <pubkey-b64>)"),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}
