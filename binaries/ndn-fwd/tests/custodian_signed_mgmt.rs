//! Live integration test: a mgmt command signed through a CustodianRegistry
//! (CustodianSigner over an InPageCustodian) is authorized by a real ndn-fwd
//! that requires signed commands, while an unsigned (DigestSha256) command is
//! rejected. This closes the "route mgmt signing through a custodian" loop
//! end-to-end against a running forwarder.
//!
//! The operator identity is created as a FilePib (its self-signed cert is
//! ndn-fwd's mgmt trust anchor); the *same* key is loaded into the in-page
//! custodian via `insert_signer`, so the custodian and the anchor agree.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_custodian::{CustodianSigner, InPageCustodian, KeyId};
use ndn_ipc::MgmtClient;
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{Certificate, Ed25519Signer, FilePib, KeyChain, Signer, encode_cert_data};

async fn wait_for_socket(path: &std::path::Path) -> bool {
    for _ in 0..100 {
        if path.exists() {
            // give mgmt a beat to start serving after the socket appears
            tokio::time::sleep(Duration::from_millis(150)).await;
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custodian_signed_command_authorized_by_strict_ndn_fwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor_pib = dir.path().join("anchor-pib");
    let sock = dir.path().join("fwd.sock");
    let conf = dir.path().join("fwd.toml");

    // 1. Operator identity → FilePib (self-signed cert = ndn-fwd's anchor).
    let kc = KeyChain::open_or_create(&anchor_pib, "/op/alice").expect("create operator identity");
    let key_name = kc.key_name().clone();
    let signer: Arc<dyn Signer> = kc.signer().expect("operator signer");
    let sig_type = signer.sig_type();
    let pubkey = signer.public_key();

    // 2. Same key into an in-page custodian → CustodianSigner.
    let key_id = KeyId(key_name.clone());
    let custodian = Arc::new(InPageCustodian::new());
    custodian.insert_signer(key_id.clone(), signer);
    let cs: Arc<dyn Signer> = Arc::new(CustodianSigner::new(custodian, key_id, sig_type, pubkey));

    // 3. ndn-fwd config: strict mgmt, anchor = the operator FilePib.
    std::fs::write(
        &conf,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n[security.mgmt]\n\
             require_signed_commands = true\ntrust_anchor_pib = \"{pib}\"\n",
            sock = sock.display(),
            pib = anchor_pib.display(),
        ),
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ndn-fwd"))
        .arg("-c")
        .arg(&conf)
        .spawn()
        .expect("spawn ndn-fwd");

    if !wait_for_socket(&sock).await {
        let _ = child.kill();
        panic!("ndn-fwd never bound its mgmt socket at {}", sock.display());
    }

    // 4. Custodian-signed command → must be authorized.
    let accepted = {
        let client = MgmtClient::connect(sock.to_str().unwrap())
            .await
            .expect("connect (signed)")
            .with_signer(cs);
        client
            .strategy_set(
                &"/test/custodian".parse::<Name>().unwrap(),
                &ndn_strategy::MulticastStrategy::strategy_name(),
            )
            .await
    };

    // 5. Unsigned (default DigestSha256) command → must be rejected.
    let rejected = {
        let client = MgmtClient::connect(sock.to_str().unwrap())
            .await
            .expect("connect (unsigned)");
        client
            .strategy_set(
                &"/test/unsigned".parse::<Name>().unwrap(),
                &ndn_strategy::MulticastStrategy::strategy_name(),
            )
            .await
    };

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        accepted.is_ok(),
        "custodian-signed command must be authorized by strict ndn-fwd, got {accepted:?}"
    );
    assert!(
        rejected.is_err(),
        "unsigned command must be rejected by the strict validator, got {rejected:?}"
    );
}

/// Regression: a SafeBag-style identity has a versioned *certificate* name
/// (`…/KEY/<id>/self/v=0`) distinct from its bare *key* name (`…/KEY/<id>`).
/// The forwarder keys its trust anchor by the cert name, so the signed
/// command's KeyLocator must name the cert — otherwise the validator returns
/// "signing certificate not yet resolved" (Pending → 403). This mirrors the
/// dashboard's `ndn-sec`-exported operator key, which the original test's
/// `KeyChain` (cert name == key name) didn't exercise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custodian_command_keylocator_must_name_the_cert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor_pib = dir.path().join("anchor-pib");
    let sock = dir.path().join("fwd.sock");
    let conf = dir.path().join("fwd.toml");

    // 1. Operator identity with a Certificate-Format-v2 versioned cert name,
    //    distinct from the bare key name (what `ndn-sec keygen` produces).
    let identity: Name = "/op/realistic".parse().unwrap();
    let key_name = identity
        .clone()
        .append("KEY")
        .append_component(NameComponent::generic(Bytes::from_static(b"k0")));
    let cert_name = key_name
        .clone()
        .append_component(NameComponent::generic(Bytes::from_static(b"self")))
        .append_version(0);
    assert_ne!(key_name, cert_name, "key and cert names must differ");

    let pib = FilePib::new(&anchor_pib).expect("pib");
    let signer = pib.generate_ed25519(&cert_name).expect("gen key");
    let pubkey = signer.public_key().expect("pubkey");
    let cert_wire = encode_cert_data(&cert_name, &pubkey, &signer, 0, u64::MAX)
        .await
        .expect("self-signed cert");
    let cert = Certificate::decode(&Data::decode(cert_wire).expect("data")).expect("cert");
    pib.store_cert(&cert_name, &cert).expect("store cert");
    pib.add_trust_anchor(&cert_name, &cert).expect("anchor");

    // 2. Load the *same* key into a custodian under the bare KEY name (as the
    //    dashboard does from a decrypted SafeBag), advertising the cert name.
    let pkcs8 = pib.export_pkcs8(&cert_name).expect("pkcs8");
    let op_signer = Ed25519Signer::from_pkcs8_der(&pkcs8, key_name.clone()).expect("op signer");
    let sig_type = op_signer.sig_type();
    let op_pub = op_signer.public_key();
    let key_id = KeyId(key_name.clone());
    let custodian = Arc::new(InPageCustodian::new());
    custodian.insert_signer(key_id.clone(), Arc::new(op_signer));

    std::fs::write(
        &conf,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n[security.mgmt]\n\
             require_signed_commands = true\ntrust_anchor_pib = \"{pib}\"\n",
            sock = sock.display(),
            pib = anchor_pib.display(),
        ),
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ndn-fwd"))
        .arg("-c")
        .arg(&conf)
        .spawn()
        .expect("spawn ndn-fwd");
    if !wait_for_socket(&sock).await {
        let _ = child.kill();
        panic!("ndn-fwd never bound its mgmt socket");
    }

    // KeyLocator = bare KEY name → can't resolve to the cert-keyed anchor.
    let without_cert = {
        let cs: Arc<dyn Signer> = Arc::new(CustodianSigner::new(
            custodian.clone(),
            key_id.clone(),
            sig_type,
            op_pub.clone(),
        ));
        MgmtClient::connect(sock.to_str().unwrap())
            .await
            .expect("connect")
            .with_signer(cs)
            .strategy_set(
                &"/test/nocert".parse::<Name>().unwrap(),
                &ndn_strategy::MulticastStrategy::strategy_name(),
            )
            .await
    };

    // KeyLocator = cert name → resolves directly to the anchor.
    let with_cert = {
        let cs: Arc<dyn Signer> = Arc::new(
            CustodianSigner::new(custodian, key_id, sig_type, op_pub)
                .with_cert_name(cert_name.clone()),
        );
        MgmtClient::connect(sock.to_str().unwrap())
            .await
            .expect("connect")
            .with_signer(cs)
            .strategy_set(
                &"/test/withcert".parse::<Name>().unwrap(),
                &ndn_strategy::MulticastStrategy::strategy_name(),
            )
            .await
    };

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        without_cert.is_err(),
        "KeyLocator naming only the bare key must NOT resolve to the cert anchor, got {without_cert:?}"
    );
    assert!(
        with_cert.is_ok(),
        "KeyLocator naming the cert must be authorized, got {with_cert:?}"
    );
}
