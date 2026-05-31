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

use ndn_custodian::{CustodianSigner, InPageCustodian, KeyId};
use ndn_ipc::MgmtClient;
use ndn_packet::Name;
use ndn_security::{KeyChain, Signer};

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
