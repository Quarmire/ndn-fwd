//! Live integration test for the G11 **capability-scoped `shm://` face**
//! handshake against a real ndn-fwd (increment 2b-tail, Option A).
//!
//! A client mints a one-time token, sends it in `faces/create`, and receives the
//! anonymous region + wakeup fds over the **token-derived** control socket via
//! `SCM_RIGHTS` — the full bootstrap, end to end through the forwarder. A *wrong*
//! token derives a different, non-existent socket path, so it can't even find the
//! handoff (the unguessable-path capability property).
#![cfg(feature = "spsc-shm")]

use std::process::Command;
use std::time::Duration;

use ndn_ipc::MgmtClient;

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
async fn shm_capability_face_handshake_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("fwd.sock");
    let conf = dir.path().join("fwd.toml");
    std::fs::write(
        &conf,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n\
             [security.mgmt]\nrequire_signed_commands = false\n",
            sock = sock.display(),
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

    let client = MgmtClient::connect(sock.to_str().unwrap())
        .await
        .expect("connect mgmt");

    // Capability-scoped face: mint a token, send it in faces/create. The router
    // provisions an ANONYMOUS region, binds the token-derived control socket, and
    // serves its fds gated by the token.
    let token = ndn_face_shm::mint_token().expect("mint token");
    let resp = client
        .face_create_shm("shm://itest", None, bytes::Bytes::copy_from_slice(&token))
        .await;

    // Receive the region + wakeup fds over the token-derived control socket.
    let path = ndn_face_shm::control_socket_path(&token);
    let handle =
        tokio::task::spawn_blocking(move || ndn_face_shm::connect_fd_handoff(&path, &token))
            .await
            .expect("handoff task join");

    // A WRONG token derives a different (never-bound) socket path → can't even
    // find the handoff, let alone obtain the fds.
    let wrong = [0u8; 32];
    let wrong_path = ndn_face_shm::control_socket_path(&wrong);
    let wrong_res =
        tokio::task::spawn_blocking(move || ndn_face_shm::connect_fd_handoff(&wrong_path, &wrong))
            .await
            .expect("wrong-token task join");

    let _ = child.kill();
    let _ = child.wait();

    let resp = resp.expect("ndn-fwd must accept the capability shm:// faces/create");
    assert!(
        resp.face_id.is_some(),
        "router must return a face_id for the shm:// face"
    );
    assert!(
        handle.is_ok(),
        "client must receive the region+wakeup fds via the token-gated handshake: {:?}",
        handle.as_ref().err()
    );
    assert!(
        wrong_res.is_err(),
        "a wrong token must not find/obtain the capability fds"
    );
}
