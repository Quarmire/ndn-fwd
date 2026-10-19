//! Regression: two forwarders on one host configured with the same UDP
//! listener port must not both run. The listener used to bind with
//! `SO_REUSEPORT`, so the second forwarder (same user) silently joined the
//! first one's reuse group and the kernel split inbound datagrams between the
//! two. The second forwarder must refuse to start and name the port; the
//! first, whose own peer face shares its listener's port, keeps working.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn spawn_fwd(conf: &std::path::Path, stderr: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ndn-fwd"))
        .arg("-c")
        .arg(conf)
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn ndn-fwd")
}

/// The local port of the forwarder's face to the hub, once it exists.
async fn peer_face_port(client: &MgmtClient, hub_port: u16) -> Option<u16> {
    client
        .face_list()
        .await
        .expect("faces/list")
        .iter()
        .find(|f| f.uri.ends_with(&format!(":{hub_port}")))
        .and_then(|f| f.local_uri.rsplit(':').next()?.parse().ok())
}

/// Kills the forwarder when the test ends, pass or fail.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_forwarder_refuses_a_held_udp_listener_port() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hub = std::net::UdpSocket::bind("127.0.0.1:0").expect("hub");
    let hub_addr = hub.local_addr().unwrap();

    // First forwarder: a UDP listener on a port the kernel picks (no window
    // for another process to take it), and a configured peer face, which
    // binds the listener's port beside it.
    let sock_a = dir.path().join("a.sock");
    let conf_a = dir.path().join("a.toml");
    std::fs::write(
        &conf_a,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n\
             [[face]]\nkind = \"udp\"\nbind = \"127.0.0.1:0\"\n\n\
             [[face]]\nkind = \"udp\"\nremote = \"{hub_addr}\"\n",
            sock = sock_a.display(),
        ),
    )
    .unwrap();
    let mut a = Reap(spawn_fwd(&conf_a, Stdio::null()));
    assert!(
        wait_for_socket(&sock_a).await,
        "first ndn-fwd never bound its mgmt socket"
    );
    let client = MgmtClient::connect(sock_a.to_str().unwrap())
        .await
        .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    let port = loop {
        match peer_face_port(&client, hub_addr.port()).await {
            Some(port) => break port,
            None => assert!(
                Instant::now() < deadline,
                "the first forwarder's peer face never came up"
            ),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_ne!(port, 0);

    // Second forwarder: the same UDP listener port.
    let sock_b = dir.path().join("b.sock");
    let conf_b = dir.path().join("b.toml");
    std::fs::write(
        &conf_b,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n\
             [[face]]\nkind = \"udp\"\nbind = \"127.0.0.1:{port}\"\n",
            sock = sock_b.display(),
        ),
    )
    .unwrap();
    let mut b = Reap(spawn_fwd(&conf_b, Stdio::piped()));
    let mut pipe = b.0.stderr.take().unwrap();
    let stderr = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = pipe.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = b.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the second forwarder started on UDP port {port}, which the first holds"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let stderr = stderr.join().unwrap();
    assert!(!status.success(), "second forwarder exited {status}");
    assert!(
        stderr.contains(&port.to_string()),
        "the refusal must name the held port {port}, got: {stderr}"
    );

    assert!(
        a.0.try_wait().unwrap().is_none(),
        "the first forwarder died"
    );
    assert!(
        peer_face_port(&client, hub_addr.port()).await == Some(port),
        "the first forwarder lost its peer face"
    );
}
