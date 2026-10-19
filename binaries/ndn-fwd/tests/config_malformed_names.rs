//! Regression: a `[[route]]` or `[[strategy]]` whose prefix is not a valid NDN
//! name must be refused, never installed on the root name `/`. Before the fix a
//! typo such as `prefix = "muas"` (missing the leading slash) became a static
//! route for `/` — every Interest with no better match went out that face — and
//! a typo'd `[[strategy]]` prefix replaced the forwarder-wide default strategy.

use std::process::Command;
use std::time::Duration;

use ndn_ipc::MgmtClient;
use ndn_packet::Name;

/// RIB origin for config / `nfdc route add` routes.
const ORIGIN_STATIC: u64 = 255;

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
async fn malformed_config_prefix_is_refused_not_rooted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("fwd.sock");
    let conf = dir.path().join("fwd.toml");

    std::fs::write(
        &conf,
        format!(
            "[management]\nface_socket = \"{sock}\"\n\n\
             [[face]]\nkind = \"udp\"\nbind = \"127.0.0.1:0\"\nremote = \"127.0.0.1:9\"\n\n\
             [[route]]\nprefix = \"muas\"\nface = 0\n\n\
             [[route]]\nprefix = \"/valid\"\nface = 0\n\n\
             [[strategy]]\nprefix = \"muas\"\nstrategy = \"/localhost/nfd/strategy/multicast\"\n",
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

    let (rib, strategies) = {
        let client = MgmtClient::connect(sock.to_str().unwrap())
            .await
            .expect("connect");
        (client.rib_list().await, client.strategy_list().await)
    };

    let _ = child.kill();
    let _ = child.wait();

    let rib = rib.expect("rib/list");
    let static_route_on = |name: &Name| {
        rib.iter()
            .filter(|e| &e.name == name)
            .flat_map(|e| &e.routes)
            .any(|r| r.origin == ORIGIN_STATIC)
    };
    assert!(
        static_route_on(&ndn_packet::name!("/valid")),
        "the well-formed config route must be installed, got {rib:?}"
    );
    assert!(
        !static_route_on(&Name::root()),
        "a malformed config route prefix must not become a static route for `/`, got {rib:?}"
    );

    let strategies = strategies.expect("strategy-choice/list");
    assert!(
        !strategies
            .iter()
            .any(|c| c.name == Name::root() && c.strategy.to_string().contains("/multicast")),
        "a malformed [[strategy]] prefix must not replace the root strategy, got {strategies:?}"
    );
}
