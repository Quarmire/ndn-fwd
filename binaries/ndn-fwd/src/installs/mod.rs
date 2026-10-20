//! Per-protocol install adapters. Each protocol's `prepare` helper runs
//! async pre-build work (UDP binds, anchor reads) and returns an
//! installer implementing [`ndn_engine::InstallableProtocol`]; the
//! installer wires `InProcFace` pairs and queues post-build FIB writes,
//! neighbour seeds, and Producer `serve` tasks via
//! [`ndn_engine::PostBuildQueue`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod dv;
pub mod nlsr;

/// The local address a routing protocol's neighbour face to `peer` binds:
/// the IP of this forwarder's first UDP listener (`[[face]] kind = "udp"`
/// without `remote`) of `peer`'s family, on an ephemeral port. Its datagrams
/// then leave from the address the forwarder listens on, the one its
/// neighbours name it by, so on a host where several forwarders each listen
/// on their own address a neighbour tells them apart: the engine never
/// forwards an Interest back to the node (peer IP) it came from, and with
/// every neighbour socket sending from the address the OS picks, two such
/// forwarders are one node to their common neighbour, which then forwards
/// nothing between them. Unspecified (the OS picks the address that routes
/// to `peer`) when that listener is on every address, or there is none.
pub(crate) fn neighbour_bind(faces: &[ndn_config::FaceConfig], peer: SocketAddr) -> SocketAddr {
    let unspecified = if peer.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let ip = faces
        .iter()
        .filter_map(|f| match f {
            ndn_config::FaceConfig::Udp { bind, remote: None } => bind
                .as_deref()
                .unwrap_or("0.0.0.0:6363")
                .parse::<SocketAddr>()
                .ok(),
            _ => None,
        })
        .find(|l| l.is_ipv4() == peer.is_ipv4())
        .map_or(unspecified, |l| l.ip());
    SocketAddr::new(ip, 0)
}

#[cfg(test)]
mod tests {
    use super::neighbour_bind;

    fn bind(toml: &str, peer: &str) -> String {
        let cfg: ndn_config::ForwarderConfig = toml.parse().unwrap();
        neighbour_bind(&cfg.faces, peer.parse().unwrap()).to_string()
    }

    /// A neighbour face leaves from its family's first listener's IP; from
    /// the address the OS picks when that listener is on every address or
    /// none of that family listens.
    #[test]
    fn a_neighbour_face_leaves_from_the_listeners_address() {
        let on_ip = "[[face]]\nkind = \"udp\"\nbind = \"10.0.0.2:6363\"\n\n\
                     [[face]]\nkind = \"udp\"\nbind = \"10.0.0.2:6363\"\nremote = \"10.0.0.9:6363\"\n";
        assert_eq!(bind(on_ip, "10.0.0.1:6363"), "10.0.0.2:0");
        assert_eq!(bind(on_ip, "[fd00::1]:6363"), "[::]:0");
        let everywhere = "[[face]]\nkind = \"udp\"\n\n\
                          [[face]]\nkind = \"udp\"\nbind = \"10.0.0.2:6363\"\n";
        assert_eq!(bind(everywhere, "10.0.0.1:6363"), "0.0.0.0:0");
        assert_eq!(bind("", "10.0.0.1:6363"), "0.0.0.0:0");
        let v6 = "[[face]]\nkind = \"udp\"\nbind = \"[fd00::2]:6363\"\n";
        assert_eq!(bind(v6, "[fd00::1]:6363"), "[fd00::2]:0");
    }
}
