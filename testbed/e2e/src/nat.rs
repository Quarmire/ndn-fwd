//! NAT boxes inside the harness's network namespace, for direct-path
//! scenarios: the harness's namespace is "the internet" (it routes between
//! the boxes and carries the public nodes on `lo`), each box is a network
//! namespace that masquerades its LAN behind its public address, and each
//! box's LAN holds one device namespace a daemon runs in.
//!
//! Box `k` (1, 2, …):
//! - `w<k>` (harness, 10.0.k.1/24) ↔ `wan` (box, 10.0.k.2/24, default route
//!   via 10.0.k.1): 10.0.k.2 is the box's public address;
//! - `lan` (box, 192.168.k.1/24) ↔ `eth0` (device, 192.168.k.2/24, default
//!   route via 192.168.k.1);
//! - nftables in the box: `masquerade` out of `wan` (cone: a LAN socket
//!   keeps its public port whatever it sends to, so a punched hole is
//!   reachable from the peer's probes) or `masquerade random,fully-random`
//!   (symmetric: every destination gets another public port, so the
//!   address the relay saw is useless to a peer), and a stateful firewall
//!   dropping whatever arrives on `wan` unsolicited (`ct state new`). The
//!   drop matters for cone boxes: an unsolicited inbound packet that went
//!   through would leave a conntrack entry that makes masquerade pick
//!   another port for the device's own probe.
//!
//! Namespaces are held by `unshare --net sleep infinity` processes and
//! entered with `nsenter --net=/proc/<pid>/ns/net`; that needs `/proc` to
//! be the harness's PID namespace's own (`unshare --mount-proc`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
/// The harness-side table [`Nat::cut`] adds and [`Nat::heal`] deletes.
const CUT_TABLE: &str = "e2e_cut";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// Port-restricted cone: endpoint-independent mapping, filtering of
    /// unsolicited inbound traffic. Hole punching works.
    Cone,
    /// Symmetric: a new public port per destination. Hole punching between
    /// two of them fails.
    Symmetric,
}

impl NatKind {
    fn masquerade(self) -> &'static str {
        match self {
            NatKind::Cone => "masquerade",
            NatKind::Symmetric => "masquerade random,fully-random",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            NatKind::Cone => "cone",
            NatKind::Symmetric => "symmetric",
        }
    }
}

/// A process holding a network namespace of its own.
struct Holder {
    child: Child,
}

impl Holder {
    fn new() -> Result<Holder, String> {
        let child = Command::new("unshare")
            .args(["--net", "--", "sleep", "infinity"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("unshare --net: {e}"))?;
        let mut h = Holder { child };
        // unshare(2) runs before it execs sleep: wait until the process
        // is in a namespace other than ours.
        let ours = fs::read_link("/proc/self/ns/net").map_err(|e| format!("/proc/self/ns/net: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if fs::read_link(h.netns()).is_ok_and(|ns| ns != ours) {
                return Ok(h);
            }
            if !matches!(h.child.try_wait(), Ok(None)) {
                return Err("`unshare --net sleep infinity` exited: cannot create a network namespace".into());
            }
            if Instant::now() > deadline {
                return Err(format!("{} did not enter a new network namespace within 5 s", h.netns().display()));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn netns(&self) -> PathBuf {
        PathBuf::from(format!("/proc/{}/ns/net", self.pid()))
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One NAT box and the device namespace on its LAN.
pub struct NatBox {
    pub index: u8,
    pub kind: NatKind,
    /// The box's address on the "internet" (its `wan`): what peers and the
    /// relay see a device behind it as.
    pub public: Ipv4Addr,
    /// The device's address on the box's LAN.
    pub device_ip: Ipv4Addr,
    // Field order: the device namespace goes before the box's.
    device: Holder,
    gateway: Holder,
}

impl NatBox {
    /// `/proc/<pid>/ns/net` of the device namespace: where a daemon behind
    /// this box runs.
    pub fn device_netns(&self) -> PathBuf {
        self.device.netns()
    }

    fn netns(&self) -> PathBuf {
        self.gateway.netns()
    }

    fn harness_if(&self) -> String {
        format!("w{}", self.index)
    }
}

pub struct Nat {
    dir: PathBuf,
    log: PathBuf,
    boxes: Vec<NatBox>,
    /// `ip_forward` of the harness's namespace before, restored on drop.
    forward_was: String,
    cut: bool,
}

impl Nat {
    /// Why NAT boxes cannot be built here, if they cannot.
    pub fn missing() -> Option<String> {
        let works = |prog: &str| {
            Command::new(prog)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        if !works("nft") {
            return Some(
                "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`".into(),
            );
        }
        if !works("nsenter") {
            return Some("nsenter (util-linux) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`".into());
        }
        let own_proc = fs::read_link("/proc/self")
            .ok()
            .and_then(|p| p.to_str().and_then(|s| s.parse::<u32>().ok()))
            == Some(std::process::id());
        if !own_proc {
            return Some(
                "/proc is not the harness's PID namespace's own (unshare without --mount-proc), so \
                 /proc/<pid>/ns/net names no namespace of ours"
                    .into(),
            );
        }
        None
    }

    /// Turn the harness's namespace into a router; boxes are added with
    /// [`Nat::add_box`]. `dir` gets the rulesets and `nat.log` (every
    /// command run, with its output).
    pub fn new(dir: PathBuf) -> Result<Nat, String> {
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let forward_was = fs::read_to_string(FORWARD).map_err(|e| format!("{FORWARD}: {e}"))?;
        fs::write(FORWARD, "1").map_err(|e| format!("{FORWARD}: {e}"))?;
        Ok(Nat {
            log: dir.join("nat.log"),
            dir,
            boxes: Vec::new(),
            forward_was,
            cut: false,
        })
    }

    /// Run `argv` in `netns` (`None`: the harness's namespace).
    fn run(&self, netns: Option<&Path>, argv: &[&str]) -> Result<String, String> {
        let mut full: Vec<String> = Vec::new();
        if let Some(ns) = netns {
            full.extend(["nsenter".to_owned(), format!("--net={}", ns.display()), "--".to_owned()]);
        }
        full.extend(argv.iter().map(|s| (*s).to_owned()));
        let line = full.join(" ");
        let out = Command::new(&full[0])
            .args(&full[1..])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("{line}: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.log) {
            let _ = writeln!(f, "$ {line}\n  -> {}\n{stdout}{stderr}", out.status);
        }
        if out.status.success() {
            Ok(stdout)
        } else {
            Err(format!("{line}: {} {}", out.status, stderr.trim()))
        }
    }

    /// Build box `k` (the next index) with a device namespace on its LAN.
    pub fn add_box(&mut self, kind: NatKind) -> Result<u8, String> {
        let k = u8::try_from(self.boxes.len() + 1).map_err(|_| "too many NAT boxes")?;
        let gateway = Holder::new()?;
        let device = Holder::new()?;
        let b = NatBox {
            index: k,
            kind,
            public: Ipv4Addr::new(10, 0, k, 2),
            device_ip: Ipv4Addr::new(192, 168, k, 2),
            device,
            gateway,
        };
        let (gw, dev) = (b.netns(), b.device_netns());
        let (gw, dev) = (Some(gw.as_path()), Some(dev.as_path()));
        let w = b.harness_if();
        let up = format!("10.0.{k}.1");
        let lan_gw = format!("192.168.{k}.1");

        // The box's wan, from the harness's side.
        self.run(None, &["ip", "link", "add", &w, "type", "veth", "peer", "name", "wan", "netns", &b.gateway.pid().to_string()])?;
        self.run(None, &["ip", "addr", "add", &format!("{up}/24"), "dev", &w])?;
        self.run(None, &["ip", "link", "set", &w, "up"])?;
        // The box.
        self.run(gw, &["ip", "link", "set", "lo", "up"])?;
        self.run(gw, &["ip", "addr", "add", &format!("{}/24", b.public), "dev", "wan"])?;
        self.run(gw, &["ip", "link", "set", "wan", "up"])?;
        self.run(gw, &["ip", "route", "add", "default", "via", &up])?;
        self.run(gw, &["ip", "link", "add", "lan", "type", "veth", "peer", "name", "eth0", "netns", &b.device.pid().to_string()])?;
        self.run(gw, &["ip", "addr", "add", &format!("{lan_gw}/24"), "dev", "lan"])?;
        self.run(gw, &["ip", "link", "set", "lan", "up"])?;
        // /proc/sys/net is the reader's namespace's, so write it from inside.
        self.run(gw, &["sh", "-c", &format!("echo 1 > {FORWARD}")])?;
        // The device.
        self.run(dev, &["ip", "link", "set", "lo", "up"])?;
        self.run(dev, &["ip", "addr", "add", &format!("{}/24", b.device_ip), "dev", "eth0"])?;
        self.run(dev, &["ip", "link", "set", "eth0", "up"])?;
        self.run(dev, &["ip", "route", "add", "default", "via", &lan_gw])?;
        // NAT and the stateful firewall. (`fwd` is an nft keyword.)
        let ruleset = format!(
            "table ip nat {{\n\
             \tchain post {{\n\
             \t\ttype nat hook postrouting priority 100;\n\
             \t\toifname \"wan\" {};\n\
             \t}}\n\
             }}\n\
             table inet fw {{\n\
             \tchain input {{\n\
             \t\ttype filter hook input priority 0;\n\
             \t\tiifname \"wan\" ct state new drop;\n\
             \t}}\n\
             \tchain forward_filter {{\n\
             \t\ttype filter hook forward priority 0;\n\
             \t\tiifname \"wan\" ct state new drop;\n\
             \t}}\n\
             }}\n",
            kind.masquerade()
        );
        let file = self.dir.join(format!("box{k}.nft"));
        fs::write(&file, ruleset).map_err(|e| format!("{}: {e}", file.display()))?;
        self.run(gw, &["nft", "-f", &file.display().to_string()])?;
        self.boxes.push(b);
        Ok(k)
    }

    pub fn nat_box(&self, k: u8) -> &NatBox {
        self.boxes
            .iter()
            .find(|b| b.index == k)
            .unwrap_or_else(|| panic!("no NAT box {k}"))
    }

    /// Drop UDP between the public addresses of boxes `a` and `b`, both
    /// ways, where the harness's namespace forwards it: whatever path the
    /// devices behind them punched dies, their paths to the relay stay.
    pub fn cut(&mut self, a: u8, b: u8) -> Result<(), String> {
        let (pa, pb) = (self.nat_box(a).public, self.nat_box(b).public);
        let ruleset = format!(
            "table inet {CUT_TABLE} {{\n\
             \tchain forward {{\n\
             \t\ttype filter hook forward priority 0;\n\
             \t\tip saddr {pa} ip daddr {pb} meta l4proto udp drop;\n\
             \t\tip saddr {pb} ip daddr {pa} meta l4proto udp drop;\n\
             \t}}\n\
             }}\n"
        );
        let file = self.dir.join("cut.nft");
        fs::write(&file, ruleset).map_err(|e| format!("{}: {e}", file.display()))?;
        self.run(None, &["nft", "-f", &file.display().to_string()])?;
        self.cut = true;
        Ok(())
    }

    /// Undo [`Nat::cut`].
    pub fn heal(&mut self) -> Result<(), String> {
        self.run(None, &["nft", "delete", "table", "inet", CUT_TABLE])?;
        self.cut = false;
        Ok(())
    }

    /// Count UDP that box `k` forwards from its LAN to `dst`, in the named
    /// counter `name` (read with [`Nat::counter`]).
    pub fn count_udp_to(&self, k: u8, name: &str, dst: Ipv4Addr) -> Result<(), String> {
        let gw = self.nat_box(k).netns();
        self.run(Some(&gw), &["nft", "add", "counter", "inet", "fw", name])?;
        self.run(
            Some(&gw),
            &[
                "nft", "add", "rule", "inet", "fw", "forward_filter", "iifname", "lan", "ip", "daddr",
                &dst.to_string(), "meta", "l4proto", "udp", "counter", "name", name,
            ],
        )?;
        Ok(())
    }

    /// Packets counted by box `k`'s counter `name`.
    pub fn counter(&self, k: u8, name: &str) -> Result<u64, String> {
        let gw = self.nat_box(k).netns();
        let out = self.run(Some(&gw), &["nft", "list", "counter", "inet", "fw", name])?;
        let mut words = out.split_whitespace();
        words
            .by_ref()
            .find(|w| *w == "packets")
            .and_then(|_| words.next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("no packet count in `nft list counter inet fw {name}`: {out}"))
    }
}

impl Drop for Nat {
    fn drop(&mut self) {
        if self.cut {
            let _ = self.run(None, &["nft", "delete", "table", "inet", CUT_TABLE]);
        }
        for b in &self.boxes {
            // Deleting one end of a veth deletes the pair, at once (a
            // namespace's own teardown is deferred).
            let _ = self.run(None, &["ip", "link", "del", &b.harness_if()]);
        }
        // Kills the holders; a namespace goes with its last process.
        self.boxes.clear();
        let _ = fs::write(FORWARD, self.forward_was.trim());
    }
}
