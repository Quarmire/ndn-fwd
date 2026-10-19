//! The nodes of one scenario: their directories, configs, daemons and
//! producers, plus readers for the state the harness asserts on (held
//! trust-context versions, certificates in a PIB).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::nat::Nat;
use crate::run::{Op, Proc};
use crate::shim::Shim;

pub const PORT: u16 = 6363;
/// UDP port of the QUIC link listener (`[[face]] kind = "quic"`).
pub const QUIC_PORT: u16 = 6367;

/// `10.200.0.<n>`: the addresses the namespace's `lo` carries. Not loopback
/// (127/8), so faces between them are non-local and every Data is validated.
pub fn addr(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 200, 0, n)
}

/// Where the binaries under test live.
#[derive(Clone, Debug)]
pub struct Bins {
    pub dir: PathBuf,
    /// Whether a second local uid (1, through `setpriv`) exists in the
    /// namespace: the daemons' peer-credential checks see it as another user.
    pub foreign_uid: bool,
}

impl Bins {
    pub fn op(&self, tool: &str) -> Op {
        Op::new(tool, self.dir.join(tool))
    }
}

/// `[ca]` of a node that runs the namespace CA.
#[derive(Clone, Debug)]
pub struct CaCfg {
    pub prefix: String,
    pub identity: String,
    pub tokens: Vec<String>,
    /// `[ca.cert_validity_days] member`: a short per-role lifetime.
    pub member_days: Option<u32>,
}

/// The parts of `ndn-fwd.toml` the scenarios vary.
#[derive(Clone, Debug, Default)]
pub struct NodeCfg {
    /// Point-to-point UDP faces, in order: `[[face]]` index 1.. (0 is the
    /// listener).
    pub links: Vec<(String, Ipv4Addr)>,
    /// `(prefix, link name)`.
    pub routes: Vec<(String, String)>,
    pub identity: Option<String>,
    pub ca: Option<CaCfg>,
    pub refresh_secs: u64,
    pub context_sync: bool,
    /// `[[face]] kind = "quic"` on this node's address, [`QUIC_PORT`].
    pub quic_listen: bool,
    /// `[[face]] kind = "quic"` with `listen = false` on this node's
    /// address (port 0): links are dialled from it, none accepted.
    pub quic_dial_only: bool,
    /// `[[peer]]` entries: QUIC links this node dials.
    pub peers: Vec<PeerCfg>,
    /// Further config, appended verbatim (e.g. `[relay_service]`).
    pub extra_toml: String,
}

/// One `[[peer]]`.
#[derive(Clone, Debug, Default)]
pub struct PeerCfg {
    /// `device = "/<ns>/<role>/<device>"`.
    pub device: Option<String>,
    /// `key = "<expected fingerprint>"`.
    pub key: Option<String>,
    /// `endpoint = "10.200.0.<host>:<QUIC_PORT>"`.
    pub endpoint: Option<Ipv4Addr>,
    /// `relay = "<device or key of another [[peer]]>"`: reach this peer
    /// through that one (and punch a direct path to it).
    pub relay: Option<String>,
    /// `routes = [...]`: prefixes routed to this peer.
    pub routes: Vec<String>,
}

impl PeerCfg {
    fn render(&self) -> String {
        let mut s = String::from("[[peer]]\n");
        if let Some(d) = &self.device {
            s.push_str(&format!("device = \"{d}\"\n"));
        }
        if let Some(k) = &self.key {
            s.push_str(&format!("key = \"{k}\"\n"));
        }
        if let Some(ip) = self.endpoint {
            s.push_str(&format!("endpoint = \"{ip}:{QUIC_PORT}\"\n"));
        }
        if let Some(r) = &self.relay {
            s.push_str(&format!("relay = \"{r}\"\n"));
        }
        if !self.routes.is_empty() {
            let routes: Vec<String> = self.routes.iter().map(|r| format!("\"{r}\"")).collect();
            s.push_str(&format!("routes = [{}]\n", routes.join(", ")));
        }
        s
    }

    /// The touchpoint: what the operator wrote.
    fn setting(&self) -> String {
        let mut parts = Vec::new();
        if let Some(d) = &self.device {
            parts.push(format!("device {d}"));
        }
        if self.key.is_some() {
            parts.push("expected fingerprint (64 hex digits)".to_owned());
        }
        if let Some(ip) = self.endpoint {
            parts.push(format!("endpoint {ip}:{QUIC_PORT}"));
        }
        if self.relay.is_some() {
            parts.push("relay (another [[peer]])".to_owned());
        }
        if !self.routes.is_empty() {
            parts.push(format!("routes {}", self.routes.join(" ")));
        }
        format!("config: [[peer]] {}", parts.join(", "))
    }
}

pub struct Node {
    pub name: String,
    pub dir: PathBuf,
    /// The address its faces bind to: `10.200.0.<n>` on the shared `lo`,
    /// or its LAN address behind a NAT box.
    pub ip: Ipv4Addr,
    /// The network namespace its daemon runs in (behind a NAT box); `None`:
    /// the harness's own.
    pub netns: Option<PathBuf>,
    pub cfg: NodeCfg,
    pub daemon: Option<Proc>,
    pub started_at: Option<Instant>,
    /// Operator settings of the config last started with (touchpoints are
    /// what changed).
    pub last_settings: Vec<String>,
}

impl Node {
    pub fn pib(&self) -> PathBuf {
        self.dir.join("pib")
    }
    pub fn sock(&self) -> PathBuf {
        self.dir.join("fwd.sock")
    }
    pub fn config(&self) -> PathBuf {
        self.dir.join("fwd.toml")
    }
    pub fn log(&self) -> PathBuf {
        self.dir.join("fwd.log")
    }
    pub fn cfg_arg(&self) -> String {
        self.config().display().to_string()
    }

    fn face_index(&self, link: &str) -> usize {
        1 + self
            .cfg
            .links
            .iter()
            .position(|(n, _)| n == link)
            .unwrap_or_else(|| panic!("{}: no link named {link}", self.name))
    }

    pub fn render(&self) -> String {
        let c = &self.cfg;
        let mut s = String::new();
        s.push_str(&format!(
            "[[face]]\nkind = \"udp\"\nbind = \"{}:{PORT}\"\n\n",
            self.ip
        ));
        for (_, ip) in &c.links {
            s.push_str(&format!(
                "[[face]]\nkind = \"udp\"\nbind = \"{}:{PORT}\"\nremote = \"{ip}:{PORT}\"\n\n",
                self.ip
            ));
        }
        for (prefix, link) in &c.routes {
            s.push_str(&format!(
                "[[route]]\nprefix = \"{prefix}\"\nface = {}\n\n",
                self.face_index(link)
            ));
        }
        // After the UDP faces, so `[[route]]` indices stay as they are.
        if c.quic_listen {
            s.push_str(&format!(
                "[[face]]\nkind = \"quic\"\nbind = \"{}:{QUIC_PORT}\"\n\n",
                self.ip
            ));
        }
        if c.quic_dial_only {
            s.push_str(&format!(
                "[[face]]\nkind = \"quic\"\nbind = \"{}:0\"\nlisten = false\n\n",
                self.ip
            ));
        }
        for peer in &c.peers {
            s.push_str(&peer.render());
            s.push('\n');
        }
        s.push_str(&format!(
            "[management]\nface_socket = \"{}\"\n\n",
            self.sock().display()
        ));
        s.push_str("[security]\n");
        if let Some(id) = &c.identity {
            s.push_str(&format!("identity = \"{id}\"\n"));
        }
        s.push_str(&format!("pib_path = \"{}\"\n", self.pib().display()));
        s.push_str(&format!("context_refresh_secs = {}\n", c.refresh_secs));
        s.push_str(&format!("context_sync = {}\n\n", c.context_sync));
        if let Some(ca) = &c.ca {
            let toks: Vec<String> = ca.tokens.iter().map(|t| format!("\"{t}\"")).collect();
            s.push_str(&format!(
                "[ca]\nenabled = true\nprefix = \"{}\"\nidentity = \"{}\"\ntokens = [{}]\n\n",
                ca.prefix,
                ca.identity,
                toks.join(", ")
            ));
            if let Some(d) = ca.member_days {
                s.push_str(&format!("[ca.cert_validity_days]\nmember = {d}\n\n"));
            }
        }
        // NDN_E2E_LOG overrides the daemons' tracing filter (e.g. "info,security=debug").
        let level = std::env::var("NDN_E2E_LOG").unwrap_or_else(|_| "info".to_owned());
        s.push_str(&format!(
            "[discovery]\nenabled = false\n\n[logging]\nlevel = \"{level}\"\n"
        ));
        if !c.extra_toml.is_empty() {
            s.push('\n');
            s.push_str(&c.extra_toml);
            s.push('\n');
        }
        s
    }

    /// What an operator had to put into this config, as touchpoint labels.
    pub fn settings(&self) -> Vec<String> {
        let c = &self.cfg;
        let mut v = Vec::new();
        for (peer, ip) in &c.links {
            v.push(format!("config: [[face]] link to {peer} ({ip})"));
        }
        for (prefix, link) in &c.routes {
            v.push(format!("config: [[route]] {prefix} -> {link}"));
        }
        if c.quic_listen {
            v.push(format!("config: [[face]] kind = \"quic\" (listen for links on {}:{QUIC_PORT})", self.ip));
        }
        if c.quic_dial_only {
            v.push(format!("config: [[face]] kind = \"quic\" listen = false (dial links from {})", self.ip));
        }
        for peer in &c.peers {
            v.push(peer.setting());
        }
        if let Some(id) = &c.identity {
            v.push(format!(
                "config: [security] identity = {id} (lines printed by init/recover)"
            ));
        }
        if let Some(ca) = &c.ca {
            v.push(format!("config: [ca] namespace CA {} (identity {})", ca.prefix, ca.identity));
            v.push(format!("config: [ca] tokens ({} invite tokens)", ca.tokens.len()));
            if let Some(d) = ca.member_days {
                v.push(format!("config: [ca.cert_validity_days] member = {d}"));
            }
        }
        v.push(format!(
            "config: [security] context_refresh_secs = {}",
            c.refresh_secs
        ));
        if c.context_sync {
            v.push("config: [security] context_sync = true".to_owned());
        }
        for line in c.extra_toml.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            v.push(format!("config: {line}"));
        }
        v
    }
}

/// All nodes, producers, shims and NAT boxes of one scenario. Dropping it
/// stops them all.
pub struct World {
    pub dir: PathBuf,
    pub bins: Bins,
    pub nodes: BTreeMap<String, Node>,
    pub producers: Vec<(String, Proc)>,
    pub shims: Vec<Shim>,
    /// NAT boxes, torn down after the daemons in them stop.
    pub nat: Option<Nat>,
    seq: u32,
}

impl World {
    pub fn new(dir: PathBuf, bins: Bins) -> Self {
        let _ = fs::create_dir_all(&dir);
        World {
            dir,
            bins,
            nodes: BTreeMap::new(),
            producers: Vec::new(),
            shims: Vec::new(),
            nat: None,
            seq: 0,
        }
    }

    pub fn add(&mut self, name: &str, host: u8, cfg: NodeCfg) {
        self.insert(name, addr(host), None, cfg);
    }

    /// A node whose daemon runs on the LAN of NAT box `nat_box` (see
    /// [`Nat::add_box`]), its faces bound to its LAN address.
    pub fn add_behind(&mut self, name: &str, nat_box: u8, cfg: NodeCfg) {
        let b = self.nat.as_ref().expect("add_behind: no NAT boxes").nat_box(nat_box);
        let (ip, netns) = (b.device_ip, b.device_netns());
        self.insert(name, ip, Some(netns), cfg);
    }

    fn insert(&mut self, name: &str, ip: Ipv4Addr, netns: Option<PathBuf>, cfg: NodeCfg) {
        let dir = self.dir.join(name);
        fs::create_dir_all(&dir).expect("node dir");
        self.nodes.insert(
            name.to_owned(),
            Node {
                name: name.to_owned(),
                dir,
                ip,
                netns,
                cfg,
                daemon: None,
                started_at: None,
                last_settings: Vec::new(),
            },
        );
    }

    pub fn node(&self, name: &str) -> &Node {
        self.nodes
            .get(name)
            .unwrap_or_else(|| panic!("no node {name}"))
    }

    pub fn node_mut(&mut self, name: &str) -> &mut Node {
        self.nodes
            .get_mut(name)
            .unwrap_or_else(|| panic!("no node {name}"))
    }

    pub fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Write the config and start the daemon; ready once its management
    /// socket accepts a connection.
    pub fn start(&mut self, name: &str) -> Result<(), String> {
        let op = {
            let n = self.node(name);
            if n.daemon.is_some() {
                return Err(format!("{name}: daemon already running"));
            }
            fs::write(n.config(), n.render()).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(n.sock());
            let _ = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(n.log())
                .and_then(|mut f| f.write_all(b"----- harness: daemon start -----\n"));
            let op = self.bins.op("ndn-fwd").arg("-c").arg(n.cfg_arg());
            match &n.netns {
                Some(ns) => op.in_netns(ns.clone()),
                None => op,
            }
        };
        let (sock, log) = {
            let n = self.node(name);
            (n.sock(), n.log())
        };
        let mut proc = op.spawn_logged(&log, name)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if UnixStream::connect(&sock).is_ok() {
                break;
            }
            if !proc.alive() {
                return Err(format!("{name}: daemon exited during start"));
            }
            if Instant::now() > deadline {
                return Err(format!("{name}: management socket not ready within 20 s"));
            }
            thread::sleep(Duration::from_millis(50));
        }
        let n = self.node_mut(name);
        n.daemon = Some(proc);
        n.started_at = Some(Instant::now());
        Ok(())
    }

    /// Stop the daemon and every producer attached to it.
    pub fn stop(&mut self, name: &str) {
        self.stop_producers(name);
        if let Some(mut d) = self.node_mut(name).daemon.take() {
            d.stop();
        }
    }

    pub fn stop_producers(&mut self, name: &str) {
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.producers)
            .into_iter()
            .partition(|(n, _)| n == name);
        self.producers = rest;
        drop(mine);
    }

    /// Log files worth showing when a step fails.
    pub fn logs(&self) -> Vec<(String, PathBuf)> {
        let mut v: Vec<(String, PathBuf)> = self
            .nodes
            .values()
            .filter(|n| n.log().exists())
            .map(|n| (format!("{} daemon", n.name), n.log()))
            .collect();
        for (n, p) in &self.producers {
            v.push((format!("{n} producer {}", p.label), p.log.clone()));
        }
        v
    }

    /// The newest trust-context version of `ns` held in `node`'s PIB.
    pub fn held_version(&self, node: &str, ns: &str) -> Option<u64> {
        held_version(&self.node(node).pib(), ns)
    }

    /// Certificate names in a PIB (`ndn-sec list`).
    pub fn certs(&self, node: &str) -> Vec<String> {
        certs_in(&self.bins, &self.node(node).pib())
    }

    /// Key names in a PIB, with or without a certificate (`ndn-sec list`).
    pub fn keys(&self, node: &str) -> Vec<String> {
        keys_in(&self.bins, &self.node(node).pib())
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.producers.clear();
        for n in self.nodes.values_mut() {
            if let Some(mut d) = n.daemon.take() {
                d.stop();
            }
        }
        self.shims.clear();
        // After the daemons: the namespaces they ran in go with the boxes.
        self.nat = None;
    }
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// `<pib>/contexts/<hex(ns)>.versions/<N>.tc`: the largest N.
pub fn held_version(pib: &Path, ns: &str) -> Option<u64> {
    let dir = pib.join("contexts").join(format!("{}.versions", hex(ns)));
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_suffix(".tc")?
                .parse::<u64>()
                .ok()
        })
        .max()
}

pub fn certs_in(bins: &Bins, pib: &Path) -> Vec<String> {
    if !pib.exists() {
        return Vec::new();
    }
    let out = bins
        .op("ndn-sec")
        .arg("--pib")
        .arg(pib.display().to_string())
        .arg("list")
        .run();
    out.stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("cert "))
        .map(|s| s.trim().to_owned())
        .collect()
}

pub fn keys_in(bins: &Bins, pib: &Path) -> Vec<String> {
    if !pib.exists() {
        return Vec::new();
    }
    let out = bins
        .op("ndn-sec")
        .arg("--pib")
        .arg(pib.display().to_string())
        .arg("list")
        .run();
    out.stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .map(str::to_owned)
        .collect()
}

/// Seconds since the Unix epoch of `YYYY-MM-DDTHH:MM:SSZ`.
pub fn parse_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, time) = s.strip_suffix('Z')?.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>());
    let (y, m, dd) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split(':').map(|x| x.parse::<i64>());
    let (hh, mm, ss) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    // days_from_civil (H. Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One TLV at the front of `b`: (type, value, rest).
fn tlv(b: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    fn var(b: &[u8]) -> Option<(u64, &[u8])> {
        let (&f, r) = b.split_first()?;
        let n = match f {
            253 => 2,
            254 => 4,
            255 => 8,
            v => return Some((u64::from(v), r)),
        };
        let (x, r) = (r.get(..n)?, r.get(n..)?);
        Some((x.iter().fold(0u64, |a, &d| (a << 8) | u64::from(d)), r))
    }
    let (t, r) = var(b)?;
    let (l, r) = var(r)?;
    let l = usize::try_from(l).ok()?;
    Some((t, r.get(..l)?, r.get(l..)?))
}

/// The KeyLocator name of a certificate (a Data packet), as a URI of its
/// generic components: the key that issued it.
pub fn issuer_of(data: &[u8]) -> Option<String> {
    let (0x06, mut body, _) = tlv(data)? else { return None };
    while let Some((t, v, rest)) = tlv(body) {
        body = rest;
        if t != 0x16 {
            continue; // SignatureInfo
        }
        let mut si = v;
        while let Some((t, v, rest)) = tlv(si) {
            si = rest;
            if t != 0x1c {
                continue; // KeyLocator
            }
            let (0x07, mut name, _) = tlv(v)? else { return None };
            let mut uri = String::new();
            while let Some((_, c, rest)) = tlv(name) {
                name = rest;
                uri.push('/');
                uri.push_str(&String::from_utf8_lossy(c));
            }
            return Some(uri);
        }
    }
    None
}

/// The issuers (KeyLocator key names) of every certificate in a PIB's keys.
pub fn cert_issuers(pib: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for k in fs::read_dir(pib.join("keys")).into_iter().flatten().flatten() {
        for c in fs::read_dir(k.path().join("certs")).into_iter().flatten().flatten() {
            if let Some(i) = fs::read(c.path()).ok().and_then(|d| issuer_of(&d)) {
                v.push(i);
            }
        }
    }
    v
}
