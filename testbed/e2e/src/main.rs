//! `ndn-e2e`: the end-to-end witness of the personal-namespace stack.
//!
//! Runs real `ndn-fwd` daemons and the operator CLIs (`ndn-fwd`,
//! `ndn-fwd-tokens`, `ndn-put`, `ndn-peek`, `ndn-ctl`, `ndn-sec`) through
//! whole scenarios and asserts observable outcomes: exit status, bytes
//! fetched, versions held, certificates in a PIB, files present or absent —
//! never message wording.
//!
//! Two processes:
//! - the outer one builds the binaries, then starts `unshare` with a new
//!   user, network, mount and PID namespace (its own `/proc`) running this
//!   binary again with `--inner`, and waits (Ctrl-C kills the namespace);
//! - the inner one is PID 1 of that namespace: it adds 10.200.0.1-10 to its
//!   private `lo` and runs the scenarios (NAT boxes, where a scenario needs
//!   them, are nested network namespaces: `nat.rs`). When it exits —
//!   normally, by panic or killed — the kernel kills every process left in
//!   the namespace, so no daemon outlives a run.

mod nat;
mod run;
mod scenarios;
mod shim;
mod step;
mod world;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::step::Scenario;
use crate::world::{Bins, World, addr};

const USAGE: &str = "\
ndn-e2e: end-to-end run of the personal-namespace stack

USAGE: cargo run -p ndn-e2e -- [OPTIONS]

OPTIONS:
  --only <scenario>   run only this scenario (repeatable, or comma-separated)
  --keep              keep the run directory (configs, PIBs, daemon logs,
                      report.json) and print its path
  --no-build          do not run `cargo build` for the binaries under test
  --bin-dir <dir>     take the binaries from <dir> (implies --no-build)
  --list              list the scenarios and exit
  -h, --help          this help

SCENARIOS: lifecycle, lifecycle-push, recovery-destroyed,
           recovery-compromised, negatives, approval, quic-links,
           direct-paths, phone-links, relays, on-demand, membership,
           multi-prefix, tui, dv
";

#[derive(Clone, Debug, Default)]
struct Args {
    only: Vec<String>,
    keep: bool,
    no_build: bool,
    bin_dir: Option<PathBuf>,
    list: bool,
    inner: bool,
    run_dir: Option<PathBuf>,
    foreign_uid: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--only" => a
                .only
                .extend(value("--only")?.split(',').map(|s| s.trim().to_owned())),
            "--keep" => a.keep = true,
            "--no-build" => a.no_build = true,
            "--bin-dir" => a.bin_dir = Some(PathBuf::from(value("--bin-dir")?)),
            "--list" => a.list = true,
            "--inner" => a.inner = true,
            "--run-dir" => a.run_dir = Some(PathBuf::from(value("--run-dir")?)),
            "--foreign-uid" => a.foreign_uid = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    for s in &a.only {
        if !scenarios::ALL.contains(&s.as_str()) {
            return Err(format!(
                "unknown scenario {s}; known: {}",
                scenarios::ALL.join(", ")
            ));
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if args.list {
        for s in scenarios::ALL {
            println!("{s}");
        }
        return ExitCode::SUCCESS;
    }
    let r = if args.inner {
        inner(&args)
    } else {
        outer(&args)
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("ndn-e2e: {e}");
            ExitCode::from(2)
        }
    }
}

fn works(cmd: &mut Command) -> bool {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The binaries under test: built from the ndn-fwd workspace (a stale binary
/// would witness old behaviour) and found under its cargo target directory.
fn binaries(args: &Args) -> Result<PathBuf, String> {
    if let Some(d) = &args.bin_dir {
        return Ok(d.clone());
    }
    let ws = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !args.no_build {
        println!("ndn-e2e: building ndn-fwd, ndn-tools, ndn-fwd-tokens …");
        let ok = Command::new("cargo")
            .args([
                "build",
                "-p",
                "ndn-fwd",
                "-p",
                "ndn-tools",
                "-p",
                "ndn-fwd-tokens",
                "--bins",
            ])
            .current_dir(&ws)
            .status()
            .map_err(|e| format!("cargo: {e}"))?
            .success();
        if !ok {
            return Err("cargo build of the binaries under test failed".into());
        }
        // The app's side of phone-links: the ndn-boltffi FFI driven over
        // stdin, from the ndn-mobile workspace (same shared target dir).
        println!("ndn-e2e: building the ndn-boltffi phone host (ndn-mobile) …");
        let ok = Command::new("cargo")
            .args(["build", "-p", "ndn-boltffi", "--example", "phone_host"])
            .current_dir(ws.join("../ndn-mobile"))
            .status()
            .map_err(|e| format!("cargo: {e}"))?
            .success();
        if !ok {
            return Err("cargo build of the ndn-boltffi phone host failed".into());
        }
    }
    let meta = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(&ws)
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&meta.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
    let target = v["target_directory"]
        .as_str()
        .ok_or("cargo metadata: no target_directory")?;
    Ok(Path::new(target).join("debug"))
}

fn outer(args: &Args) -> Result<bool, String> {
    let bin_dir = binaries(args)?;
    for b in [
        "ndn-fwd",
        "ndn-fwd-tokens",
        "ndn-ctl",
        "ndn-put",
        "ndn-peek",
        "ndn-sec",
        "examples/phone_host",
    ] {
        if !bin_dir.join(b).is_file() {
            return Err(format!("{b} not found in {}", bin_dir.display()));
        }
    }
    if !works(Command::new("ip").arg("-V")) {
        return Err("`ip` (iproute2) is not on PATH; e.g. `nix-shell -p iproute2`".into());
    }
    // --mount-proc: /proc of the new PID namespace, so /proc/<pid>/ns/net
    // of a process started inside names it (nested namespaces, nat.rs).
    let base = [
        "--map-root-user",
        "--net",
        "--pid",
        "--mount-proc",
        "--fork",
    ];
    let foreign_uid = works(Command::new("unshare").arg("--map-auto").args(base).args([
        "setpriv",
        "--reuid=1",
        "--regid=1",
        "--clear-groups",
        "true",
    ]));
    if !foreign_uid && !works(Command::new("unshare").args(base).arg("true")) {
        return Err(
            "cannot create a user+network+mount+PID namespace (`unshare --map-root-user --net \
             --pid --mount-proc --fork true` fails): unprivileged user namespaces are disabled here"
                .into(),
        );
    }
    if !foreign_uid {
        println!(
            "ndn-e2e: note: `unshare --map-auto` or `setpriv` is unavailable (no subordinate \
             uids for this user, or no newuidmap): the other-local-user steps are skipped"
        );
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let run_dir = std::env::temp_dir().join(format!("ndn-e2e-{stamp}-{}", std::process::id()));
    fs::create_dir_all(&run_dir).map_err(|e| format!("{}: {e}", run_dir.display()))?;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("unshare");
    if foreign_uid {
        cmd.arg("--map-auto");
    }
    cmd.args(base)
        .arg("--kill-child")
        .arg("--")
        .arg(exe)
        .arg("--inner");
    cmd.arg("--run-dir")
        .arg(&run_dir)
        .arg("--bin-dir")
        .arg(&bin_dir);
    if foreign_uid {
        cmd.arg("--foreign-uid");
    }
    if args.keep {
        cmd.arg("--keep");
    }
    for s in &args.only {
        cmd.arg("--only").arg(s);
    }
    let mut child = cmd.spawn().map_err(|e| format!("unshare: {e}"))?;
    let pid = child.id();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let passed = rt.block_on(async move {
        let wait = tokio::task::spawn_blocking(move || child.wait());
        tokio::select! {
            r = wait => matches!(r, Ok(Ok(s)) if s.success()),
            _ = tokio::signal::ctrl_c() => {
                // unshare's death SIGKILLs the namespace's PID 1 (--kill-child),
                // and with it every process in the namespace.
                let _ = Command::new("kill").args(["-KILL", &pid.to_string()]).status();
                eprintln!("ndn-e2e: interrupted; the namespace and its daemons are gone");
                false
            }
        }
    });

    if args.keep {
        println!("ndn-e2e: run directory kept: {}", run_dir.display());
    } else if let Err(e) = fs::remove_dir_all(&run_dir) {
        eprintln!("ndn-e2e: could not remove {}: {e}", run_dir.display());
    }
    Ok(passed)
}

fn setup_network() -> Result<(), String> {
    let ip = |args: &[&str]| -> Result<(), String> {
        let out = Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("ip: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    };
    ip(&["link", "set", "lo", "up"])?;
    for n in 1..=10 {
        ip(&["addr", "add", &format!("{}/24", addr(n)), "dev", "lo"])?;
    }
    Ok(())
}

fn inner(args: &Args) -> Result<bool, String> {
    let run_dir = args.run_dir.clone().ok_or("--inner needs --run-dir")?;
    let bins = Bins {
        dir: args.bin_dir.clone().ok_or("--inner needs --bin-dir")?,
        foreign_uid: args.foreign_uid,
    };
    setup_network()?;
    println!(
        "ndn-e2e: private user+network+mount+PID namespace up; nodes on 10.200.0.1-10 (lo); run dir {}",
        run_dir.display()
    );
    let selected: Vec<&str> = scenarios::ALL
        .iter()
        .copied()
        .filter(|s| args.only.is_empty() || args.only.iter().any(|o| o == s))
        .collect();

    let started = Instant::now();
    let mut reports = Vec::new();
    let mut summary = Vec::new();
    for name in selected {
        println!("\n=== scenario {name} ===");
        let world = World::new(run_dir.join(name), bins.clone());
        let mut sc = Scenario::new(name, world);
        let t = Instant::now();
        let aborted = scenarios::run(name, &mut sc).is_err();
        let dur = t.elapsed();
        let passed = sc.passed() && !aborted;
        println!(
            "=== scenario {name}: {} ({} steps, {:.1}s) ===",
            if passed { "PASS" } else { "FAIL" },
            sc.steps.len(),
            dur.as_secs_f64()
        );
        reports.push(sc.to_json(dur, aborted));
        summary.push((name, passed, sc.steps.len(), dur, sc.steps.clone()));
        // Dropping the scenario stops its daemons, producers and shims.
        drop(sc);
    }
    let total = started.elapsed();

    println!("\n=== summary ===");
    let mut all = true;
    for (name, passed, n, dur, steps) in &summary {
        let skipped = steps
            .iter()
            .filter(|s| matches!(s.status, step::Status::Skip(_)))
            .count();
        println!(
            "{:<22} {}  {n:>2} steps{}  {:>6.1}s",
            name,
            if *passed { "PASS" } else { "FAIL" },
            if skipped > 0 {
                format!(" ({skipped} skipped)")
            } else {
                String::new()
            },
            dur.as_secs_f64()
        );
        all &= passed;
    }
    println!(
        "total {:.1}s: {}",
        total.as_secs_f64(),
        if all { "PASS" } else { "FAIL" }
    );

    print_touchpoints(&summary);

    let report = json!({
        "passed": all,
        "duration_ms": total.as_millis() as u64,
        "scenarios": reports,
    });
    let path = run_dir.join("report.json");
    let _ = fs::write(
        &path,
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );
    if args.keep {
        println!("touchpoints and results written to {}", path.display());
    }
    Ok(all)
}

type Summary<'a> = (&'a str, bool, usize, Duration, Vec<step::StepRecord>);

fn print_touchpoints(summary: &[Summary<'_>]) {
    println!("\n=== touchpoints: what a person supplied, per step ===");
    for (name, _, _, _, steps) in summary {
        println!("\n[{name}]");
        for (i, s) in steps.iter().enumerate() {
            if s.inputs.is_empty() && s.concepts.is_empty() {
                continue;
            }
            println!("  {:>2}. {}", i + 1, s.name);
            if !s.inputs.is_empty() {
                println!("      inputs:   {}", s.inputs.join("; "));
            }
            if !s.concepts.is_empty() {
                println!("      concepts: {}", s.concepts.join("; "));
            }
        }
        let mut distinct: Vec<&String> = Vec::new();
        for s in steps {
            for i in &s.inputs {
                if !i.starts_with("Data name") && !distinct.contains(&i) {
                    distinct.push(i);
                }
            }
        }
        let secrets: Vec<&&String> = distinct
            .iter()
            .filter(|i| step::SECRET_INPUTS.contains(&i.as_str()))
            .collect();
        println!(
            "  — {} distinct inputs, {} of them secrets: {}",
            distinct.len(),
            secrets.len(),
            secrets
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}
