//! Running the binaries under test: one-shot commands with a deadline and
//! captured output, and long-lived processes (daemons, producers) that are
//! always stopped — on drop, and by the PID namespace when the harness dies.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Environment variables whose values are secrets the operator types: shown
/// by name only in transcripts.
const SECRET_ENV: &[&str] = &[
    "NDN_ROOT_PASSPHRASE",
    "NDN_ROOT_PIN",
    "NDN_KIT_PASSPHRASE",
    "NDN_KIT_PIN",
    "NDN_KIT_WORDS",
];

/// One invocation of a binary under test.
#[derive(Clone, Debug)]
pub struct Op {
    /// The tool as an operator names it (`ndn-fwd`, `ndn-peek`, …).
    pub tool: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    /// Run as uid/gid 1 with no supplementary groups (`setpriv`): a local
    /// user who is neither the daemons' user nor in their groups.
    pub foreign_user: bool,
}

impl Op {
    pub fn new(tool: &str, program: PathBuf) -> Self {
        Op {
            tool: tool.to_owned(),
            program,
            args: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(60),
            foreign_user: false,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, k: &str, v: impl Into<String>) -> Self {
        self.env.push((k.to_owned(), v.into()));
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn by_foreign_user(mut self) -> Self {
        self.foreign_user = true;
        self
    }

    /// The command line, secrets shown by name only.
    pub fn display(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.env {
            if SECRET_ENV.contains(&k.as_str()) {
                s.push_str(&format!("{k}=<secret> "));
            } else {
                s.push_str(&format!("{k}={v} "));
            }
        }
        if self.foreign_user {
            s.push_str("setpriv --reuid=1 --regid=1 --clear-groups ");
        }
        s.push_str(&self.tool);
        for a in &self.args {
            if a.chars().count() > 96 {
                let head: String = a.chars().take(64).collect();
                s.push_str(&format!(" {head}…"));
            } else {
                s.push_str(&format!(" {a}"));
            }
        }
        s
    }

    fn command(&self) -> Command {
        let mut c = if self.foreign_user {
            let mut c = Command::new("setpriv");
            c.args(["--reuid=1", "--regid=1", "--clear-groups"]);
            c.arg(&self.program);
            c
        } else {
            Command::new(&self.program)
        };
        c.args(&self.args);
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c.stdin(Stdio::null());
        c
    }

    /// Run to completion or the deadline (then killed).
    pub fn run(&self) -> Out {
        let start = Instant::now();
        let mut cmd = self.command();
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Out {
                    code: None,
                    stdout: String::new(),
                    stderr: format!("could not start {}: {e}", self.program.display()),
                    timed_out: false,
                    elapsed: start.elapsed(),
                };
            }
        };
        let mut so = child.stdout.take().expect("piped stdout");
        let mut se = child.stderr.take().expect("piped stderr");
        let t_out = thread::spawn(move || {
            let mut b = Vec::new();
            let _ = so.read_to_end(&mut b);
            b
        });
        let t_err = thread::spawn(move || {
            let mut b = Vec::new();
            let _ = se.read_to_end(&mut b);
            b
        });
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if start.elapsed() >= self.timeout => {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().ok();
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => break None,
            }
        };
        let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
        Out {
            code: status.and_then(|s| s.code()),
            stdout,
            stderr,
            timed_out,
            elapsed: start.elapsed(),
        }
    }

    /// Start as a long-lived process, output appended to `log`.
    pub fn spawn_logged(&self, log: &Path, label: &str) -> Result<Proc, String> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("open {}: {e}", log.display()))?;
        let f2 = f.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = self.command();
        cmd.stdout(Stdio::from(f)).stderr(Stdio::from(f2));
        let child = cmd
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", self.program.display()))?;
        Ok(Proc {
            child,
            label: label.to_owned(),
            log: log.to_owned(),
        })
    }
}

/// The outcome of one [`Op::run`].
#[derive(Debug)]
pub struct Out {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub elapsed: Duration,
}

impl Out {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    /// Values of `key = value` lines on stdout (the CLIs' machine-readable
    /// result lines), in order.
    pub fn kv_all(&self, key: &str) -> Vec<String> {
        self.stdout
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .filter(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim().to_owned())
            .collect()
    }

    pub fn kv(&self, key: &str) -> Option<String> {
        self.kv_all(key).into_iter().next()
    }

    pub fn status_text(&self) -> String {
        if self.timed_out {
            format!("killed at the deadline after {:.1}s", self.elapsed.as_secs_f64())
        } else {
            match self.code {
                Some(c) => format!("exit {c} after {:.2}s", self.elapsed.as_secs_f64()),
                None => "no exit status (signal or spawn failure)".to_owned(),
            }
        }
    }
}

/// A long-lived child process. Stopped (SIGTERM, then SIGKILL) on drop.
pub struct Proc {
    pub child: Child,
    pub label: String,
    pub log: PathBuf,
}

impl Proc {
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn stop(&mut self) {
        if !self.alive() {
            return;
        }
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !self.alive() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The last `n` lines of a file (for failure reports).
pub fn tail(path: &Path, n: usize) -> String {
    let mut s = String::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    let lines: Vec<&str> = s.lines().collect();
    let from = lines.len().saturating_sub(n);
    lines[from..].join("\n")
}

/// Every file under `dir`, with its bytes, sorted by path: a snapshot to
/// prove that a refused operation changed nothing.
pub fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = fs::read(&p) {
                out.push((p, b));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
