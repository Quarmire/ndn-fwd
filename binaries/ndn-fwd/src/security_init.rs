//! Security identity loading: PIB recovery, ephemeral fallback, and
//! mgmt-validator construction.

use std::path::PathBuf;

use ndn_config::ForwarderConfig;
use ndn_config::boot;
use ndn_security::SecurityManager;

use crate::parse_name;

pub(crate) struct SecurityInit {
    pub mgr: SecurityManager,
    pub pib_path: Option<PathBuf>,
    pub is_ephemeral: bool,
}

/// Priority: 1) configured `[security].identity` from PIB (loaded by
/// [`boot::load_identity`], as `ndn-sim` boots a node); 2) on PIB failure,
/// interactive recovery menu if stdin is a TTY else ephemeral fallback; 3) no
/// identity ⇒ ephemeral in-memory key.
pub fn load_security(cfg: &ForwarderConfig) -> SecurityInit {
    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);
    let identity_uri = cfg.security.identity.as_deref().unwrap_or_default();

    match boot::load_identity(cfg, &pib_path) {
        Ok(Some((mgr, generated))) => {
            tracing::info!(
                target: "security",
                identity = %identity_uri,
                pib = %pib_path.display(),
                "{}",
                if generated {
                    "auto-initialized new security identity"
                } else {
                    "loaded security identity from PIB"
                }
            );
            SecurityInit {
                mgr,
                pib_path: Some(pib_path),
                is_ephemeral: false,
            }
        }
        Ok(None) => make_ephemeral(cfg, None),
        Err(e) => recover_from_pib_error(identity_uri, &e.to_string(), &pib_path, cfg),
    }
}

pub fn recover_from_pib_error(
    identity_uri: &str,
    error: &str,
    pib_path: &std::path::Path,
    cfg: &ForwarderConfig,
) -> SecurityInit {
    use std::io::IsTerminal as _;

    let is_tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();

    if is_tty {
        eprintln!();
        eprintln!("  ERROR  Failed to load security identity");
        eprintln!("  Identity : {identity_uri}");
        eprintln!("  PIB path : {}", pib_path.display());
        eprintln!("  Reason   : {error}");
        eprintln!();
        eprintln!("  Recovery options:");
        eprintln!("    [1] Generate a new key for '{identity_uri}' and save it to the PIB");
        eprintln!("        (creates a self-signed certificate; overwrites any existing key)");
        eprintln!("    [2] Continue with an ephemeral identity (key not saved to disk)");
        eprintln!("    [3] Abort");
        eprintln!();
        eprint!("  Choose [1-3]: ");
        let _ = std::io::Write::flush(&mut std::io::stderr());

        let mut input = String::new();
        let _ = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut input);
        match input.trim() {
            "1" => match SecurityManager::auto_init(&parse_name(identity_uri), pib_path) {
                Ok((mgr, _)) => {
                    eprintln!();
                    eprintln!("  Generated new identity '{identity_uri}' in PIB.");
                    return SecurityInit {
                        mgr,
                        pib_path: Some(pib_path.to_path_buf()),
                        is_ephemeral: false,
                    };
                }
                Err(e) => {
                    eprintln!("  Key generation failed: {e}");
                    eprintln!("  Falling back to ephemeral identity.");
                }
            },
            "3" => {
                eprintln!("  Aborting.");
                std::process::exit(1);
            }
            _ => {
                eprintln!("  Continuing with ephemeral identity.");
            }
        }
        eprintln!();
    } else {
        tracing::error!(
            target: "security",
            error = %error,
            identity = %identity_uri,
            pib = %pib_path.display(),
            "PIB error — falling back to ephemeral identity; \
             set [security] auto_init=true or run `ndn-sec keygen` to fix"
        );
    }

    make_ephemeral(cfg, Some(identity_uri))
}

/// [`boot::ephemeral_identity`] (the same fallback `ndn-sim` boots a node
/// with), named from `[security].ephemeral_prefix`, then `$HOSTNAME`, then the
/// PID.
pub fn make_ephemeral(cfg: &ForwarderConfig, configured_identity: Option<&str>) -> SecurityInit {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| format!("pid-{}", std::process::id()));
    match boot::ephemeral_identity(cfg, &host) {
        Ok((mgr, name)) => {
            if let Some(id) = configured_identity {
                tracing::warn!(
                    target: "security",
                    ephemeral_identity = %name,
                    configured_identity = %id,
                    "PIB error — using ephemeral identity; \
                     data signed this session will not be verifiable across restarts"
                );
            } else {
                tracing::warn!(
                    target: "security",
                    ephemeral_identity = %name,
                    "no [security] identity configured — using ephemeral in-memory key; \
                     add `identity = \"/your/name\"` to the [security] config to persist signing"
                );
            }
            SecurityInit {
                mgr,
                pib_path: None,
                is_ephemeral: true,
            }
        }
        Err(e) => {
            tracing::error!(target: "security", error = %e, "failed to generate ephemeral identity; starting unsigned");
            SecurityInit {
                mgr: SecurityManager::new(),
                pib_path: None,
                is_ephemeral: true,
            }
        }
    }
}

pub fn default_pib_path() -> PathBuf {
    let mut p = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    p.push(".ndn");
    p.push("pib");
    p
}
