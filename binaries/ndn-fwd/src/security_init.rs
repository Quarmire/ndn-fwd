//! Security identity loading: PIB recovery, ephemeral fallback, and
//! mgmt-validator construction.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_config::ForwarderConfig;
use ndn_config::boot;
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager};

use crate::parse_name;

pub(crate) struct SecurityInit {
    /// Shared with the engine as-is (`EngineBuilder::security`).
    pub mgr: Arc<SecurityManager>,
    pub pib_path: Option<PathBuf>,
    pub is_ephemeral: bool,
}

/// Priority: 1) configured `[security].identity` — its key under
/// `<identity>/KEY/` — from the PIB (loaded by [`boot::load_identity`], as
/// `ndn-sim` boots a node); 2) else the PIB's default identity (set by
/// `ndn-fwd enroll`; the config file is never edited); 3) on PIB failure,
/// interactive recovery menu if stdin is a TTY else ephemeral fallback; 4) no
/// identity ⇒ ephemeral in-memory key. A malformed `[security].identity` is a
/// startup error.
pub fn load_security(cfg: &ForwarderConfig) -> anyhow::Result<SecurityInit> {
    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let (identity_uri, identity) = match cfg.security.identity.as_ref() {
        Some(uri) => {
            let identity = parse_name(uri)
                .map_err(|e| e.context("[security].identity is not a valid NDN name"))?;
            (uri.clone(), identity)
        }
        None => match pib_default_identity(&pib_path) {
            Some(identity) => {
                tracing::info!(
                    target: "security",
                    identity = %identity,
                    pib = %pib_path.display(),
                    "no [security] identity configured: using the PIB's default identity"
                );
                (identity.to_string(), identity)
            }
            None => return Ok(make_ephemeral(cfg, None)),
        },
    };
    let identity_uri = identity_uri.as_str();

    // A configured identity loads as `ndn-sim` boots a node, `auto_init`
    // minting a key the PIB lacks. The PIB's own default identity always has
    // one, so it is only loaded.
    let loaded = if cfg.security.identity.is_some() {
        boot::load_identity(cfg, &pib_path)
    } else {
        FilePib::open(&pib_path)
            .map_err(Into::into)
            .and_then(|pib| SecurityManager::from_pib(&pib, &identity))
            .map(|mgr| Some((mgr, false)))
    };

    match loaded {
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
            Ok(SecurityInit {
                mgr: Arc::new(mgr),
                pib_path: Some(pib_path),
                is_ephemeral: false,
            })
        }
        Ok(None) => Ok(make_ephemeral(cfg, None)),
        Err(e) => Ok(recover_from_pib_error(
            &identity,
            identity_uri,
            &e.to_string(),
            &pib_path,
            cfg,
        )),
    }
}

pub fn recover_from_pib_error(
    identity: &Name,
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
            "1" => match SecurityManager::auto_init(identity, pib_path) {
                Ok((mgr, _)) => {
                    eprintln!();
                    eprintln!("  Generated new identity '{identity_uri}' in PIB.");
                    return SecurityInit {
                        mgr: Arc::new(mgr),
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
                mgr: Arc::new(mgr),
                pib_path: None,
                is_ephemeral: true,
            }
        }
        Err(e) => {
            tracing::error!(target: "security", error = %e, "failed to generate ephemeral identity; starting unsigned");
            SecurityInit {
                mgr: Arc::new(SecurityManager::new()),
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

/// The PIB's default identity, when the PIB exists and records one.
fn pib_default_identity(pib_path: &std::path::Path) -> Option<Name> {
    let pib = FilePib::open(pib_path).ok()?;
    match pib.get_default_identity() {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!(
                target: "security",
                pib = %pib_path.display(),
                error = %e,
                "unreadable default identity in the PIB; ignoring it"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[security].identity` names an identity, not a key: the daemon loads
    /// that identity's key from a PIB that also holds another identity,
    /// instead of falling back to an ephemeral key.
    #[test]
    fn load_security_resolves_configured_identity_key() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let ident: Name = "/home/bob/laptop".parse().unwrap();
        let node: Name = "/home/bob/node".parse().unwrap();
        SecurityManager::auto_init(&ident, &pib_path).unwrap();
        let (created, _) = SecurityManager::auto_init(&node, &pib_path).unwrap();
        let node_key = created.identity_key_name(&node).unwrap();

        let mut cfg = ForwarderConfig::default();
        cfg.security.identity = Some(node.to_string());
        cfg.security.pib_path = Some(pib_path.display().to_string());
        let init = load_security(&cfg).unwrap();

        assert!(!init.is_ephemeral, "configured identity must load from the PIB");
        assert_eq!(init.mgr.any_signer().unwrap().key_name(), &node_key);
    }

    /// Without `[security].identity` the PIB's default identity is loaded;
    /// a configured identity still takes precedence over it.
    #[test]
    fn pib_default_identity_is_used_unless_config_names_one() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let ident: Name = "/home/bob/laptop".parse().unwrap();
        let node: Name = "/home/bob/node".parse().unwrap();
        let (root_mgr, _) = SecurityManager::auto_init(&ident, &pib_path).unwrap();
        let (node_mgr, _) = SecurityManager::auto_init(&node, &pib_path).unwrap();
        FilePib::open(&pib_path)
            .unwrap()
            .set_default_identity(&node)
            .unwrap();

        let mut cfg = ForwarderConfig::default();
        cfg.security.pib_path = Some(pib_path.display().to_string());
        let init = load_security(&cfg).unwrap();
        assert!(!init.is_ephemeral);
        assert_eq!(
            init.mgr.any_signer().unwrap().key_name(),
            &node_mgr.identity_key_name(&node).unwrap()
        );

        cfg.security.identity = Some(ident.to_string());
        let init = load_security(&cfg).unwrap();
        assert_eq!(
            init.mgr.any_signer().unwrap().key_name(),
            &root_mgr.identity_key_name(&ident).unwrap()
        );
    }
}
