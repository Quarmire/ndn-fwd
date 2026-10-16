//! Security identity loading: PIB recovery, ephemeral fallback, and
//! mgmt-validator construction.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_config::ForwarderConfig;
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
/// `<identity>/KEY/` — from the PIB; 2) else the PIB's default identity (set
/// by `ndn-fwd enroll`; the config file is never edited); 3) on PIB failure,
/// interactive recovery menu if stdin is a TTY else ephemeral fallback; 4) no
/// identity ⇒ ephemeral in-memory key.
pub fn load_security(cfg: &ForwarderConfig) -> SecurityInit {
    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let (identity_uri, identity) = match cfg.security.identity.as_ref() {
        Some(uri) => (uri.clone(), parse_name(uri)),
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
            None => return make_ephemeral(cfg, None),
        },
    };
    let identity_uri = identity_uri.as_str();

    // `auto_init` mints a key for a configured identity the PIB lacks; the
    // PIB's own default identity always has one, so it is only loaded.
    if cfg.security.auto_init && cfg.security.identity.is_some() {
        match SecurityManager::auto_init(&identity, &pib_path) {
            Ok((mgr, generated)) => {
                if generated {
                    tracing::info!(
                        target: "security",
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "auto-initialized new security identity"
                    );
                } else {
                    tracing::info!(
                        target: "security",
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "loaded existing security identity from PIB"
                    );
                }
                return SecurityInit {
                    mgr: Arc::new(mgr),
                    pib_path: Some(pib_path),
                    is_ephemeral: false,
                };
            }
            Err(e) => {
                return recover_from_pib_error(identity_uri, &e.to_string(), &pib_path, cfg);
            }
        }
    }

    let pib = match FilePib::open(&pib_path) {
        Ok(p) => p,
        Err(e) => {
            return recover_from_pib_error(identity_uri, &e.to_string(), &pib_path, cfg);
        }
    };

    match SecurityManager::from_pib(&pib, &identity) {
        Ok(mgr) => {
            tracing::info!(
                target: "security",
                identity = %identity_uri,
                pib = %pib_path.display(),
                "loaded security identity from PIB"
            );
            SecurityInit {
                mgr: Arc::new(mgr),
                pib_path: Some(pib_path),
                is_ephemeral: false,
            }
        }
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

/// Name comes from `[security].ephemeral_prefix`, then `$HOSTNAME`, then
/// the PID.
pub fn make_ephemeral(cfg: &ForwarderConfig, configured_identity: Option<&str>) -> SecurityInit {
    let name_str = if let Some(prefix) = &cfg.security.ephemeral_prefix {
        prefix.clone()
    } else {
        let host =
            std::env::var("HOSTNAME").unwrap_or_else(|_| format!("pid-{}", std::process::id()));
        format!("/ndn-fwd/{host}")
    };

    // ECDSA-P256 is the lowest common denominator for ndn-cxx interop:
    // ndn-cxx's `KeyType` enum has RSA + EC + AES + HMAC but no Ed25519,
    // so mgmt responses signed with Ed25519 fail to verify against an
    // ndn-cxx trust schema.
    match ndn_security::KeyChain::ephemeral_ecdsa(&name_str) {
        Ok(kc) => {
            let mgr = kc.into_manager_arc();

            if let Some(id) = configured_identity {
                tracing::warn!(
                    target: "security",
                    ephemeral_identity = %name_str,
                    configured_identity = %id,
                    "PIB error — using ephemeral identity; \
                     data signed this session will not be verifiable across restarts"
                );
            } else {
                tracing::warn!(
                    target: "security",
                    ephemeral_identity = %name_str,
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
        let init = load_security(&cfg);

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
        let init = load_security(&cfg);
        assert!(!init.is_ephemeral);
        assert_eq!(
            init.mgr.any_signer().unwrap().key_name(),
            &node_mgr.identity_key_name(&node).unwrap()
        );

        cfg.security.identity = Some(ident.to_string());
        let init = load_security(&cfg);
        assert_eq!(
            init.mgr.any_signer().unwrap().key_name(),
            &root_mgr.identity_key_name(&ident).unwrap()
        );
    }
}
