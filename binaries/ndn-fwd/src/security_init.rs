//! Security identity loading: PIB recovery, ephemeral fallback, and
//! mgmt-validator construction.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_config::ForwarderConfig;
#[allow(unused_imports)]
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager};

use crate::parse_name;

pub(crate) struct SecurityInit {
    pub mgr: SecurityManager,
    pub pib_path: Option<PathBuf>,
    pub is_ephemeral: bool,
}

/// Priority: 1) configured `[security].identity` from PIB; 2) on PIB
/// failure, interactive recovery menu if stdin is a TTY else ephemeral
/// fallback; 3) no identity ⇒ ephemeral in-memory key.
pub fn load_security(cfg: &ForwarderConfig) -> SecurityInit {
    let Some(identity_uri) = cfg.security.identity.as_ref() else {
        return make_ephemeral(cfg, None);
    };

    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let identity = parse_name(identity_uri);

    if cfg.security.auto_init {
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
                    mgr,
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
                mgr,
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
            // `into_manager_arc` consumes the keychain so its internal
            // `Arc::clone` drops first, letting `try_unwrap` succeed and
            // the signer survive for mgmt-response signing. The fallback
            // branch copies only trust anchors and is hit only by tests
            // that intentionally leak a second `Arc`.
            let arc = kc.into_manager_arc();
            let mgr = Arc::try_unwrap(arc).unwrap_or_else(|a| {
                let m = SecurityManager::new();
                for n in a.trust_anchor_names() {
                    if let Some(cert) = a.trust_anchor(&n) {
                        m.add_trust_anchor(cert);
                    }
                }
                m
            });

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
