//! Security identity loading: the node identity (chosen by
//! [`ndn_cert::choose_node_identity`], logged with why) and every other PIB
//! identity with a currently valid certificate, PIB recovery, ephemeral
//! fallback.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_cert::NodeIdentitySource;
use ndn_config::ForwarderConfig;
use ndn_config::boot;
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager, Signer};

use crate::parse_name;

pub(crate) struct SecurityInit {
    /// Shared with the engine as-is (`EngineBuilder::security`): the node
    /// identity's key first, then every other identity the daemon signs
    /// Data as.
    pub mgr: Arc<SecurityManager>,
    pub pib_path: Option<PathBuf>,
    pub is_ephemeral: bool,
    /// The node identity's signer (management responses, discovery records,
    /// links); `None` only when not even an ephemeral key could be made.
    pub node: Option<Arc<dyn Signer>>,
    /// Which rule chose the node identity.
    pub source: NodeIdentitySource,
}

/// The node identity, by [`ndn_cert::choose_node_identity`]: 1) configured
/// `[security].identity` — its key under `<identity>/KEY/` — from the PIB
/// (loaded by [`boot::load_identity`], as `ndn-sim` boots a node); 2) the
/// PIB's default identity (recorded by the first `ndn-fwd enroll`, or set by
/// `ndn-fwd node-identity`; the config file is never edited); 3) the device
/// identity in a namespace whose root the PIB holds; 4) the first enrolled;
/// 5) none ⇒ ephemeral in-memory key. Every other PIB identity with a
/// currently valid certificate is loaded beside it. On a PIB failure:
/// interactive recovery menu if stdin is a TTY, else ephemeral fallback. A
/// malformed `[security].identity` is a startup error.
pub fn load_security(cfg: &ForwarderConfig) -> anyhow::Result<SecurityInit> {
    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let configured = match cfg.security.identity.as_ref() {
        Some(uri) => Some(
            parse_name(uri)
                .map_err(|e| e.context("[security].identity is not a valid NDN name"))?,
        ),
        None => None,
    };
    let pib = FilePib::open(&pib_path).ok();
    let chosen = ndn_cert::choose_node_identity(pib.as_ref(), configured.as_ref());
    let Some(identity) = chosen.identity else {
        return Ok(make_ephemeral(cfg, None));
    };
    let source = chosen.source;
    tracing::info!(
        target: "security",
        identity = %identity,
        source = %source,
        pib = %pib_path.display(),
        "node identity {identity}: {}",
        source.describe()
    );
    let identity_uri = identity.to_string();

    // A configured identity loads as `ndn-sim` boots a node, `auto_init`
    // minting a key the PIB lacks. An identity chosen from the PIB always
    // has one, so it is only loaded.
    let loaded = if configured.is_some() {
        boot::load_identity(cfg, &pib_path)
    } else {
        FilePib::open(&pib_path)
            .map_err(Into::into)
            .and_then(|pib| SecurityManager::from_pib(&pib, &identity))
            .map(|mgr| Some((mgr, false)))
    };

    match loaded {
        Ok(Some((mgr, generated))) => {
            let signing: Vec<String> = mgr
                .signing_identities()
                .iter()
                .map(|s| s.identity.to_string())
                .collect();
            tracing::info!(
                target: "security",
                identity = %identity_uri,
                pib = %pib_path.display(),
                signing = %signing.join(", "),
                "{}",
                if generated {
                    "auto-initialized new security identity"
                } else {
                    "loaded security identities from PIB"
                }
            );
            Ok(loaded_init(mgr, &identity, Some(pib_path), source))
        }
        Ok(None) => Ok(make_ephemeral(cfg, None)),
        Err(e) => Ok(recover_from_pib_error(
            &identity,
            &identity_uri,
            &e.to_string(),
            &pib_path,
            cfg,
            source,
        )),
    }
}

/// A [`SecurityInit`] over `mgr`, whose node identity is `identity`.
fn loaded_init(
    mgr: SecurityManager,
    identity: &Name,
    pib_path: Option<PathBuf>,
    source: NodeIdentitySource,
) -> SecurityInit {
    let node = mgr.identity_signer(identity).ok();
    SecurityInit {
        mgr: Arc::new(mgr),
        pib_path,
        is_ephemeral: source == NodeIdentitySource::Ephemeral,
        node,
        source,
    }
}

pub fn recover_from_pib_error(
    identity: &Name,
    identity_uri: &str,
    error: &str,
    pib_path: &std::path::Path,
    cfg: &ForwarderConfig,
    source: NodeIdentitySource,
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
                    return loaded_init(mgr, identity, Some(pib_path.to_path_buf()), source);
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
                    "node identity: {}; enroll in a trusted prefix (`ndn-fwd enroll`) or add \
                     `identity = \"/your/name\"` to the [security] config to persist signing",
                    NodeIdentitySource::Ephemeral.describe()
                );
            }
            let node = name
                .parse::<Name>()
                .ok()
                .and_then(|identity| mgr.identity_signer(&identity).ok());
            SecurityInit {
                mgr: Arc::new(mgr),
                pib_path: None,
                is_ephemeral: true,
                node,
                source: NodeIdentitySource::Ephemeral,
            }
        }
        Err(e) => {
            tracing::error!(target: "security", error = %e, "failed to generate ephemeral identity; starting unsigned");
            SecurityInit {
                mgr: Arc::new(SecurityManager::new()),
                pib_path: None,
                is_ephemeral: true,
                node: None,
                source: NodeIdentitySource::Ephemeral,
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

        assert!(
            !init.is_ephemeral,
            "configured identity must load from the PIB"
        );
        assert_eq!(init.source, NodeIdentitySource::Configured);
        assert_eq!(init.node.unwrap().key_name(), &node_key);
        assert!(
            init.mgr.identity_key_name(&ident).is_some(),
            "the other identity is loaded beside the node identity"
        );
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
        assert_eq!(init.source, NodeIdentitySource::PibDefault);
        assert_eq!(
            init.node.unwrap().key_name(),
            &node_mgr.identity_key_name(&node).unwrap()
        );

        cfg.security.identity = Some(ident.to_string());
        let init = load_security(&cfg).unwrap();
        assert_eq!(
            init.node.unwrap().key_name(),
            &root_mgr.identity_key_name(&ident).unwrap()
        );
    }
}
