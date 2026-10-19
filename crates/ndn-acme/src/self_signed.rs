//! Persistent self-signed listener certs.
//!
//! A pinning dialer (a WebTransport `[[face]] cert_sha256`, a browser's
//! `serverCertificateHashes`) trusts the SHA-256 of the listener's leaf
//! certificate. Minting a fresh key + cert on every resolve would break every
//! paired peer's pin at each restart, so the key (PKCS#8) and cert are
//! persisted under a state directory and reused. The key is reused forever;
//! the 13-day cert is re-issued (same key) once it is within a day of expiry.
//!
//! Entries are keyed by hostnames, so changing the hostnames mints a new key
//! and cert. Files are written `0600` (directories `0700`) and published
//! atomically, so concurrent resolvers sharing a directory converge on one key.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::cert_source::{CertMaterial, SelfSignedDev};
use crate::client::AcmeError;

const DAY_SECS: i64 = 86_400;

/// Validity of a freshly minted cert. Chrome's WebTransport
/// `serverCertificateHashes` rejects certs valid for more than 14 days.
const VALIDITY_DAYS: i64 = 13;

/// A cached cert is re-issued once fewer than this many seconds remain.
const REISSUE_MARGIN_SECS: i64 = DAY_SECS;

/// Tag in cache file names; kept so certs already on disk keep being reused.
const CACHE_TAG: &str = "browser";

/// Default directory for persisted self-signed listener certs:
/// `$XDG_STATE_HOME/ndn-fwd/tls`, else `$HOME/.local/state/ndn-fwd/tls`.
/// `None` when neither variable yields an absolute path.
pub fn default_self_signed_cache_dir() -> Option<PathBuf> {
    default_cache_dir_from(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
}

fn default_cache_dir_from(
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let absolute = |v: std::ffi::OsString| Some(PathBuf::from(v)).filter(|p| p.is_absolute());
    let base = xdg_state_home.and_then(absolute).or_else(|| {
        home.and_then(absolute)
            .map(|h| h.join(".local").join("state"))
    })?;
    Some(base.join("ndn-fwd").join("tls"))
}

/// Resolves a [`SelfSignedDev`] source, reusing the persisted key/cert.
pub(crate) async fn resolve(src: &SelfSignedDev) -> Result<CertMaterial, AcmeError> {
    let hostnames = src.hostnames.clone();
    let dir = src.cache_dir.clone().or_else(default_self_signed_cache_dir);
    tokio::task::spawn_blocking(move || resolve_blocking(&hostnames, dir.as_deref()))
        .await
        .map_err(|e| AcmeError::Other(format!("self-signed cert task failed: {e}")))?
}

fn resolve_blocking(hostnames: &[String], dir: Option<&Path>) -> Result<CertMaterial, AcmeError> {
    let Some(dir) = dir else {
        tracing::warn!(
            target: "ndn_acme",
            "no state directory for the self-signed cert (set `cache_dir`, \
             XDG_STATE_HOME or HOME); minting an ephemeral cert whose pinned \
             hash changes on every restart"
        );
        let key = rcgen::KeyPair::generate()?;
        let cert_pem = mint_cert(hostnames, &key)?;
        return Ok(material(cert_pem, &key));
    };
    create_private_dir(dir)?;
    let stem = cache_stem(hostnames);
    let key_path = dir.join(format!("{stem}.key.pem"));
    let cert_path = dir.join(format!("{stem}.cert.pem"));

    let key = load_or_create_key(&key_path)?;
    let spki = key.public_key_der();

    let existing = read_optional(&cert_path)?;
    if let Some(pem) = &existing
        && cert_reusable(pem, &spki)
    {
        tracing::debug!(target: "ndn_acme", path = %cert_path.display(), "reusing persisted self-signed cert");
        return Ok(material(pem.clone(), &key));
    }

    let cert_pem = mint_cert(hostnames, &key)?;
    match existing {
        Some(_) => publish_replace(&cert_path, &cert_pem)?,
        None if publish_new(&cert_path, &cert_pem)? => {}
        None => {
            // A concurrent resolver published first; converge on its cert.
            let theirs = fs::read(&cert_path)?;
            if cert_reusable(&theirs, &spki) {
                return Ok(material(theirs, &key));
            }
            publish_replace(&cert_path, &cert_pem)?;
        }
    }
    tracing::info!(
        target: "ndn_acme",
        path = %cert_path.display(),
        "issued self-signed cert from the persisted key"
    );
    Ok(material(cert_pem, &key))
}

fn material(cert_chain_pem: Vec<u8>, key: &rcgen::KeyPair) -> CertMaterial {
    CertMaterial {
        cert_chain_pem,
        private_key_pem: key.serialize_pem().into_bytes(),
    }
}

/// File-name stem: cache tag + a digest of the (ordered) hostnames.
fn cache_stem(hostnames: &[String]) -> String {
    let mut h = Sha256::new();
    for name in hostnames {
        h.update((name.len() as u64).to_be_bytes());
        h.update(name.as_bytes());
    }
    let digest = h.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("self-signed-{CACHE_TAG}-{hex}")
}

fn mint_cert(hostnames: &[String], key: &rcgen::KeyPair) -> Result<Vec<u8>, AcmeError> {
    let mut params = rcgen::CertificateParams::new(hostnames.to_vec())?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(VALIDITY_DAYS);
    Ok(params.self_signed(key)?.pem().into_bytes())
}

/// True when `cert_pem` holds a leaf for `spki` that is currently valid and
/// not within the re-issue margin of expiry.
fn cert_reusable(cert_pem: &[u8], spki: &[u8]) -> bool {
    use x509_parser::prelude::*;
    let Some(Ok(der)) = rustls_pemfile::certs(&mut &cert_pem[..]).next() else {
        return false;
    };
    let Ok((_, cert)) = X509Certificate::from_der(der.as_ref()) else {
        return false;
    };
    if cert.public_key().raw != spki {
        return false;
    }
    let now = now_unix();
    let validity = cert.validity();
    validity.not_before.timestamp() <= now
        && validity.not_after.timestamp() - now > REISSUE_MARGIN_SECS
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn load_or_create_key(path: &Path) -> Result<rcgen::KeyPair, AcmeError> {
    if let Some(pem) = read_optional(path)? {
        return parse_key(path, &pem);
    }
    let key = rcgen::KeyPair::generate()?;
    if publish_new(path, key.serialize_pem().as_bytes())? {
        tracing::info!(target: "ndn_acme", path = %path.display(), "persisted new self-signed listener key");
        Ok(key)
    } else {
        // Lost a race with a concurrent resolver: adopt its key.
        parse_key(path, &fs::read(path)?)
    }
}

fn parse_key(path: &Path, pem: &[u8]) -> Result<rcgen::KeyPair, AcmeError> {
    std::str::from_utf8(pem)
        .ok()
        .and_then(|s| rcgen::KeyPair::from_pem(s).ok())
        .ok_or_else(|| {
            AcmeError::Other(format!(
                "persisted self-signed key {} is unreadable; delete it to mint a new \
                 key (this changes the cert hash peers pin)",
                path.display()
            ))
        })
}

fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Writes `bytes` to a fresh owner-only (`0600`) temp file beside `path`.
fn write_private_tmp(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = path.with_file_name(name);
    // A leftover from a crashed process that had the same pid.
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// Publishes `bytes` at `path` only if nothing is there yet. Returns `false`
/// (leaving the existing file untouched) when another writer got there first.
fn publish_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let tmp = write_private_tmp(path, bytes)?;
    let published = match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        // Filesystem without hard links: best-effort exclusive publish.
        Err(_) if path.exists() => Ok(false),
        Err(_) => fs::rename(&tmp, path).map(|()| true),
    };
    // Gone already after a successful rename; otherwise drop the temp copy.
    let _ = fs::remove_file(&tmp);
    published
}

/// Atomically replaces `path` with `bytes`, as an owner-only (`0600`) file.
pub(crate) fn publish_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = write_private_tmp(path, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_source::CertSource;

    fn source(dir: &Path, hostnames: &[&str]) -> CertSource {
        CertSource::SelfSignedDev(SelfSignedDev {
            hostnames: hostnames.iter().map(|h| (*h).to_string()).collect(),
            cache_dir: Some(dir.to_path_buf()),
        })
    }

    async fn leaf(src: &CertSource) -> [u8; 32] {
        src.resolve(None)
            .await
            .expect("resolve")
            .leaf_sha256()
            .expect("leaf")
    }

    #[tokio::test]
    async fn same_cache_dir_yields_stable_leaf_hash() {
        let dir = tempfile::tempdir().unwrap();
        let first = leaf(&source(dir.path(), &["localhost"])).await;
        let second = leaf(&source(dir.path(), &["localhost"])).await;
        assert_eq!(first, second, "pin must survive a re-resolve");
    }

    #[tokio::test]
    async fn different_hostnames_yield_new_cert() {
        let dir = tempfile::tempdir().unwrap();
        let a = leaf(&source(dir.path(), &["localhost"])).await;
        let b = leaf(&source(dir.path(), &["localhost", "127.0.0.1"])).await;
        assert_ne!(a, b);
        // Each hostname set keeps its own stable cert.
        assert_eq!(a, leaf(&source(dir.path(), &["localhost"])).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("tls");
        leaf(&source(&cache, &["localhost"])).await;
        let mut files = 0;
        for entry in fs::read_dir(&cache).unwrap() {
            let entry = entry.unwrap();
            let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", entry.path().display());
            files += 1;
        }
        assert_eq!(files, 2, "exactly one key + one cert, no temp leftovers");
        let dir_mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[tokio::test]
    async fn cert_near_expiry_is_reissued_with_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let src = source(dir.path(), &["localhost"]);
        let first = src.resolve(None).await.unwrap();

        // Overwrite the cached cert with one (same key) expiring in an hour.
        let stem = cache_stem(&["localhost".to_string()]);
        let key =
            rcgen::KeyPair::from_pem(std::str::from_utf8(&first.private_key_pem).unwrap()).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(12);
        params.not_after = now + time::Duration::hours(1);
        let expiring = params.self_signed(&key).unwrap().pem();
        fs::write(dir.path().join(format!("{stem}.cert.pem")), &expiring).unwrap();

        let second = src.resolve(None).await.unwrap();
        assert_eq!(second.private_key_pem, first.private_key_pem, "key kept");
        let st = crate::cert_status(&second.cert_chain_pem).unwrap();
        assert!(st.days_remaining >= 12, "re-issued for the full window");
        assert_ne!(second.cert_chain_pem, expiring.into_bytes());
        // The re-issued cert is itself persisted and reused.
        assert_eq!(second.leaf_sha256(), leaf(&src).await.into());
    }

    #[test]
    fn default_cache_dir_prefers_xdg_state_home() {
        assert_eq!(
            default_cache_dir_from(Some("/x/state".into()), Some("/home/u".into())),
            Some(PathBuf::from("/x/state/ndn-fwd/tls"))
        );
        assert_eq!(
            default_cache_dir_from(Some("relative".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/ndn-fwd/tls"))
        );
        assert_eq!(default_cache_dir_from(None, None), None);
    }
}
