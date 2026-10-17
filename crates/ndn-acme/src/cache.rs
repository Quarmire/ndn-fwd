//! Plaintext PEM cert + key cached on disk under `cache_dir/`.

use std::path::{Path, PathBuf};

use tokio::fs;

use crate::self_signed::{create_private_dir, publish_replace};

/// On-disk store for issued ACME certs, keyed by domain.
///
/// Each domain gets a `<domain>.cert.pem` / `<domain>.key.pem` pair under the
/// cache directory. Contents are plaintext, so the directory is created `0700`
/// and entries are written `0600` from creation (on unix; elsewhere they
/// inherit the directory's ACL).
#[derive(Debug, Clone)]
pub struct CertCache {
    dir: PathBuf,
}

impl CertCache {
    /// Opens (creating if needed) the cache directory at `dir`.
    pub async fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let d = dir.clone();
        tokio::task::spawn_blocking(move || create_private_dir(&d)).await??;
        Ok(Self { dir })
    }

    fn cert_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.cert.pem"))
    }
    fn key_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.key.pem"))
    }

    /// Loads the cached `(cert_pem, key_pem)` for `domain`, or `None` if either
    /// file is absent.
    pub async fn load(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let cert = fs::read(self.cert_path(domain)).await.ok()?;
        let key = fs::read(self.key_path(domain)).await.ok()?;
        Some((cert, key))
    }

    /// Writes the `cert_pem` / `key_pem` pair for `domain`, overwriting any
    /// existing entry.
    pub async fn store(
        &self,
        domain: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> std::io::Result<()> {
        let (cert_path, key_path) = (self.cert_path(domain), self.key_path(domain));
        let (cert_pem, key_pem) = (cert_pem.to_vec(), key_pem.to_vec());
        tokio::task::spawn_blocking(move || {
            publish_replace(&cert_path, &cert_pem)?;
            publish_replace(&key_path, &key_pem)
        })
        .await?
    }
}
