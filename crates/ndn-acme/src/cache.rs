//! Plaintext PEM cert + key cached on disk under `cache_dir/`.

use std::path::{Path, PathBuf};

use tokio::fs;

/// On-disk store for issued ACME certs, keyed by domain.
///
/// Each domain gets a `<domain>.cert.pem` / `<domain>.key.pem` pair under the
/// cache directory. Contents are plaintext, so the directory must be
/// operator-protected.
#[derive(Debug, Clone)]
pub struct CertCache {
    dir: PathBuf,
}

impl CertCache {
    /// Opens (creating if needed) the cache directory at `dir`.
    pub async fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).await?;
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
        fs::write(self.cert_path(domain), cert_pem).await?;
        fs::write(self.key_path(domain), key_pem).await?;
        Ok(())
    }
}
