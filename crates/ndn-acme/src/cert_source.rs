//! Operator-facing cert source enum (`Pem` / `Acme` / `SelfSignedDev`).

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cache::CertCache;
use crate::client::{AcmeClient, AcmeError};
use crate::dns::DnsProvider;

/// A resolved certificate: the PEM chain plus its private key.
///
/// Produced by [`CertSource::resolve`] regardless of the source shape.
#[derive(Clone)]
pub struct CertMaterial {
    /// PEM-encoded certificate chain, leaf first.
    pub cert_chain_pem: Vec<u8>,
    /// PEM-encoded private key for the leaf certificate.
    pub private_key_pem: Vec<u8>,
}

impl CertMaterial {
    /// SHA-256 of the leaf (first) certificate in the chain.
    ///
    /// This is the value a *pinning* dialer trusts — `CertHashes` on a
    /// forwarder-to-forwarder face, or a browser's `serverCertificateHashes`.
    /// Returns `None` if the PEM holds no parseable certificate.
    pub fn leaf_sha256(&self) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let leaf = rustls_pemfile::certs(&mut self.cert_chain_pem.as_slice())
            .next()?
            .ok()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(&leaf));
        Some(out)
    }
}

/// Self-signed cert (dev or `serverCertificateHashes`); never a publicly
/// trusted cert. Valid for 13 days, the most Chrome accepts for WebTransport
/// `serverCertificateHashes`.
///
/// The generated key (PKCS#8) and cert are persisted under
/// [`cache_dir`](Self::cache_dir), keyed by hostnames, and reused on
/// later resolves so the leaf SHA-256 that dialers pin stays stable across
/// restarts. Changing `hostnames` mints a new key and cert.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SelfSignedDev {
    /// Subject-alternative-name hostnames to embed (defaults to `localhost`).
    #[serde(default = "default_hostnames")]
    pub hostnames: Vec<String>,
    /// Directory for the persisted key + cert (files `0600`, directory
    /// `0700`). `None` uses [`default_self_signed_cache_dir`]
    /// (`$XDG_STATE_HOME/ndn-fwd/tls`, else `~/.local/state/ndn-fwd/tls`).
    /// Nodes sharing one directory and hostname set share the cert; give each
    /// node its own directory to keep their pins distinct.
    ///
    /// [`default_self_signed_cache_dir`]: crate::default_self_signed_cache_dir
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<PathBuf>,
}

fn default_hostnames() -> Vec<String> {
    vec!["localhost".into()]
}

/// Operator config for the ACME arm of [`CertSource`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// ACME directory URL, e.g. `https://acme-v02.api.letsencrypt.org/directory`.
    pub directory_url: String,
    /// Account contact address; `mailto:` is implied if the scheme is omitted.
    pub email: String,
    /// Fully-qualified domain the certificate is issued for.
    pub domain: String,
    /// Selects a registered `DnsProvider` impl (e.g. `"cloudflare"`).
    pub dns_provider: String,
    /// Provider-specific (API token, zone id, ...).
    #[serde(default)]
    pub params: serde_json::Value,
    /// Directory where issued certs are cached (see [`CertCache`]).
    pub cache_dir: PathBuf,
}

/// One operator-facing config shape for every cert-bearing face transport.
///
/// Tagged by a `type` field when (de)serialized: `pem`, `acme`, or
/// `self_signed_dev`. [`resolve`](Self::resolve) turns any variant into
/// [`CertMaterial`].
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertSource {
    /// Load a fixed cert chain and key from PEM files on disk.
    Pem {
        /// Path to the PEM certificate chain (leaf first).
        cert_pem: PathBuf,
        /// Path to the PEM private key.
        key_pem: PathBuf,
    },
    /// Provision (and cache) a real cert via an ACME CA over DNS-01.
    Acme(AcmeConfig),
    /// Mint (once) and persist a self-signed cert; never a publicly trusted one.
    SelfSignedDev(SelfSignedDev),
}

impl CertSource {
    /// Runs an ACME order if the cached cert is missing or stale.
    pub async fn resolve(
        &self,
        provider: Option<Arc<dyn DnsProvider>>,
    ) -> Result<CertMaterial, AcmeError> {
        match self {
            CertSource::Pem { cert_pem, key_pem } => {
                let cert_chain_pem = tokio::fs::read(cert_pem).await?;
                let private_key_pem = tokio::fs::read(key_pem).await?;
                Ok(CertMaterial {
                    cert_chain_pem,
                    private_key_pem,
                })
            }
            CertSource::Acme(cfg) => {
                let cache = CertCache::open(&cfg.cache_dir).await?;
                if let Some((cert, key)) = cache.load(&cfg.domain).await
                    && !crate::renewal::needs_renewal(&cert).unwrap_or(true)
                {
                    return Ok(CertMaterial {
                        cert_chain_pem: cert,
                        private_key_pem: key,
                    });
                }
                let provider = provider.ok_or(AcmeError::NoDnsProvider)?;
                let client = AcmeClient::new(cfg, provider).await?;
                let mat = client.issue().await?;
                cache
                    .store(&cfg.domain, &mat.cert_chain_pem, &mat.private_key_pem)
                    .await?;
                Ok(mat)
            }
            CertSource::SelfSignedDev(s) => crate::self_signed::resolve(s).await,
        }
    }
}
