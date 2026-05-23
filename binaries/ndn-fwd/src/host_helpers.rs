//! Host-binary helpers: address and name parsing, validator construction,
//! content-store builder, and the optional coding + rate-limit loaders.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use ndn_config::CsConfig;
use ndn_packet::Name;
use ndn_store::{ErasedContentStore, LruCs, NullCs, ShardedCs};

pub fn parse_bind_addr(bind: &str, label: &str) -> Option<std::net::SocketAddr> {
    match bind.parse() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!(target: "engine", bind=%bind, error=%e, "invalid {label} bind address");
            None
        }
    }
}

pub fn parse_name(uri: &str) -> Name {
    uri.parse().unwrap_or_else(|_| Name::root())
}

/// `None` when `trust_anchor_pib` is unset. Returns an error (startup
/// failure) if the PIB is unreachable or empty — operators must either
/// populate it or set `require_signed_commands = false`. The resulting
/// validator uses `accept_all`: any Interest signed by a key whose cert
/// is in the anchor set passes.
pub fn load_mgmt_validator(
    cfg: &ndn_config::MgmtSecurityConfig,
) -> Result<Option<Arc<ndn_security::Validator>>> {
    let Some(pib_path_str) = &cfg.trust_anchor_pib else {
        if cfg.require_signed_commands {
            tracing::warn!(
                target: "security",
                "[security.mgmt] require_signed_commands=true but no trust_anchor_pib set; \
                 all management commands will be rejected. \
                 Add trust_anchor_pib or set require_signed_commands=false for dev mode."
            );
        }
        return Ok(None);
    };
    let pib_path = PathBuf::from(pib_path_str);
    let pib = ndn_security::FilePib::open(&pib_path).map_err(|e| {
        anyhow::anyhow!(
            "[security.mgmt] cannot open trust_anchor_pib '{}': {e}. \
             Run `ndn-sec --pib {pib_path_str} keygen --anchor /your/identity` to create one.",
            pib_path.display()
        )
    })?;
    let anchors = pib.trust_anchors().map_err(|e| {
        anyhow::anyhow!(
            "[security.mgmt] failed to load anchors from '{}': {e}",
            pib_path.display()
        )
    })?;
    if anchors.is_empty() {
        return Err(anyhow::anyhow!(
            "[security.mgmt] trust_anchor_pib '{}' contains no trust anchors. \
             Run `ndn-sec --pib {pib_path_str} anchor add /your/identity` to add one.",
            pib_path.display()
        ));
    }
    let schema = ndn_security::TrustSchema::accept_all();
    let validator = ndn_security::Validator::new(schema);
    for anchor in anchors {
        tracing::info!(target: "security", name = %anchor.name, "mgmt: loaded trust anchor");
        validator.add_trust_anchor(anchor);
    }
    Ok(Some(Arc::new(validator)))
}

/// `Some(validator)` when `[security.mgmt].localhop_trust_anchor_pib` is
/// populated; `None` disables `/localhop/nfd/...` registration (mirroring
/// NFD's `enableLocalhop`). Schema is `accept_all`: any Interest signed by
/// a key whose cert chains to an anchor passes.
pub fn load_localhop_validator(
    cfg: &ndn_config::MgmtSecurityConfig,
) -> Result<Option<Arc<ndn_security::Validator>>> {
    let Some(pib_path_str) = &cfg.localhop_trust_anchor_pib else {
        return Ok(None);
    };
    let pib_path = PathBuf::from(pib_path_str);
    let pib = ndn_security::FilePib::open(&pib_path).map_err(|e| {
        anyhow::anyhow!(
            "[security.mgmt] cannot open localhop_trust_anchor_pib '{}': {e}",
            pib_path.display()
        )
    })?;
    let anchors = pib.trust_anchors().map_err(|e| {
        anyhow::anyhow!(
            "[security.mgmt] failed to load anchors from '{}': {e}",
            pib_path.display()
        )
    })?;
    if anchors.is_empty() {
        return Err(anyhow::anyhow!(
            "[security.mgmt] localhop_trust_anchor_pib '{}' contains no trust anchors",
            pib_path.display()
        ));
    }
    let schema = ndn_security::TrustSchema::accept_all();
    let validator = ndn_security::Validator::new(schema);
    for anchor in anchors {
        tracing::info!(target: "security", name = %anchor.name, "localhop: loaded trust anchor");
        validator.add_trust_anchor(anchor);
    }
    Ok(Some(Arc::new(validator)))
}

pub fn build_cs(cfg: &CsConfig) -> Arc<dyn ErasedContentStore> {
    let cap = cfg.capacity_mb * 1024 * 1024;
    match cfg.variant.as_str() {
        "null" => {
            tracing::info!(target: "engine", "content store disabled (variant=null)");
            Arc::new(NullCs)
        }
        "sharded-lru" => {
            let n = cfg.shards.unwrap_or(4);
            tracing::info!(
                target: "engine",
                variant = "sharded-lru",
                shards = n,
                capacity_mb = cfg.capacity_mb,
                "content store"
            );
            Arc::new(ShardedCs::new(
                (0..n).map(|_| LruCs::new(cap / n)).collect(),
            ))
        }
        _ => {
            tracing::info!(
                target: "engine",
                variant = "lru",
                capacity_mb = cfg.capacity_mb,
                "content store"
            );
            Arc::new(LruCs::new(cap))
        }
    }
}

#[cfg(feature = "fec")]
pub fn load_coding_handler(raw_toml: &str) -> Result<Arc<ndn_coding::CodingMgmtHandler>> {
    use anyhow::Context as _;
    let cfg = ndn_coding::CodingConfig::from_toml(raw_toml)
        .map_err(|e| anyhow::anyhow!("parse [coding]: {e}"))?;
    let table: ndn_coding::SharedPolicyTable = Arc::new(ndn_coding::CodingPolicyTable::new());
    cfg.populate(&table)
        .map_err(|e| anyhow::anyhow!("apply [coding]: {e}"))
        .context("[coding] policy")?;
    let n_entries = table.entries().len();
    if n_entries > 0 {
        tracing::info!(
            target: "engine",
            entries = n_entries,
            "fec: installed coding policies from config"
        );
    }
    Ok(Arc::new(ndn_coding::CodingMgmtHandler::new(table)))
}

#[cfg(feature = "rate-limit")]
type RateLimitPair = (
    Option<Arc<ndn_ratelimit::RateLimitMgmtHandler>>,
    Option<Arc<dyn ndn_engine::RateLimitHook>>,
);

#[cfg(feature = "rate-limit")]
pub fn load_rate_limit_pair(raw_toml: &str) -> Result<RateLimitPair> {
    use anyhow::Context as _;
    let cfg = ndn_ratelimit::RateLimitConfig::from_toml(raw_toml)
        .map_err(|e| anyhow::anyhow!("parse [rate-limit]: {e}"))?;
    if cfg.policy.is_empty() {
        return Ok((None, None));
    }
    let table: ndn_ratelimit::SharedPolicyTable =
        Arc::new(ndn_ratelimit::RateLimitPolicyTable::new());
    cfg.populate(&table)
        .map_err(|e| anyhow::anyhow!("apply [rate-limit]: {e}"))
        .context("[rate-limit] policy")?;
    tracing::info!(
        target: "engine",
        entries = table.len(),
        "rate-limit: installed cells from config"
    );
    let handler = Arc::new(ndn_ratelimit::RateLimitMgmtHandler::new(Arc::clone(&table)));
    let hook: Arc<dyn ndn_engine::RateLimitHook> =
        Arc::new(ndn_ratelimit::EngineRateLimitHook::new(table));
    Ok((Some(handler), Some(hook)))
}
