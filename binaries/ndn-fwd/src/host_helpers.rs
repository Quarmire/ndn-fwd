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

/// A [`RecordVerifier`](ndn_discovery::RecordVerifier) backed by an
/// `ndn_security::Validator` (trust anchors for peer service records). The
/// discovery `on_inbound` path is synchronous and the validator's only
/// `.await` points are pure-CPU signature checks, so a single poll drives
/// `validate` to completion; a missing cert yields `Pending` → `Untrusted`
/// (fail-closed).
struct DiscoveryVerifier {
    validator: Arc<ndn_security::Validator>,
}

impl ndn_discovery::RecordVerifier for DiscoveryVerifier {
    fn verify(&self, data: &ndn_packet::Data) -> ndn_discovery::VerifyVerdict {
        use ndn_discovery::VerifyVerdict;
        let identity = data
            .sig_info()
            .and_then(|si| si.key_locator_name())
            .map(|n| (*n).clone());
        match poll_once(self.validator.validate(data)) {
            Some(ndn_security::ValidationResult::Valid(_)) => {
                // `authentic` is true only when the validated signature is asymmetric
                // (keyed) — never a bare DigestSha256, which proves integrity, not
                // authorship. Only an authentic verdict may drive FIB auto-population
                // (ndn-discovery red-team SEC-11). A trust-anchor `Validator` won't
                // return `Valid` for an unkeyed digest in practice, but we derive the
                // flag from the signature type so the FIB gate can never be fed a
                // non-authentic verdict regardless.
                let authentic = data
                    .sig_info()
                    .map(|si| si.sig_type != ndn_packet::SignatureType::DigestSha256)
                    .unwrap_or(false);
                VerifyVerdict::Verified {
                    identity: identity.unwrap_or_else(|| (*data.name).clone()),
                    authentic,
                }
            }
            _ => VerifyVerdict::Untrusted,
        }
    }
}

/// Drive a non-pending (pure-CPU) future to completion with one poll.
fn poll_once<F: std::future::Future>(fut: F) -> Option<F::Output> {
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Build the service-discovery record verifier from
/// `[discovery].trust_anchor_pib`. `None` ⇒ fail-closed (peer records are
/// browseable but never auto-install FIB). Mirrors [`load_mgmt_validator`].
pub fn load_discovery_verifier(
    trust_anchor_pib: Option<&str>,
) -> Result<Option<Arc<dyn ndn_discovery::RecordVerifier>>> {
    let Some(pib_path_str) = trust_anchor_pib else {
        return Ok(None);
    };
    let pib_path = PathBuf::from(pib_path_str);
    let pib = ndn_security::FilePib::open(&pib_path).map_err(|e| {
        anyhow::anyhow!("[discovery] cannot open trust_anchor_pib '{pib_path_str}': {e}")
    })?;
    let anchors = pib
        .trust_anchors()
        .map_err(|e| anyhow::anyhow!("[discovery] failed to load anchors: {e}"))?;
    if anchors.is_empty() {
        return Err(anyhow::anyhow!(
            "[discovery] trust_anchor_pib '{pib_path_str}' contains no trust anchors"
        ));
    }
    let validator = ndn_security::Validator::new(ndn_security::TrustSchema::accept_all());
    for anchor in anchors {
        tracing::info!(target: "discovery", name = %anchor.name, "discovery: loaded trust anchor");
        validator.add_trust_anchor(anchor);
    }
    Ok(Some(Arc::new(DiscoveryVerifier {
        validator: Arc::new(validator),
    })))
}

// This test module sits mid-file (next to the discovery helpers it covers); the
// crate's other `pub fn` helpers follow it, which trips the style lint.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod discovery_verifier_tests {
    use super::*;
    use ndn_discovery::RecordVerifier;
    use ndn_security::KeyChain;

    #[test]
    fn verifier_accepts_anchored_signer_rejects_others() {
        // The forwarder's identity key, self-signed cert added as a
        // discovery trust anchor.
        let kc = KeyChain::ephemeral_ecdsa("/ndn/fwd/peerA").unwrap();
        let anchor = kc.manager_arc().trust_anchor(kc.key_name()).unwrap();
        let validator = ndn_security::Validator::new(ndn_security::TrustSchema::accept_all());
        validator.add_trust_anchor(anchor);
        let verifier = DiscoveryVerifier {
            validator: Arc::new(validator),
        };

        let rec = ndn_discovery::ServiceRecord::new(
            "/ndn/svc/x".parse().unwrap(),
            "/ndn/fwd/peerA".parse().unwrap(),
        );

        // Signed by the anchored key → Verified (proves poll_once drives
        // the ECDSA validate to completion).
        let pkt = rec.build_data_signed(1, &ndn_discovery::SignerAdapter(kc.signer().unwrap()));
        let data = ndn_packet::Data::decode(pkt).unwrap();
        assert!(
            matches!(
                verifier.verify(&data),
                ndn_discovery::VerifyVerdict::Verified { authentic: true, .. }
            ),
            "a record signed by an anchored key must verify AS AUTHENTIC \
             (keyed signature → eligible to drive FIB; ndn-discovery SEC-11)"
        );

        // Signed by a different, un-anchored key → Untrusted.
        let kc2 = KeyChain::ephemeral_ecdsa("/ndn/fwd/attacker").unwrap();
        let pkt2 = rec.build_data_signed(2, &ndn_discovery::SignerAdapter(kc2.signer().unwrap()));
        let data2 = ndn_packet::Data::decode(pkt2).unwrap();
        assert_eq!(
            verifier.verify(&data2),
            ndn_discovery::VerifyVerdict::Untrusted,
            "record signed by an un-anchored key must be untrusted"
        );
    }

    /// End-to-end: the forwarder's real `DiscoveryVerifier` wired into a live
    /// `ServiceDiscoveryProtocol` with auto-FIB, exercising both the SEC-11
    /// (authenticity) and SEC-12 (name→authority) gates against an actual inbound
    /// signed `ServiceRecord` — a keyed, name-bound record installs a route; a
    /// digest-signed one and a keyed-but-foreign-prefix one do not.
    #[test]
    fn discovery_auto_fib_gate_end_to_end() {
        use bytes::Bytes;
        use ndn_discovery::{
            DiscoveryContext, DiscoveryProtocol, FaceLifecycleContext, InboundMeta, NeighborContext,
            NeighborTable, NeighborTableView, NeighborUpdate, ProtocolId, RoutingTableContext,
            ServiceDiscoveryConfig, ServiceDiscoveryProtocol, ServiceRecord, SignerAdapter,
        };
        use ndn_transport::FaceId;
        use std::sync::Mutex;
        use std::time::Instant;

        // A DiscoveryContext that records FIB installs.
        struct FibCtx {
            now: Instant,
            added: Mutex<Vec<Name>>,
        }
        impl FaceLifecycleContext for FibCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(0)
            }
            fn add_face(&self, _: Arc<ndn_transport::Face>) -> FaceId {
                FaceId(0)
            }
            fn remove_face(&self, _: FaceId) {}
        }
        impl RoutingTableContext for FibCtx {
            fn add_fib_entry(&self, p: &Name, _: FaceId, _: u32, _: ProtocolId) {
                self.added.lock().unwrap().push(p.clone());
            }
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
        }
        impl NeighborContext for FibCtx {
            fn neighbors(&self) -> Arc<dyn NeighborTableView> {
                NeighborTable::new()
            }
            fn update_neighbor(&self, _: NeighborUpdate) {}
        }
        impl DiscoveryContext for FibCtx {
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant {
                self.now
            }
        }

        // The forwarder's anchored identity key (KeyLocator => /ndn/fwd/peerA/KEY/..,
        // so its signing namespace for SEC-12 is /ndn/fwd/peerA).
        let kc = KeyChain::ephemeral_ecdsa("/ndn/fwd/peerA").unwrap();
        let anchor = kc.manager_arc().trust_anchor(kc.key_name()).unwrap();
        let validator = ndn_security::Validator::new(ndn_security::TrustSchema::accept_all());
        validator.add_trust_anchor(anchor);
        let verifier = Arc::new(DiscoveryVerifier {
            validator: Arc::new(validator),
        });
        let signer = SignerAdapter(kc.signer().unwrap());

        let build_sd = || {
            // record_verifier present + auto-FIB (on by default) = the gated path.
            let cfg = ServiceDiscoveryConfig {
                record_verifier: Some(verifier.clone() as Arc<dyn ndn_discovery::RecordVerifier>),
                ..ServiceDiscoveryConfig::default()
            };
            ServiceDiscoveryProtocol::new(
                parse_name("/ndn/fwd/here"),
                ndn_discovery::sd_root().clone(),
                cfg,
            )
        };
        let fresh_ctx = || FibCtx {
            now: Instant::now(),
            added: Mutex::new(Vec::new()),
        };
        let installed = |sd: &ServiceDiscoveryProtocol, prefix: &str, ts: u64, keyed: bool| {
            let ctx = fresh_ctx();
            let rec = ServiceRecord::new(parse_name(prefix), parse_name("/ndn/fwd/peerA"));
            let pkt = if keyed {
                rec.build_data_signed(ts, &signer)
            } else {
                rec.build_data(ts) // default DigestSha256 signer
            };
            sd.on_inbound(&pkt, FaceId(10), &InboundMeta::none(), &ctx);
            ctx.added.lock().unwrap().clone()
        };

        // 1. Keyed + announced prefix under the signer's namespace → route installed.
        let added = installed(&build_sd(), "/ndn/fwd/peerA/svc", 1, true);
        assert_eq!(added, vec![parse_name("/ndn/fwd/peerA/svc")], "authentic, name-bound record installs FIB");

        // 2. Digest-signed (integrity only, not authentic) → NO route (SEC-11).
        assert!(
            installed(&build_sd(), "/ndn/fwd/peerA/svc", 2, false).is_empty(),
            "a digest-only record must not install FIB (SEC-11)"
        );

        // 3. Keyed but announced prefix NOT under the signer's namespace → NO route (SEC-12).
        assert!(
            installed(&build_sd(), "/ndn/bank/api", 3, true).is_empty(),
            "a signer cannot install a route outside its own namespace (SEC-12)"
        );
    }
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
