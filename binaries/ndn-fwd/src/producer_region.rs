//! The forwarder's producer region (NDNLPv2 ForwardingHint, NFD's
//! NetworkRegionTable): this device's own names, the identities it signs
//! as, kept current as they change.
//!
//! An Interest whose ForwardingHint names this device has reached it: the
//! forwarder strips the hint and forwards the Interest by its name. A relay
//! is thus reachable by its name from a device that routes nothing of the
//! namespace asked for: the device's relay link routes the relay's name,
//! and the relay forwards the hinted Interest by name over the link of the
//! device its name routes (ndn-rs `docs/specs/ndn-link.md` §15.5 "Reaching
//! a device not followed yet"). Nothing here knows the names asked for.

use std::collections::BTreeSet;
use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use tokio_util::sync::CancellationToken;

use crate::active_identity::ActiveIdentity;

/// Make the engine's producer region `identity`'s names now, and again on
/// each change of its identities, until `cancel`.
pub(crate) fn spawn(
    engine: &ForwarderEngine,
    identity: Arc<ActiveIdentity>,
    cancel: CancellationToken,
) {
    let region = engine.network_region();
    let mut changes = identity.changes();
    let mut held = BTreeSet::new();
    follow(&region, &identity, &mut held);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                changed = changes.changed() => if changed.is_err() { return },
            }
            follow(&region, &identity, &mut held);
        }
    });
}

/// Set `region` to the names `identity` signs as, given `held`, the ones
/// set before (updated).
fn follow(
    region: &ndn_engine::stages::strategy::NetworkRegionTable,
    identity: &ActiveIdentity,
    held: &mut BTreeSet<Name>,
) {
    let now: BTreeSet<Name> = identity
        .signing_identities()
        .into_iter()
        .map(|si| si.identity)
        .filter(|name| !name.is_empty())
        .collect();
    for gone in held.difference(&now) {
        region.remove_region(gone);
    }
    for new in now.difference(held) {
        region.add_region(new.clone());
    }
    if *held != now {
        tracing::info!(
            region = ?now.iter().map(Name::to_string).collect::<Vec<_>>(),
            "producer region (a ForwardingHint naming one of these is forwarded by name here)"
        );
    }
    *held = now;
}
