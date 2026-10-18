//! Trust-context updates pushed over each namespace's sync group
//! (`[security] context_sync = true`), beside the periodic refresh:
//! [`ndn_namespace::sync`] with the daemon's member name (a hash of the
//! machine's id and the PIB's path, [`ndn_namespace::sync::member_id`]) and
//! the context store beside the PIB.

use std::path::Path;
use std::sync::Arc;

use ndn_namespace::PibContextStore;
use ndn_namespace::sync::{ContextSync, Groups};

/// With `[security] context_sync`, the handle for the [`TrustAdmin`] and the
/// task to spawn once it exists (`groups.spawn(Arc::clone(&admin.ns), …)`).
///
/// [`TrustAdmin`]: crate::context_adopt::TrustAdmin
pub(crate) fn prepare(enabled: bool, pib_root: &Path) -> Option<(ContextSync, Groups)> {
    enabled.then(|| {
        ndn_namespace::sync::prepare(
            ndn_namespace::sync::member_id(pib_root),
            Arc::new(PibContextStore::new(pib_root)),
        )
    })
}
