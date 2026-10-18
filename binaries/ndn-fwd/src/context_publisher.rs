//! Publication of the node's stored trust contexts by name (RDR),
//! [`ndn_namespace::publish`] over the context store beside the PIB
//! (`<pib>/contexts/`), on the daemon's in-process face
//! [`CONTEXT_FACE_ID`].

use std::path::Path;

use ndn_face::local::InProcFace;
use ndn_namespace::PibContextStore;
use ndn_namespace::publish::ContextPublisher;
use ndn_transport::FaceId;

pub(crate) const CONTEXT_FACE_ID: u64 = 0xFFFF_0005;

/// Read the context store under `pib_root` and build the replies. Returns
/// the face to attach before build (it exists even when nothing is stored
/// yet, so a context adopted at runtime can be published).
pub(crate) fn prepare(pib_root: &Path) -> (InProcFace, ContextPublisher) {
    ndn_namespace::publish::prepare(&PibContextStore::new(pib_root), FaceId(CONTEXT_FACE_ID))
}
