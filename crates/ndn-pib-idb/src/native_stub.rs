//! Native-target stub — every method returns [`IdbPibError::NativeUnsupported`].
//! Native callers should use `ndn_security::FilePib`.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::safebag::SafeBag;
use ndn_security::{Signer, Validator};
use thiserror::Error;

/// Error type for the native [`IdbPib`] stub.
#[derive(Debug, Error)]
pub enum IdbPibError {
    /// `IdbPib` is browser-only; a native build reached a stub method.
    #[error("IdbPib is browser-only; this binary was built for native")]
    NativeUnsupported,
}

/// Native-build placeholder for the wasm `IdbPib`.
///
/// Every method returns [`IdbPibError::NativeUnsupported`]. Native callers
/// should use `ndn_security::FilePib` instead.
pub struct IdbPib;

impl IdbPib {
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn open(_db_name: &str) -> Result<Self, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn put_safebag(&self, _name: &Name, _bag: &SafeBag) -> Result<(), IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn get_safebag(&self, _name: &Name) -> Result<Option<SafeBag>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn put_passphrase(&self, _name: &Name, _pw: &[u8]) -> Result<(), IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn get_passphrase(&self, _name: &Name) -> Result<Option<Vec<u8>>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn put_anchor(&self, _name: &Name, _wire: Bytes) -> Result<(), IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn get_anchor(&self, _name: &Name) -> Result<Option<Bytes>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn list_anchors(&self) -> Result<Vec<Name>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn list_safebags(&self) -> Result<Vec<Name>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn build_validator(&self) -> Result<Option<Validator>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn build_signer(&self) -> Result<Option<std::sync::Arc<dyn Signer>>, IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
    /// Stub: always returns [`IdbPibError::NativeUnsupported`].
    pub async fn clear(&self) -> Result<(), IdbPibError> {
        Err(IdbPibError::NativeUnsupported)
    }
}
