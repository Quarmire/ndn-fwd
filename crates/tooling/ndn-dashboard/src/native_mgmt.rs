//! Desktop `ManagementClient` impl over the Unix-socket `ndn_ipc::MgmtClient`.
//!
//! The orphan rule forbids `impl ManagementClient for ndn_ipc::MgmtClient` here
//! (both the trait and the type are foreign to this crate), so we wrap the
//! client in a local newtype. The `DashboardEngine` (in `ndn-dashboard-core`)
//! stays transport-free and holds whichever `ManagementClient` the platform
//! injects: this on desktop, `WsMgmtClient` on web, a mobile IPC face later.

use ndn_config::ControlParameters;
use ndn_dashboard_core::{ManagementClient, MgmtResponse};
use ndn_ipc::MgmtClient;

/// Newtype wrapper so the dashboard can implement the core-defined
/// `ManagementClient` over the ndn-ipc Unix-socket client.
pub struct NativeMgmtClient(pub MgmtClient);

#[async_trait::async_trait(?Send)]
impl ManagementClient for NativeMgmtClient {
    async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> std::result::Result<MgmtResponse, String> {
        let (status_code, status_text, body) = self
            .0
            .send_cmd_raw(module, verb, params)
            .await
            .map_err(|e| e.to_string())?;
        Ok(MgmtResponse {
            status_code,
            status_text,
            body,
        })
    }
}
