use ndn_dashboard_next::core::{
    AttachMode, CapabilitySet, FeatureState, ForwarderKind, ForwarderProfile, ObservePosture,
};
use ndn_dashboard_next::observe::{ObserveSourceState, poll_observe_summary};

fn live_socket_from_env() -> String {
    std::env::var("NDN_DASHBOARD_NEXT_LIVE_NDN_FWD_SOCK")
        .unwrap_or_else(|_| "/tmp/ndn-fwd.sock".into())
        .trim_start_matches("unix://")
        .to_string()
}

fn live_profile(socket: &str, observability: FeatureState) -> ForwarderProfile {
    ForwarderProfile {
        kind: ForwarderKind::NdnRs,
        version: "live ndn-fwd".into(),
        endpoint: format!("unix://{socket}"),
        attach_mode: AttachMode::LocalDesktop,
        capabilities: CapabilitySet {
            nfd_basic: FeatureState::Enabled,
            ndnrs_native: FeatureState::Enabled,
            observability,
            trust_context: FeatureState::Disabled,
            tools: FeatureState::Enabled,
        },
    }
}

#[tokio::test]
#[ignore = "requires a running ndn-fwd socket with observability disabled; use dashboard_next_observe_disabled_ndn_fwd.sh"]
async fn desktop_live_ndn_fwd_observability_disabled_shows_guidance() {
    let socket = live_socket_from_env();
    let mgmt = ndn_ipc::MgmtClient::connect(&socket)
        .await
        .expect("connect to live ndn-fwd management socket");
    mgmt.status().await.expect("status/general dataset");

    let summary = poll_observe_summary(
        live_profile(&socket, FeatureState::Disabled),
        ObservePosture::Disabled,
    )
    .await;
    assert_eq!(summary.source, ObserveSourceState::Disabled);
    assert!(summary.recent.is_empty());
    assert!(
        summary
            .guidance
            .as_deref()
            .unwrap_or_default()
            .contains("disabled"),
        "disabled observe guidance should name the disabled publisher state"
    );
}

#[tokio::test]
#[ignore = "requires a running ndn-fwd socket with observability enabled; use dashboard_next_observe_enabled_ndn_fwd.sh"]
async fn desktop_live_ndn_fwd_observability_enabled_lists_traces() {
    let socket = live_socket_from_env();
    let mgmt = ndn_ipc::MgmtClient::connect(&socket)
        .await
        .expect("connect to live ndn-fwd management socket");

    let profile = live_profile(&socket, FeatureState::Enabled);
    let mut last_summary = None;
    for _ in 0..8 {
        mgmt.status().await.expect("status/general dataset");
        mgmt.face_list().await.expect("faces/list dataset");

        let summary = poll_observe_summary(profile.clone(), ObservePosture::Enabled).await;
        if summary.source == ObserveSourceState::Live && !summary.recent.is_empty() {
            assert!(
                summary
                    .recent
                    .iter()
                    .any(|trace| trace.spans.iter().any(|span| !span.name.is_empty())),
                "live Observe summary should contain decoded OTLP spans"
            );
            return;
        }
        last_summary = Some(summary);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    panic!("live observability did not list traces: {last_summary:#?}");
}
