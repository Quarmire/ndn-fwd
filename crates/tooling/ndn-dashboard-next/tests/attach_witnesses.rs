use ndn_dashboard_next::client::{
    BrowserEngineClient, DashboardClient, DesktopLocalClient, ProbeEndpoint, state_from_probe,
};
use ndn_dashboard_next::core::{
    AttachMode, FeatureState, ForwarderKind, ObservePosture, PlatformKind, TrustPosture,
};
use ndn_dashboard_next::engine::{DatasetState, poll_engine_summary};

fn live_socket_from_env() -> String {
    std::env::var("NDN_DASHBOARD_NEXT_LIVE_NDN_FWD_SOCK")
        .unwrap_or_else(|_| "/tmp/ndn-fwd.sock".into())
        .trim_start_matches("unix://")
        .to_string()
}

#[test]
fn desktop_attach_witness_normalizes_local_ndn_fwd_profile() {
    let client = DesktopLocalClient {
        socket: "unix:///run/ndn-fwd/mgmt.sock".into(),
    };
    let target = client
        .attach_targets()
        .into_iter()
        .next()
        .expect("desktop attach target");

    assert_eq!(target.mode, AttachMode::LocalDesktop);
    assert_eq!(target.profile_hint, Some(ForwarderKind::NdnRs));

    let probe = client.probe(&target).expect("desktop probe");
    assert!(probe.transcript.saw_ok(ProbeEndpoint::NfdStatusGeneral));
    assert!(probe.transcript.saw_ok(ProbeEndpoint::NfdFacesList));
    assert!(probe.transcript.saw_ok(ProbeEndpoint::NdnRsCapabilities));

    let state = state_from_probe(PlatformKind::Desktop, probe);
    assert_eq!(state.profile.kind, ForwarderKind::NdnRs);
    assert_eq!(state.profile.capabilities.nfd_basic, FeatureState::Enabled);
    assert_eq!(
        state.profile.capabilities.ndnrs_native,
        FeatureState::Enabled
    );
    assert_eq!(state.observe, ObservePosture::Enabled);
    assert_eq!(state.trust, TrustPosture::Valid);
}

#[tokio::test]
#[ignore = "requires a running ndn-fwd socket; use the testbed dashboard_next_desktop_attach_ndn_fwd.sh witness"]
async fn desktop_live_ndn_fwd_socket_answers_management_probe() {
    let socket = live_socket_from_env();
    let mgmt = ndn_ipc::MgmtClient::connect(&socket)
        .await
        .expect("connect to live ndn-fwd management socket");

    mgmt.status().await.expect("status/general dataset");
    let faces = mgmt.face_list().await.expect("faces/list dataset");
    assert!(
        !faces.is_empty(),
        "live ndn-fwd should report at least one face"
    );

    let client = DesktopLocalClient {
        socket: format!("unix://{socket}"),
    };
    let target = client
        .attach_targets()
        .into_iter()
        .next()
        .expect("desktop attach target");
    let probe = client
        .probe(&target)
        .expect("dashboard probe normalization");
    let state = state_from_probe(PlatformKind::Desktop, probe);

    assert_eq!(state.profile.kind, ForwarderKind::NdnRs);
    assert_eq!(state.profile.capabilities.nfd_basic, FeatureState::Enabled);
    assert_eq!(state.observe, ObservePosture::Enabled);

    let engine = poll_engine_summary(state.profile)
        .await
        .expect("dashboard Engine live poll");
    assert!(engine.status.is_some());
    assert!(!engine.faces.is_empty());
    assert!(
        engine
            .sources
            .iter()
            .any(|source| source.name == "status/general" && source.state == DatasetState::Fresh)
    );
}

#[test]
fn browser_attach_witness_uses_browser_safe_in_page_engine() {
    let client = BrowserEngineClient;
    let target = client
        .attach_targets()
        .into_iter()
        .next()
        .expect("browser engine target");

    assert_eq!(target.mode, AttachMode::BrowserEngine);
    assert_eq!(target.profile_hint, Some(ForwarderKind::BrowserEngine));

    let probe = client.probe(&target).expect("browser engine probe");
    assert!(probe.transcript.saw_ok(ProbeEndpoint::NfdStatusGeneral));
    assert!(probe.transcript.saw_ok(ProbeEndpoint::NdnRsCapabilities));

    let state = state_from_probe(PlatformKind::Browser, probe);
    assert_eq!(state.profile.kind, ForwarderKind::BrowserEngine);
    assert_eq!(state.profile.capabilities.nfd_basic, FeatureState::Enabled);
    assert_eq!(
        state.profile.capabilities.ndnrs_native,
        FeatureState::Enabled
    );
    assert_eq!(state.observe, ObservePosture::Degraded);
    assert_eq!(state.trust, TrustPosture::Valid);
}
