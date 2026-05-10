//! Dioxus components for the in-browser demo.

use std::sync::Arc;
use std::time::Duration;

use dioxus::prelude::*;
use ndn_packet::{Name, SignatureType};
use ndn_runtime::{Runtime, default_runtime};

use crate::engine::{DataResponse, Engine, EngineError};
use crate::state::{DataView, FaceStatus};

const DEFAULT_URL: &str = "https://localhost:4433/ndn";
const DEFAULT_LIFETIME: Duration = Duration::from_millis(4000);

#[derive(Clone)]
struct EngineCtx {
    handle: Signal<Option<Arc<Engine>>>,
    runtime: Arc<dyn Runtime>,
}

pub fn App() -> Element {
    let face_status = use_signal(|| FaceStatus::Idle);
    let url = use_signal(|| DEFAULT_URL.to_owned());

    let producer_prefix = use_signal(random_demo_prefix);
    let producer_counter = use_signal(|| 0u64);

    let last_data = use_signal(|| None::<DataView>);
    let last_error = use_signal(|| None::<String>);
    let interest_name = use_signal(|| "/demo/hello".to_owned());

    let ctx = use_context_provider(|| EngineCtx {
        handle: Signal::new(None),
        runtime: default_runtime(),
    });
    let _ = ctx; // context registered; consumed via use_context

    rsx! {
        Header { face_status }
        main {
            FacePanel { face_status, url, producer_prefix, producer_counter }
            ConsumerPanel { interest_name, last_data, last_error, face_status }
            ProducerPanel { producer_prefix, producer_counter, face_status }
            WebRtcPanel {}
        }
    }
}

#[component]
fn Header(face_status: Signal<FaceStatus>) -> Element {
    let label = face_status.read().label();
    rsx! {
        header {
            h1 { "ndn-rs in the browser" }
            div {
                class: "face-status {label}",
                "data-testid": "face-status",
                "{label}"
            }
        }
    }
}

#[component]
fn FacePanel(
    face_status: Signal<FaceStatus>,
    url: Signal<String>,
    producer_prefix: Signal<String>,
    producer_counter: Signal<u64>,
) -> Element {
    let ctx = use_context::<EngineCtx>();

    let connect = move |_| {
        let url_now = url.read().clone();
        let prefix_str = producer_prefix.read().clone();
        let runtime = Arc::clone(&ctx.runtime);
        let mut handle = ctx.handle;
        let mut status = face_status;
        let mut counter_sig = producer_counter;
        status.set(FaceStatus::Connecting);
        spawn(async move {
            match Engine::connect(runtime.clone(), &url_now).await {
                Ok(engine) => {
                    let engine = Arc::new(engine);
                    handle.set(Some(Arc::clone(&engine)));
                    status.set(FaceStatus::Connected);

                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::log_1(
                        &format!("connect ok; registering prefix={prefix_str}").into(),
                    );
                    let parsed = prefix_str.parse::<Name>();
                    #[cfg(target_arch = "wasm32")]
                    if parsed.is_err() {
                        web_sys::console::error_1(
                            &format!("prefix parse failed: {prefix_str}").into(),
                        );
                    }
                    if let Ok(prefix) = parsed {
                        // NDNCERT enrollment against /demo/CA — issued
                        // cert chains to the localhop trust anchor, so
                        // /localhop/nfd/rib/register signed with this
                        // identity is accepted by ndn-fwd.
                        let ca_prefix: Name = "/demo/CA"
                            .parse()
                            .expect("static demo CA prefix");
                        let ident_name: Name =
                            format!("/demo/browser/{}", random_short_id())
                                .parse()
                                .expect("synthesised identity name");
                        let identity = match crate::enroll::enroll(
                            &engine,
                            &ca_prefix,
                            &ident_name,
                        )
                        .await
                        {
                            Ok(id) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::log_1(
                                    &format!("NDNCERT issued cert: {}", id.cert_name)
                                        .into(),
                                );
                                id
                            }
                            Err(e) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::error_1(
                                    &format!("enroll failed: {e}").into(),
                                );
                                tracing::warn!("enroll failed: {e}");
                                return;
                            }
                        };

                        match engine
                            .register_producer_signed(prefix, &identity)
                            .await
                        {
                            Ok(counter) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::log_1(
                                    &"signed /localhop register Interest sent".into(),
                                );
                                let rt = Arc::clone(&runtime);
                                spawn(async move {
                                    let mut last = 0u64;
                                    loop {
                                        rt.sleep(std::time::Duration::from_millis(200)).await;
                                        let cur = counter.load(
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        if cur != last {
                                            counter_sig.set(cur);
                                            last = cur;
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::error_1(
                                    &format!("register_producer failed: {e}").into(),
                                );
                                tracing::warn!("register_producer failed: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    status.set(FaceStatus::Disconnected(e.to_string()));
                }
            }
        });
    };

    rsx! {
        section { class: "panel",
            h2 { "Face" }
            div { class: "field",
                label { "Forwarder URL" }
                input {
                    r#type: "text",
                    value: "{url}",
                    oninput: move |e| url.set(e.value()),
                }
            }
            button {
                "data-testid": "face-connect",
                onclick: connect,
                "Connect"
            }
            dl {
                dt { "kind" } dd { "WebTransport" }
                dt { "id" }   dd { "1" }
                dt { "url" }  dd { "{url}" }
            }
        }
    }
}

#[component]
fn ConsumerPanel(
    interest_name: Signal<String>,
    last_data: Signal<Option<DataView>>,
    last_error: Signal<Option<String>>,
    face_status: Signal<FaceStatus>,
) -> Element {
    let ctx = use_context::<EngineCtx>();

    let express = move |_| {
        let Some(engine) = ctx.handle.read().clone() else {
            return;
        };
        let raw = interest_name.read().clone();
        let Ok(name) = raw.parse::<Name>() else {
            last_error.clone().set(Some(format!("invalid name: {raw}")));
            return;
        };
        let mut data_sig = last_data;
        let mut err_sig = last_error;
        spawn(async move {
            match engine.express(name, DEFAULT_LIFETIME).await {
                Ok(resp) => {
                    data_sig.set(Some(view_from_response(&resp)));
                    err_sig.set(None);
                }
                Err(EngineError::Timeout) => {
                    data_sig.set(None);
                    err_sig.set(Some("timeout".into()));
                }
                Err(e) => {
                    err_sig.set(Some(e.to_string()));
                }
            }
        });
    };

    let connected = matches!(*face_status.read(), FaceStatus::Connected);
    let data = last_data.read().clone();
    let err = last_error.read().clone();

    rsx! {
        section { class: "panel",
            h2 { "Consumer" }
            div { class: "field",
                label { "Name" }
                input {
                    r#type: "text",
                    "data-testid": "interest-name",
                    value: "{interest_name}",
                    oninput: move |e| interest_name.set(e.value()),
                }
            }
            button {
                "data-testid": "express-interest",
                disabled: !connected,
                onclick: express,
                "Express Interest"
            }
            if let Some(d) = data {
                dl {
                    dt { "Name" }            dd { "data-testid": "data-name", "{d.name}" }
                    dt { "ContentType" }     dd { "{d.content_type}" }
                    dt { "Freshness (ms)" }  dd {
                        match d.freshness {
                            Some(f) => format!("{}", f.as_millis()),
                            None => "—".to_owned(),
                        }
                    }
                    dt { "Payload (bytes)" } dd { "data-testid": "data-payload-len", "{d.payload_len}" }
                    dt { "Signature" }       dd { "{d.sig_type}" }
                    dt { "RTT (ms)" }        dd {
                        "data-testid": "data-rtt-ms",
                        match d.rtt {
                            Some(r) => format!("{}", r.as_millis()),
                            None => "—".to_owned(),
                        }
                    }
                }
            } else if let Some(e) = err {
                p { class: "muted", "Error: {e}" }
            } else {
                p { class: "muted", "No Data yet." }
            }
        }
    }
}

#[component]
fn ProducerPanel(
    producer_prefix: Signal<String>,
    producer_counter: Signal<u64>,
    face_status: Signal<FaceStatus>,
) -> Element {
    let connected = matches!(*face_status.read(), FaceStatus::Connected);
    rsx! {
        section { class: "panel",
            h2 { "Producer" }
            dl {
                dt { "Prefix" }  dd { "data-testid": "producer-prefix", "{producer_prefix}" }
                dt { "Counter" } dd { "data-testid": "producer-counter", "{producer_counter}" }
                dt { "State" }   dd {
                    if connected { "registered — serving /counter" } else { "waiting for face" }
                }
            }
            p { class: "muted",
                "On Connect, sends /localhost/nfd/rib/register with the \
                 prefix as ApplicationParameters. Inbound Interests under \
                 the registered prefix are answered with a DigestSha256-signed \
                 Data carrying a monotonic counter."
            }
        }
    }
}

fn view_from_response(resp: &DataResponse) -> DataView {
    let data = &resp.data;
    let content_type = data
        .meta_info()
        .map(|m| m.content_type.code())
        .unwrap_or(0);
    let freshness = data.meta_info().and_then(|m| m.freshness_period);
    let payload_len = data.content().map(|b| b.len()).unwrap_or(0);
    let sig_type = data
        .sig_info()
        .map(|s| sig_type_label(s.sig_type))
        .unwrap_or_else(|| "—".to_owned());
    DataView {
        name: data.name.to_string(),
        content_type,
        freshness,
        payload_len,
        sig_type,
        rtt: Some(resp.rtt),
    }
}

fn sig_type_label(t: SignatureType) -> String {
    match t {
        SignatureType::DigestSha256 => "DigestSha256".into(),
        SignatureType::SignatureSha256WithRsa => "Sha256WithRsa".into(),
        SignatureType::SignatureSha256WithEcdsa => "Sha256WithEcdsa".into(),
        SignatureType::SignatureHmacWithSha256 => "HmacSha256".into(),
        SignatureType::SignatureEd25519 => "Ed25519".into(),
        SignatureType::Other(n) => format!("type={n}"),
    }
}

fn random_demo_prefix() -> String {
    format!("/demo/{}", random_short_id())
}

fn random_short_id() -> String {
    let mut bytes = [0u8; 4];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── WebRTC peer panel ───────────────────────────────────────────────────────
//
// Two-tab manual demo. Tab A clicks "Create offer", copies the
// printed bundle, pastes it into tab B's "Accept offer" box. Tab
// B clicks "Accept", copies its answer bundle, pastes it back
// into tab A's "Finalize with answer" box. Both tabs go to
// "Connected"; "Send ping" round-trips a payload over the
// peer-to-peer SCTP/DTLS datachannel — no NDN forwarder in the
// path.
//
// This panel exists to validate the wasm WebRtcConnector at
// runtime. Compilation passing is necessary but not sufficient;
// `web_sys::RtcPeerConnection` callbacks have to actually fire,
// the closure-bag bookkeeping has to keep them alive, and the
// SDP/ICE flow has to round-trip. The HTTP relay path
// automates this, but two-tab manual paste is the simplest
// reproducible witness for the panel itself.

#[derive(Clone, Debug, PartialEq)]
enum RtcStatus {
    Idle,
    Offering,
    Accepting,
    Connecting,
    Connected,
    Error(String),
}

#[component]
#[cfg(not(target_arch = "wasm32"))]
fn WebRtcPanel() -> Element {
    // Native build — the wasm WebRtcConnector and the
    // PendingState fields below only exist under
    // `cfg(target_arch = "wasm32")`. Render a placeholder so
    // dioxus-demo still compiles for `cargo build` /
    // `cargo clippy` on the host toolchain. The user-facing demo
    // is wasm-only by construction.
    rsx! {
        section { class: "panel rtc-panel",
            h2 { "WebRTC Peer (browser-as-peer demo)" }
            p { "Available only in the wasm browser build of dioxus-demo." }
        }
    }
}

#[component]
#[cfg(target_arch = "wasm32")]
fn WebRtcPanel() -> Element {
    use ndn_face_webrtc::signaling::manual::{Bundle, decode_bundle, encode_bundle};
    use ndn_face_webrtc::{IceServers, RtcChannel, WebRtcConnector};

    let mut status = use_signal(|| RtcStatus::Idle);
    let mut offer_blob = use_signal(String::new);
    let mut answer_input = use_signal(String::new);
    let mut peer_offer_input = use_signal(String::new);
    let mut answer_blob = use_signal(String::new);
    let mut last_message = use_signal(|| None::<String>);
    let pending: Signal<Option<std::rc::Rc<std::cell::RefCell<Option<PendingState>>>>> =
        use_signal(|| None);
    let face: Signal<Option<std::rc::Rc<std::cell::RefCell<Option<ndn_face_webrtc::WebRtcFace>>>>> =
        use_signal(|| None);

    // Offerer flow.
    let create_offer = {
        let mut status = status;
        let mut offer_blob = offer_blob;
        let mut pending = pending;
        move |_| {
            let mut status = status;
            let mut offer_blob = offer_blob;
            let mut pending = pending;
            spawn(async move {
                status.set(RtcStatus::Offering);
                let connector = match WebRtcConnector::new(IceServers::default()) {
                    Ok(c) => c,
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("connector: {e}")));
                        return;
                    }
                };
                match connector.create_offer().await {
                    Ok((offer, p)) => {
                        let bundle = Bundle {
                            description: offer,
                            candidates: vec![],
                        };
                        match encode_bundle(&bundle) {
                            Ok(s) => offer_blob.set(s),
                            Err(e) => {
                                status.set(RtcStatus::Error(format!("encode: {e}")));
                                return;
                            }
                        }
                        // Stash pending + connector for the finalize step.
                        // Box::leak is fine: this panel's lifetime == page tab.
                        let connector: &'static _ = Box::leak(Box::new(connector));
                        let state = PendingState {
                            connector,
                            pending: Some(p),
                        };
                        pending.set(Some(std::rc::Rc::new(std::cell::RefCell::new(Some(state)))));
                        status.set(RtcStatus::Connecting);
                    }
                    Err(e) => status.set(RtcStatus::Error(format!("offer: {e}"))),
                }
            });
        }
    };

    // Answerer flow: accept a pasted offer bundle, produce an answer.
    let accept_offer = {
        let mut status = status;
        let mut answer_blob = answer_blob;
        let mut peer_offer_input = peer_offer_input;
        let mut face = face;
        move |_| {
            let blob_text = peer_offer_input.read().clone();
            let mut status = status;
            let mut answer_blob = answer_blob;
            let mut face = face;
            peer_offer_input.set(String::new());
            spawn(async move {
                status.set(RtcStatus::Accepting);
                let bundle = match decode_bundle(&blob_text) {
                    Ok(b) => b,
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("decode offer: {e}")));
                        return;
                    }
                };
                let connector = match WebRtcConnector::new(IceServers::default()) {
                    Ok(c) => c,
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("connector: {e}")));
                        return;
                    }
                };
                let (answer, pending_face) = match connector.accept_offer(bundle.description).await
                {
                    Ok(p) => p,
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("accept: {e}")));
                        return;
                    }
                };
                let answer_bundle = Bundle {
                    description: answer,
                    candidates: vec![],
                };
                match encode_bundle(&answer_bundle) {
                    Ok(s) => answer_blob.set(s),
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("encode answer: {e}")));
                        return;
                    }
                }
                status.set(RtcStatus::Connecting);
                match connector.finalize_pending(pending_face).await {
                    Ok(f) => {
                        face.set(Some(std::rc::Rc::new(std::cell::RefCell::new(Some(f)))));
                        status.set(RtcStatus::Connected);
                    }
                    Err(e) => status.set(RtcStatus::Error(format!("finalize: {e}"))),
                }
            });
        }
    };

    // Offerer's finalize: paste the answerer's bundle.
    let finalize = {
        let mut status = status;
        let mut answer_input = answer_input;
        let mut face = face;
        let mut pending = pending;
        move |_| {
            let blob_text = answer_input.read().clone();
            let mut status = status;
            let mut face = face;
            let pending_holder = pending.read().clone();
            answer_input.set(String::new());
            spawn(async move {
                let Some(holder) = pending_holder else {
                    status.set(RtcStatus::Error("no offer in flight".into()));
                    return;
                };
                let mut state = match holder.borrow_mut().take() {
                    Some(s) => s,
                    None => {
                        status.set(RtcStatus::Error("offer already consumed".into()));
                        return;
                    }
                };
                let bundle = match decode_bundle(&blob_text) {
                    Ok(b) => b,
                    Err(e) => {
                        status.set(RtcStatus::Error(format!("decode answer: {e}")));
                        return;
                    }
                };
                let pending_face = state.pending.take().expect("pending only finalized once");
                match state
                    .connector
                    .finalize_with_answer(pending_face, bundle.description)
                    .await
                {
                    Ok(f) => {
                        face.set(Some(std::rc::Rc::new(std::cell::RefCell::new(Some(f)))));
                        status.set(RtcStatus::Connected);
                    }
                    Err(e) => status.set(RtcStatus::Error(format!("finalize: {e}"))),
                }
            });
            pending.set(None);
        }
    };

    // Send ping over the live datachannel; the receiver echoes
    // it back via its own recv-loop (set up below).
    let send_ping = {
        let face = face;
        let last_message = last_message;
        let status = status;
        move |_| {
            let face_holder = face.read().clone();
            let mut last_message = last_message;
            let mut status = status;
            spawn(async move {
                let Some(holder) = face_holder else {
                    status.set(RtcStatus::Error("not connected".into()));
                    return;
                };
                let f = holder.borrow();
                let Some(face) = f.as_ref() else {
                    status.set(RtcStatus::Error("face dropped".into()));
                    return;
                };
                let chan = face.channel();
                let payload = bytes::Bytes::from_static(b"ping from dioxus-demo");
                if let Err(e) = chan.send(payload).await {
                    status.set(RtcStatus::Error(format!("send: {e}")));
                    return;
                }
                last_message.set(Some("(sent ping; awaiting pong from peer)".into()));
            });
        }
    };

    // Background: poll the live face for inbound bytes; echo
    // them back with a "pong: " prefix so two tabs ping each
    // other naturally.
    use_effect({
        let face = face;
        let mut last_message = last_message;
        move || {
            let face_holder = face.read().clone();
            if let Some(holder) = face_holder {
                spawn(async move {
                    let chan = {
                        let guard = holder.borrow();
                        guard.as_ref().map(|f| f.channel())
                    };
                    let Some(chan) = chan else { return };
                    while let Ok(bytes) = chan.recv().await {
                        let text = String::from_utf8_lossy(&bytes).to_string();
                        last_message.set(Some(format!("recv: {text}")));
                        // Auto-echo: reply with "pong: …" once.
                        if text.starts_with("ping") {
                            let echo = format!("pong: {text}");
                            let _ = chan.send(bytes::Bytes::from(echo)).await;
                        }
                    }
                });
            }
        }
    });

    let status_label = match status.read().clone() {
        RtcStatus::Idle => "idle".to_string(),
        RtcStatus::Offering => "creating offer…".to_string(),
        RtcStatus::Accepting => "accepting offer…".to_string(),
        RtcStatus::Connecting => "connecting (waiting for handshake)…".to_string(),
        RtcStatus::Connected => "connected (peer-to-peer)".to_string(),
        RtcStatus::Error(e) => format!("error: {e}"),
    };

    let last_msg = last_message.read().clone().unwrap_or_default();
    let offer_text = offer_blob.read().clone();
    let answer_text = answer_blob.read().clone();
    let connected = matches!(status.read().clone(), RtcStatus::Connected);

    rsx! {
        section { class: "panel rtc-panel",
            h2 { "WebRTC Peer (browser-as-peer demo)" }
            p {
                "Two-tab manual signaling. One tab clicks "
                em { "Create offer" }
                ", pastes the bundle into the other tab's "
                em { "Accept offer" }
                " box, copies the answer back, and the offerer pastes it into "
                em { "Finalize with answer" }
                ". After both go to "
                em { "connected" }
                ", "
                em { "Send ping" }
                " round-trips bytes peer-to-peer with no forwarder in the path."
            }
            dl { class: "kv",
                dt { "Status" } dd { "data-testid": "rtc-status", "{status_label}" }
            }

            div { class: "rtc-actions",
                button {
                    "data-testid": "rtc-create-offer",
                    onclick: create_offer,
                    disabled: connected,
                    "Create offer"
                }
                button {
                    "data-testid": "rtc-accept-offer",
                    onclick: accept_offer,
                    disabled: connected,
                    "Accept offer (paste below first)"
                }
                button {
                    "data-testid": "rtc-finalize",
                    onclick: finalize, disabled: connected,
                    "Finalize with answer (paste below first)"
                }
                button {
                    "data-testid": "rtc-send-ping",
                    onclick: send_ping,
                    disabled: !connected,
                    "Send ping"
                }
            }

            div { class: "rtc-blobs",
                label { "Outgoing offer (copy to peer):"
                    textarea {
                        "data-testid": "rtc-offer-out",
                        readonly: true,
                        rows: "3",
                        value: "{offer_text}",
                    }
                }
                label { "Outgoing answer (copy to peer):"
                    textarea {
                        "data-testid": "rtc-answer-out",
                        readonly: true,
                        rows: "3",
                        value: "{answer_text}",
                    }
                }
                label { "Paste peer's offer here:"
                    textarea {
                        "data-testid": "rtc-offer-in",
                        rows: "3",
                        oninput: move |e| peer_offer_input.set(e.value()),
                        value: "{peer_offer_input.read()}",
                    }
                }
                label { "Paste peer's answer here:"
                    textarea {
                        "data-testid": "rtc-answer-in",
                        rows: "3",
                        oninput: move |e| answer_input.set(e.value()),
                        value: "{answer_input.read()}",
                    }
                }
            }

            if !last_msg.is_empty() {
                p { class: "rtc-msg", "data-testid": "rtc-msg", "{last_msg}" }
            }
        }
    }
}

/// State held between offer/answer create and finalize. We need
/// to keep the connector + pending face together because the
/// async tasks that drive the handshake outlive the synchronous
/// onclick callback that started them.
///
/// `'static` connector via `Box::leak` is intentional: the panel
/// lives as long as the page tab, and a leaked `WebRtcConnector`
/// is a couple of hundred bytes.
#[cfg(target_arch = "wasm32")]
struct PendingState {
    connector: &'static ndn_face_webrtc::WebRtcConnector,
    pending: Option<ndn_face_webrtc::PendingFace>,
}
#[cfg(not(target_arch = "wasm32"))]
struct PendingState;
