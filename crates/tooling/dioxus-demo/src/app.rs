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

    let _ = use_context_provider(|| EngineCtx {
        handle: Signal::new(None),
        runtime: default_runtime(),
    });

    rsx! {
        Header { face_status }
        main {
            JoinPanel { url }
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

/// Read an invite token from the URL fragment (`#join=<token>`, optionally with
/// `&`-separated extras), if present and non-empty.
fn token_from_fragment() -> Option<String> {
    let hash = web_sys::window()?.location().hash().ok()?;
    hash.trim_start_matches('#')
        .split('&')
        .find_map(|kv| kv.strip_prefix("join=").map(str::to_owned))
        .filter(|t| !t.is_empty())
}

fn js_err(e: wasm_bindgen::JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// NDNCERT onboarding gesture: paste (or scan via a `#join=` link) an invite
/// token, enrol against the embedded CA over the forwarder face, and persist
/// the identity in IndexedDB so a reload stays signed in.
#[component]
fn JoinPanel(url: Signal<String>) -> Element {
    use crate::join::JoinClient;

    let mut token = use_signal(|| token_from_fragment().unwrap_or_default());
    // (cert_name, restored_from_this_device)
    let mut identity = use_signal(|| None::<(String, bool)>);
    let mut joining = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    // On mount, restore a cached identity if one exists (no NDNCERT round-trip).
    use_future(move || async move {
        match JoinClient::open().await {
            Ok(mut c) => match c.try_restore().await {
                Ok(Some(info)) => identity.set(Some((info.cert_name(), info.restored()))),
                Ok(None) => {}
                Err(e) => error.set(Some(js_err(e))),
            },
            Err(e) => error.set(Some(js_err(e))),
        }
    });

    let do_join = move |_| {
        let host = url.read().clone();
        let tok = token.read().clone();
        if tok.is_empty() {
            error.set(Some("paste an invite token first".into()));
            return;
        }
        joining.set(true);
        error.set(None);
        spawn(async move {
            let outcome = async {
                let mut c = JoinClient::open().await.map_err(js_err)?;
                let info = c
                    .join(host, "/demo".to_owned(), "/demo/users".to_owned(), tok)
                    .await
                    .map_err(js_err)?;
                Ok::<_, String>((info.cert_name(), info.restored()))
            }
            .await;
            match outcome {
                Ok(v) => identity.set(Some(v)),
                Err(e) => error.set(Some(e)),
            }
            joining.set(false);
        });
    };

    let do_forget = move |_| {
        spawn(async move {
            if let Ok(c) = JoinClient::open().await {
                let _ = c.forget().await;
            }
            identity.set(None);
            error.set(None);
        });
    };

    let current = identity.read().clone();
    let busy = *joining.read();
    let err = error.read().clone();

    rsx! {
        section { class: "panel",
            h2 { "Join a network" }
            if let Some((cert, restored)) = current {
                p { class: "muted", "Signed in." }
                dl {
                    dt { "Identity" }
                    dd { "data-testid": "join-cert", "{cert}" }
                    dt { "Source" }
                    dd {
                        if restored { "restored from this device" } else { "freshly enrolled" }
                    }
                }
                button { "data-testid": "join-forget", onclick: do_forget, "Forget identity" }
            } else {
                div { class: "field",
                    label { "Forwarder URL" }
                    input {
                        r#type: "text",
                        value: "{url}",
                        oninput: move |e| url.set(e.value()),
                    }
                }
                div { class: "field",
                    label { "Invite token" }
                    input {
                        r#type: "text",
                        "data-testid": "join-token",
                        placeholder: "paste an invite token (or open a #join=… link)",
                        value: "{token}",
                        oninput: move |e| token.set(e.value()),
                    }
                }
                button {
                    "data-testid": "join-submit",
                    disabled: busy,
                    onclick: do_join,
                    if busy { "Joining…" } else { "Join" }
                }
                if let Some(e) = err {
                    p { class: "muted", "Error: {e}" }
                }
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
                        // NDNCERT enrollment: `ca_prefix` is the CA *identity*
                        // (`/demo`); the enroll client appends `/CA/NEW`, so the
                        // CA (serving `/demo/CA/*`) answers. The issued cert
                        // chains to the localhop trust anchor, so ndn-fwd accepts
                        // /localhop/nfd/rib/register signed with it.
                        let ca_prefix: Name = "/demo".parse().expect("static demo CA prefix");
                        let ident_name: Name = format!("/demo/browser/{}", random_short_id())
                            .parse()
                            .expect("synthesised identity name");
                        let identity = match crate::enroll::enroll(&engine, &ca_prefix, &ident_name)
                            .await
                        {
                            Ok(id) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::log_1(
                                    &format!("NDNCERT issued cert: {}", id.cert_name).into(),
                                );
                                id
                            }
                            Err(e) => {
                                #[cfg(target_arch = "wasm32")]
                                web_sys::console::error_1(&format!("enroll failed: {e}").into());
                                tracing::warn!("enroll failed: {e}");
                                return;
                            }
                        };

                        match engine.register_producer_signed(prefix, &identity).await {
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
                                        let cur =
                                            counter.load(std::sync::atomic::Ordering::Relaxed);
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
    let content_type = data.meta_info().map(|m| m.content_type.code()).unwrap_or(0);
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

// Two-tab manual WebRTC demo. Tab A creates an offer, tab B accepts it and
// returns an answer, tab A finalizes. After both reach Connected, "Send
// ping" round-trips bytes over the peer-to-peer datachannel with no NDN
// forwarder in the path.

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
    // Native compile-check placeholder; the real panel is wasm-only.
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
                        // Leak the connector: its lifetime matches the page tab,
                        // and finalize runs asynchronously after this closure
                        // returns.
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

    // Background recv loop: echo "ping…" as "pong: ping…" so two tabs ping
    // each other naturally.
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

/// Handshake state shared between offer/answer creation and finalize. The
/// `'static` connector is intentional: it outlives the onclick callback that
/// spawned the async finalize, and the panel lives as long as the page tab.
#[cfg(target_arch = "wasm32")]
struct PendingState {
    connector: &'static ndn_face_webrtc::WebRtcConnector,
    pending: Option<ndn_face_webrtc::PendingFace>,
}
#[cfg(not(target_arch = "wasm32"))]
struct PendingState;
