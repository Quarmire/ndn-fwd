//! SharedWorker entry point. Loaded inside the per-origin
//! `SharedWorker` scope: optionally dials a single
//! `BrowserWebTransportFace` upstream, builds a face-agnostic [`Engine`],
//! pre-registers producer prefixes, installs a [`WorkerListener`], and
//! registers each tab `MessagePort` as an inbound face.
//!
//! The first tab's `connect` event can fire before `init_worker_scope`
//! runs. The JS bootstrap installs a synchronous `onconnect` that
//! buffers ports and drains them through [`accept_port_from_js`] once
//! the listener is stashed.

use std::cell::RefCell;
use std::sync::Arc;

use wasm_bindgen::prelude::*;
use web_sys::MessagePort;

use ndn_face_shared_worker::{WorkerListener, init_worker_scope};
use ndn_face_webtransport_wasm::BrowserWebTransportFace;
use ndn_packet::Name;
use ndn_runtime::default_runtime;
use ndn_transport::{Face, FaceId, Transport};

use crate::engine::Engine;

fn worker_log(msg: &str) {
    web_sys::console::log_1(&format!("[shared-worker] {msg}").into());
}

thread_local! {
    static LISTENER: RefCell<Option<Arc<WorkerListener>>> = const { RefCell::new(None) };
}

/// `upstream_url` empty skips the WT dial (producers + CS still work).
/// `producers` is a comma-separated prefix list registered locally before
/// any tab ports are accepted.
#[wasm_bindgen]
pub async fn worker_main(upstream_url: String, producers: String) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    worker_log(&format!(
        "starting; upstream={} producers={}",
        if upstream_url.is_empty() {
            "<none>"
        } else {
            &upstream_url
        },
        if producers.is_empty() {
            "<none>"
        } else {
            &producers
        },
    ));

    let runtime = default_runtime();

    let upstream: Option<Arc<Face>> = if upstream_url.is_empty() {
        None
    } else {
        let face =
            BrowserWebTransportFace::connect(FaceId(1), &upstream_url, &[], Arc::clone(&runtime))
                .await
                .map_err(|e| JsValue::from_str(&format!("upstream connect: {e:?}")))?;
        Some(Arc::new(Face::from_transport(face)))
    };

    // On a first-run page IdbPib has neither anchors nor a SafeBag, and the
    // engine boots permissive + DigestSha256-signed. After enrollment
    // populates both, subsequent worker_main calls upgrade to validated
    // inbound Data and persisted-identity-signed mgmt responses.
    let (validator, signer): (
        Option<Arc<ndn_security::Validator>>,
        Option<Arc<dyn ndn_security::Signer>>,
    ) = match ndn_pib_idb::IdbPib::open("dioxus-demo").await {
        Ok(pib) => {
            let v = match pib.build_validator().await {
                Ok(Some(v)) => {
                    worker_log("loaded validator from IdbPib trust anchors");
                    Some(Arc::new(v))
                }
                Ok(None) => None,
                Err(e) => {
                    worker_log(&format!("IdbPib build_validator: {e}"));
                    None
                }
            };
            let s = match pib.build_signer().await {
                Ok(Some(s)) => {
                    worker_log(&format!("loaded signer from IdbPib: {}", s.key_name()));
                    Some(s)
                }
                Ok(None) => None,
                Err(e) => {
                    worker_log(&format!("IdbPib build_signer: {e}"));
                    None
                }
            };
            (v, s)
        }
        Err(e) => {
            worker_log(&format!("IdbPib open: {e}"));
            (None, None)
        }
    };

    // Without a persisted identity, fall back to an ephemeral in-memory
    // ECDSA-P256 signer for mgmt responses — ECDSA is the
    // lowest-common-denominator with ndn-cxx, which has no Ed25519
    // `KeyType`. An IdbPib-persisted SafeBag, when present, takes
    // precedence regardless of algorithm.
    let signer = match signer {
        Some(s) => Some(s),
        None => match ndn_security::KeyChain::ephemeral_ecdsa("/dioxus-demo/ephemeral") {
            Ok(kc) => {
                let key_name = kc.key_name().clone();
                let arc_mgr = kc.into_manager_arc();
                match arc_mgr.get_signer_sync(&key_name) {
                    Ok(s) => {
                        worker_log(&format!("ephemeral signer: {}", key_name));
                        Some(s)
                    }
                    Err(e) => {
                        worker_log(&format!("ephemeral signer fetch: {e}"));
                        None
                    }
                }
            }
            Err(e) => {
                worker_log(&format!("ephemeral keychain: {e}"));
                None
            }
        },
    };

    let engine = Arc::new(Engine::new_with_security(
        Arc::clone(&runtime),
        upstream,
        validator,
        signer,
    ));

    for raw in producers.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<Name>() {
            Ok(prefix) => {
                engine.register_producer_local(prefix.clone()).await;
                worker_log(&format!("registered local producer {prefix}"));
            }
            Err(_) => worker_log(&format!("skipped invalid prefix {trimmed:?}")),
        }
    }

    let listener =
        Arc::new(init_worker_scope().map_err(|e| JsValue::from_str(&format!("listener: {e}")))?);
    LISTENER.with(|cell| *cell.borrow_mut() = Some(Arc::clone(&listener)));
    worker_log("listener bound; accept_port_from_js available");

    let runtime_for_loop = Arc::clone(&runtime);
    let engine_for_loop = Arc::clone(&engine);
    let listener_for_loop = Arc::clone(&listener);
    runtime.spawn(Box::pin(async move {
        loop {
            let id = engine_for_loop.forwarder().faces().alloc_id();
            match listener_for_loop
                .accept_one(id, Arc::clone(&runtime_for_loop))
                .await
            {
                Ok(port_face) => {
                    worker_log(&format!(
                        "tab port accepted as {}",
                        Transport::id(&port_face)
                    ));
                    engine_for_loop.add_face(port_face);
                }
                Err(e) => {
                    worker_log(&format!("listener closed: {e}"));
                    break;
                }
            }
        }
    }));

    Ok(())
}

/// Accept a [`MessagePort`] handed in by the JS bootstrap (once per
/// pre-buffered or subsequent connect event).
#[wasm_bindgen]
pub fn accept_port_from_js(port: MessagePort) {
    LISTENER.with(|cell| {
        if let Some(listener) = cell.borrow().as_ref() {
            listener.accept_port(port);
        } else {
            worker_log("accept_port_from_js called before worker_main; dropping port");
        }
    });
}
