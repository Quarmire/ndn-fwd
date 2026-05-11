//! Phase 6 SharedWorker entrypoint.
//!
//! Loaded inside the per-origin `SharedWorker` scope. The JS bootstrap
//! `importScripts(...)` the wasm-bindgen output, calls `init()`, then
//! invokes [`worker_main`]. From that point on the worker:
//!
//! - optionally dials a single `BrowserWebTransportFace` upstream
//!   (skipped when `upstream_url` is empty — the cache-hit witness
//!   runs without any forwarder),
//! - constructs a face-agnostic [`Engine`](crate::engine::Engine),
//! - pre-registers any producer prefixes passed by the bootstrap,
//! - installs a [`WorkerListener`](ndn_face_shared_worker::WorkerListener)
//!   on the `SharedWorkerGlobalScope` and stashes it for the bootstrap
//!   to drain pre-buffered ports into via [`accept_port_from_js`],
//! - loops `accept_one` and registers each tab `MessagePort` as an
//!   inbound face via [`Engine::add_face`](crate::engine::Engine::add_face).
//!
//! ## SharedWorker connect-event race
//!
//! The W3C SharedWorker `connect` event for the very first tab fires
//! after the bootstrap script's first task finishes — i.e. after
//! `worker_main` *starts* but possibly before its `init_worker_scope`
//! runs. To avoid losing that first port, the bootstrap installs a
//! synchronous `onconnect` that buffers ports into a JS array; once
//! the wasm is initialized and `worker_main` has returned (the
//! listener is stashed), the bootstrap drains the buffer through
//! [`accept_port_from_js`] and replaces `onconnect` with a forwarder
//! that calls the same function for every subsequent connect.
//!
//! Lifecycle: the worker dies when its last connected port closes (W3C
//! `SharedWorker` rule); the engine, CS, pending table, and upstream
//! WT face all go with it.

use std::cell::RefCell;
use std::sync::Arc;

use wasm_bindgen::prelude::*;
use web_sys::MessagePort;

use ndn_face_shared_worker::{WorkerListener, init_worker_scope};
use ndn_face_webtransport_wasm::BrowserWebTransportFace;
use ndn_packet::Name;
use ndn_runtime::default_runtime;
use ndn_transport::{ErasedFace, FaceId};

use crate::engine::Engine;

fn worker_log(msg: &str) {
    web_sys::console::log_1(&format!("[shared-worker] {msg}").into());
}

thread_local! {
    /// Listener installed by `worker_main`. The bootstrap calls
    /// [`accept_port_from_js`] for every buffered + future port; that
    /// helper looks the listener up here.
    static LISTENER: RefCell<Option<Arc<WorkerListener>>> = const { RefCell::new(None) };
}

/// Worker entrypoint.
///
/// `upstream_url` is the WebTransport URL the worker dials out to —
/// empty string skips the dial (no upstream face; producers + CS still
/// work; `Engine::express` returns "no upstream"). `producers` is a
/// comma-separated list of prefix strings to register locally before
/// accepting tab ports — every tab connecting after this point can
/// express against `<prefix>/counter` and observe the worker's CS.
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

    let upstream: Option<Arc<dyn ErasedFace>> = if upstream_url.is_empty() {
        None
    } else {
        let face =
            BrowserWebTransportFace::connect(FaceId(1), &upstream_url, &[], Arc::clone(&runtime))
                .await
                .map_err(|e| JsValue::from_str(&format!("upstream connect: {e:?}")))?;
        Some(Arc::new(face) as Arc<dyn ErasedFace>)
    };

    // Open the per-origin IdbPib once and pull both:
    //  - a Validator seeded from persisted trust anchors, and
    //  - a Signer reconstructed from the first persisted SafeBag.
    //
    // Both are idempotent — a fresh first-run page finds neither and
    // the engine boots permissive + DigestSha256-signed.  After an
    // enrollment flow has populated trust anchors / SafeBag, the same
    // worker_main call upgrades to full signature enforcement on both
    // directions: inbound Data validated by the validator, outbound
    // mgmt responses signed by the persisted identity.
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

    // Audit N.12 parity with native — when no persisted identity
    // exists yet, fall back to an ephemeral in-memory ECDSA-P256
    // signer for mgmt-response signing.  Same choice ndn-fwd makes:
    // ECDSA is the lowest common denominator (ndn-cxx's `KeyType`
    // enum has no Ed25519).  An IdbPib-persisted Ed25519 SafeBag
    // takes precedence — `build_signer` returns whichever algorithm
    // the SafeBag carries — but the auto-init fallback picks the
    // interop-safe default.
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
            // Pull a fresh face id from the engine's face table so
            // the tab port doesn't collide with the AppFace (which
            // also lives in the same table).
            let id = engine_for_loop.forwarder().faces().alloc_id();
            match listener_for_loop
                .accept_one(id, Arc::clone(&runtime_for_loop))
                .await
            {
                Ok(port_face) => {
                    worker_log(&format!(
                        "tab port accepted as {}",
                        ndn_transport::Face::id(&port_face)
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

/// Accept a [`MessagePort`] handed in by the JS bootstrap. Called
/// once per port that arrived via the bootstrap's pre-buffer (before
/// the Rust-side `onconnect` was installed) and once per subsequent
/// connect event the bootstrap forwards.
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
