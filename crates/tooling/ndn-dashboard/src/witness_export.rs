//! wasm-bindgen surface for the browser-side mgmt-wire witness.
//!
//! Each `witness_*` function dials the supplied WebSocket URL via the
//! dashboard's actual [`WsMgmtClient`], issues a single management
//! command, and returns the result as a small JSON string Playwright
//! can `JSON.parse`. The intent is to prove the *production* web wire
//! path — `InterestBuilder::app_parameters(ControlParameters::encode())`
//! → `gloo-net WebSocket` → `ndn-fwd` ws face → mgmt dispatcher —
//! works inside a real browser. Native-only validation lives in
//! `crates/ndn-mgmt/tests/web_wire_e2e.rs`.
//!
//! The JS surface is intentionally narrow: each call builds a fresh
//! client, connects, sends one command, and resolves. No cross-call
//! state, no connection pooling. Tests assert on the returned
//! `{ status_code, status_text }`.

#![cfg(all(target_arch = "wasm32", feature = "witness-export"))]

use serde::Serialize;
use wasm_bindgen::prelude::*;

use ndn_config::ControlParameters;
use ndn_packet::Name;

use crate::ws_mgmt::WsMgmtClient;

#[derive(Serialize)]
struct MgmtResultJson {
    status_code: u64,
    status_text: String,
    body_len: usize,
}

fn ok_json(status_code: u64, status_text: String, body_len: usize) -> String {
    serde_json::to_string(&MgmtResultJson {
        status_code,
        status_text,
        body_len,
    })
    .unwrap_or_else(|_| String::from("{}"))
}

fn err_json(msg: impl std::fmt::Display) -> String {
    ok_json(0, format!("witness-error: {msg}"), 0)
}

async fn connect(ws_url: &str) -> Result<WsMgmtClient, String> {
    let mut client = WsMgmtClient::new(ws_url);
    client.connect().await.map_err(|e| e.to_string())?;
    Ok(client)
}

#[wasm_bindgen]
pub async fn witness_status_general(ws_url: String) -> String {
    let mut client = match connect(&ws_url).await {
        Ok(c) => c,
        Err(e) => return err_json(e),
    };
    match client.status_general().await {
        Ok(resp) => ok_json(resp.status_code, resp.status_text, resp.body.len()),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub async fn witness_faces_list(ws_url: String) -> String {
    let mut client = match connect(&ws_url).await {
        Ok(c) => c,
        Err(e) => return err_json(e),
    };
    match client.list_faces().await {
        Ok(resp) => ok_json(resp.status_code, resp.status_text, resp.body.len()),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub async fn witness_cs_config(ws_url: String, capacity: u64) -> String {
    let mut client = match connect(&ws_url).await {
        Ok(c) => c,
        Err(e) => return err_json(e),
    };
    let cp = ControlParameters {
        capacity: Some(capacity),
        ..Default::default()
    };
    match client.send_cmd("cs", "config", Some(&cp)).await {
        Ok(resp) => ok_json(resp.status_code, resp.status_text, resp.body.len()),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub async fn witness_face_create(ws_url: String, uri: String) -> String {
    let mut client = match connect(&ws_url).await {
        Ok(c) => c,
        Err(e) => return err_json(e),
    };
    let cp = ControlParameters {
        uri: Some(uri),
        ..Default::default()
    };
    match client.send_cmd("faces", "create", Some(&cp)).await {
        Ok(resp) => ok_json(resp.status_code, resp.status_text, resp.body.len()),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub async fn witness_rib_register(
    ws_url: String,
    prefix: String,
    face_id: u64,
    cost: u64,
) -> String {
    let mut client = match connect(&ws_url).await {
        Ok(c) => c,
        Err(e) => return err_json(e),
    };
    let name: Name = match prefix.parse() {
        Ok(n) => n,
        Err(e) => return err_json(format!("invalid prefix: {e:?}")),
    };
    let cp = ControlParameters {
        name: Some(name),
        // `face_id == 0` means "use the requesting face" — same
        // convention as `app_web::run_cmd_web`.
        face_id: (face_id != 0).then_some(face_id),
        cost: Some(cost),
        ..Default::default()
    };
    match client.send_cmd("rib", "register", Some(&cp)).await {
        Ok(resp) => ok_json(resp.status_code, resp.status_text, resp.body.len()),
        Err(e) => err_json(e),
    }
}
