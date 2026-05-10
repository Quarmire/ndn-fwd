//! Phase-#4 onboarding-link client.
//!
//! `JoinClient` ties together three pieces:
//!
//!   1. The browser-tier `Engine` (Phase 7's real `ForwarderEngine`
//!      with a WT face upstream) — same as `SharedClient` uses.
//!   2. The NDNCERT enrollment flow against the host's CA, with a
//!      one-shot invite token submitted via the `token` challenge
//!      (Phase #4's load-bearing primitive).
//!   3. The [`IdbPib`](ndn_pib_idb::IdbPib) — IndexedDB-backed PIB
//!      that persists the issued cert + signing key across reloads
//!      and SharedWorker restarts.
//!
//! The intended UX:
//!
//! ```text
//!   user clicks https://<host>/?join=<token>
//!     │
//!     ▼
//!   JoinClient.try_restore()         ── returns Some if a prior
//!     │                                  enrollment is in IdbPib
//!     │  (none on first visit)
//!     ▼
//!   JoinClient.join(host_url, ca_prefix, token)
//!     ├── connect Engine to host's WT face
//!     ├── NDNCERT NEW + CHALLENGE("token", token)
//!     └── persist signer seed + cert wire bytes to IdbPib
//!     │
//!     ▼
//!   user sees "you're in"; refresh skips straight to try_restore.
//! ```
//!
//! Witness coverage is currently a follow-on (needs a fixture page
//! + an ndn-fwd configured with a known invite token). The unit
//! correctness of each piece is exercised by the underlying crate's
//! tests (`ndn-cert`, `ndn-pib-idb` types).

use std::sync::Arc;

use ndn_packet::Name;
use ndn_pib_idb::{IdbPib, IdbPibError};
use ndn_runtime::default_runtime;
use ndn_safebag::{SafeBag, ed25519_seed_to_pkcs8};
use ndn_security::{Ed25519Signer, Signer};
use wasm_bindgen::prelude::*;

use crate::engine::Engine;
use crate::enroll::{Challenge, EnrolledIdentity, enroll_with_signer};

const PIB_DB_NAME: &str = "ndn-rs-pib";

fn join_log(msg: &str) {
    web_sys::console::log_1(&format!("[join] {msg}").into());
}

/// JS-visible result of a successful join (or restore). Pure data —
/// no engine handle here; the caller asks the JoinClient for the
/// engine separately when it needs to express Interests.
#[wasm_bindgen]
pub struct JoinedIdentityInfo {
    /// NDN name of the issued cert (KeyLocator on subsequent
    /// signed Interests).
    cert_name: String,
    /// Whether this was a fresh enrollment (`false`) or a restore
    /// from IdbPib (`true`). Lets the UI show "welcome back" vs.
    /// "you're in".
    restored: bool,
}

#[wasm_bindgen]
impl JoinedIdentityInfo {
    #[wasm_bindgen(getter)]
    pub fn cert_name(&self) -> String {
        self.cert_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn restored(&self) -> bool {
        self.restored
    }
}

/// Browser-tier onboarding client. Constructor opens the per-origin
/// IdbPib; `try_restore` short-circuits a fresh enrollment if a
/// prior one is cached; `join` runs NDNCERT with the supplied
/// invite token and persists the result.
#[wasm_bindgen]
pub struct JoinClient {
    pib: IdbPib,
    /// Engine handle, populated lazily on the first `join` call
    /// that produces an upstream face. None until then (the JS
    /// caller may construct JoinClient before it has a host URL).
    engine: Option<Arc<Engine>>,
    /// Live `Ed25519Signer` for the restored or freshly-enrolled
    /// identity — `None` before `join` / `try_restore` succeeds.
    signer: Option<Arc<Ed25519Signer>>,
}

#[wasm_bindgen]
impl JoinClient {
    /// Open the per-origin PIB. Idempotent: subsequent calls hit
    /// the same IndexedDB database (per W3C origin isolation).
    pub async fn open() -> Result<JoinClient, JsValue> {
        console_error_panic_hook::set_once();
        let pib = IdbPib::open(PIB_DB_NAME)
            .await
            .map_err(|e: IdbPibError| JsValue::from_str(&format!("idb open: {e}")))?;
        Ok(Self {
            pib,
            engine: None,
            signer: None,
        })
    }

    /// Look for a previously persisted identity. Returns `None` on
    /// the first visit; subsequent visits reconstruct the
    /// `Ed25519Signer` from the persisted seed and the cert from
    /// its persisted wire bytes — the user is fully signed-in
    /// without any NDNCERT round-trip. The JS caller can use
    /// `restored` on the returned info to decide between
    /// "welcome back" UX and the new-user landing.
    pub async fn try_restore(&mut self) -> Result<Option<JoinedIdentityInfo>, JsValue> {
        let names = self
            .pib
            .list_safebags()
            .await
            .map_err(|e: IdbPibError| JsValue::from_str(&format!("list_safebags: {e}")))?;
        let Some(key_name) = names.into_iter().next() else {
            join_log("no cached identity in IdbPib");
            return Ok(None);
        };

        // SafeBag → seed → signer reconstruction.
        let bag = self
            .pib
            .get_safebag(&key_name)
            .await
            .map_err(|e| JsValue::from_str(&format!("get_safebag: {e}")))?
            .ok_or_else(|| {
                JsValue::from_str("PIB indexed key has no SafeBag; call forget() then re-join")
            })?;
        let pw = self
            .pib
            .get_passphrase(&key_name)
            .await
            .map_err(|e| JsValue::from_str(&format!("get_passphrase: {e}")))?
            .ok_or_else(|| {
                JsValue::from_str(
                    "PIB has SafeBag but no passphrase; schema corruption — call forget() then re-join",
                )
            })?;
        let seed = bag
            .decrypt_ed25519_seed(&pw)
            .map_err(|e| JsValue::from_str(&format!("safebag decrypt: {e}")))?;
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));

        // Cert is the SafeBag's `certificate` half.
        let cert_data = ndn_packet::Data::decode(bag.certificate.clone())
            .map_err(|e| JsValue::from_str(&format!("decode cert: {e}")))?;
        let cert_name = cert_data.name.to_string();

        self.signer = Some(signer);
        join_log(&format!("restored from IdbPib: {cert_name}"));

        Ok(Some(JoinedIdentityInfo {
            cert_name,
            restored: true,
        }))
    }

    /// One-shot enrollment: dial `host_url` (a WebTransport URL),
    /// run NDNCERT against `ca_prefix` with `token` as the
    /// challenge response, persist the issued identity. Returns
    /// the issued cert name.
    ///
    /// `identity_name_prefix` is the NDN namespace under which a
    /// fresh random identity name is generated (e.g.
    /// `/com/example/users` → `/com/example/users/<random>`).
    pub async fn join(
        &mut self,
        host_url: String,
        ca_prefix: String,
        identity_name_prefix: String,
        token: String,
    ) -> Result<JoinedIdentityInfo, JsValue> {
        let runtime = default_runtime();

        // 1. Connect to the host's WT face.
        let engine = Engine::connect(runtime, &host_url)
            .await
            .map_err(|e| JsValue::from_str(&format!("engine connect: {e}")))?;
        let engine = Arc::new(engine);

        // 2. Mint a random identity name under the supplied prefix
        //    + a fresh 32-byte Ed25519 seed. The seed lives in this
        //    function for the duration of the call; we hand it to
        //    Ed25519Signer::from_seed AND persist it via IdbPib so
        //    reload restores the same signer (load-bearing for the
        //    "remember me" UX — the cert alone is useless without
        //    the matching private key).
        let mut id_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut id_bytes);
        let id_hex: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let identity_name: Name = format!("{identity_name_prefix}/{id_hex}")
            .parse()
            .map_err(|_| JsValue::from_str("bad identity_name_prefix"))?;
        let key_name: Name = format!("{identity_name}/KEY/k1")
            .parse()
            .map_err(|_| JsValue::from_str("bad key name"))?;

        let mut seed = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed);
        let signer: Arc<Ed25519Signer> =
            Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));

        let ca_prefix_name: Name = ca_prefix
            .parse()
            .map_err(|_| JsValue::from_str("bad ca_prefix"))?;

        // 3. Run NDNCERT with the token challenge, handing in the
        //    signer we just minted (so we own the seed end-to-end).
        join_log(&format!("enrolling under {identity_name} via token challenge"));
        let signer_dyn: Arc<dyn Signer> = signer.clone();
        let identity = enroll_with_signer(
            &engine,
            &ca_prefix_name,
            signer_dyn,
            Challenge::Token { value: token },
        )
        .await
        .map_err(|e| JsValue::from_str(&format!("enroll: {e}")))?;

        // 4. Persist seed + cert to IdbPib so reload restores both.
        self.persist(&key_name, &seed, &identity).await?;

        let cert_name = identity.cert_name.to_string();
        join_log(&format!("joined: {cert_name}"));

        self.engine = Some(engine);
        self.signer = Some(signer);
        Ok(JoinedIdentityInfo {
            cert_name,
            restored: false,
        })
    }

    /// Wipe the cached identity (logout). Subsequent `try_restore`
    /// returns `None` until the next `join`.
    pub async fn forget(&self) -> Result<(), JsValue> {
        self.pib
            .clear()
            .await
            .map_err(|e| JsValue::from_str(&format!("clear: {e}")))?;
        Ok(())
    }

    // ── internals ────────────────────────────────────────────────

    async fn persist(
        &self,
        key_name: &Name,
        seed: &[u8; 32],
        identity: &EnrolledIdentity,
    ) -> Result<(), JsValue> {
        // Encode the seed as PKCS#8 PrivateKeyInfo and wrap it +
        // the issued cert in a SafeBag. The bag's encrypted-key
        // half uses pkcs8-default PBES2 (PBKDF2-HMAC-SHA256 +
        // AES-256-CBC) — same shape `ndnsec export` produces, so
        // the bytes round-trip cleanly into ndn-cxx tooling.
        let pkcs8 = ed25519_seed_to_pkcs8(seed)
            .map_err(|e| JsValue::from_str(&format!("ed25519 → pkcs8: {e}")))?;

        // Per-identity random passphrase. Today it lives in
        // IndexedDB next to the bag (so origin-scope compromise
        // loses the identity); the wire shape doesn't change when
        // a future implementation derives this from a WebAuthn
        // passkey or asks the user to type it.
        let mut pw = [0u8; 32];
        let _ = getrandom::getrandom(&mut pw);

        let bag = SafeBag::encrypt(identity.cert_wire.clone(), &pkcs8, &pw)
            .map_err(|e| JsValue::from_str(&format!("safebag encrypt: {e}")))?;

        // Bag first, then passphrase — the bag is the spec-shaped
        // bundle; if the passphrase put fails afterwards
        // try_restore surfaces the schema-corruption error and
        // prompts a re-join.
        self.pib
            .put_safebag(key_name, &bag)
            .await
            .map_err(|e| JsValue::from_str(&format!("put_safebag: {e}")))?;
        self.pib
            .put_passphrase(key_name, &pw)
            .await
            .map_err(|e| JsValue::from_str(&format!("put_passphrase: {e}")))?;
        Ok(())
    }
}
