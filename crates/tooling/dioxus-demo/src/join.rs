//! Onboarding-link client: a browser-tier [`Engine`] plus NDNCERT-via-token
//! enrollment plus IdbPib-backed identity persistence so refreshing the tab
//! short-circuits the join flow.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_pib_idb::{IdbPib, IdbPibError};
use ndn_runtime::default_runtime;
use ndn_security::safebag::{SafeBag, ed25519_seed_to_pkcs8};
use ndn_security::{Ed25519Signer, Signer};
use wasm_bindgen::prelude::*;

use crate::engine::Engine;
use crate::enroll::{Challenge, EnrolledIdentity, enroll_with_signer};

const PIB_DB_NAME: &str = "ndn-rs-pib";

fn join_log(msg: &str) {
    web_sys::console::log_1(&format!("[join] {msg}").into());
}

/// JS-visible summary of a join or restore. `restored=true` means the
/// identity came from IdbPib without an NDNCERT round-trip.
#[wasm_bindgen]
pub struct JoinedIdentityInfo {
    cert_name: String,
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

/// Browser-tier onboarding client.
#[wasm_bindgen]
pub struct JoinClient {
    pib: IdbPib,
    engine: Option<Arc<Engine>>,
    signer: Option<Arc<Ed25519Signer>>,
}

#[wasm_bindgen]
impl JoinClient {
    /// Open the per-origin PIB (idempotent; per-origin via IndexedDB).
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

    /// Returns `None` on first visit; otherwise reconstructs the signer
    /// from the persisted seed and the cert from its wire bytes (no NDNCERT
    /// round-trip).
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

    /// Dial `host_url` (WebTransport), run NDNCERT against `ca_prefix`
    /// with the token challenge, persist the result. A random identity is
    /// minted under `identity_name_prefix`.
    pub async fn join(
        &mut self,
        host_url: String,
        ca_prefix: String,
        identity_name_prefix: String,
        token: String,
    ) -> Result<JoinedIdentityInfo, JsValue> {
        let runtime = default_runtime();

        let engine = Engine::connect(runtime, &host_url)
            .await
            .map_err(|e| JsValue::from_str(&format!("engine connect: {e}")))?;
        let engine = Arc::new(engine);

        // Persist the seed to IdbPib so reload reconstructs the same signer
        // (the cert is useless without the matching private key).
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

        join_log(&format!(
            "enrolling under {identity_name} via token challenge"
        ));
        let signer_dyn: Arc<dyn Signer> = signer.clone();
        let identity = enroll_with_signer(
            &engine,
            &ca_prefix_name,
            signer_dyn,
            Challenge::Token { value: token },
        )
        .await
        .map_err(|e| JsValue::from_str(&format!("enroll: {e}")))?;

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

    /// Wipe the cached identity. Subsequent `try_restore` returns `None`.
    pub async fn forget(&self) -> Result<(), JsValue> {
        self.pib
            .clear()
            .await
            .map_err(|e| JsValue::from_str(&format!("clear: {e}")))?;
        Ok(())
    }

    async fn persist(
        &self,
        key_name: &Name,
        seed: &[u8; 32],
        identity: &EnrolledIdentity,
    ) -> Result<(), JsValue> {
        // PKCS#8 + SafeBag wrapping (PBES2 with PBKDF2-HMAC-SHA256 +
        // AES-256-CBC) — matches `ndnsec export`, so bytes round-trip
        // cleanly into ndn-cxx tooling.
        let pkcs8 = ed25519_seed_to_pkcs8(seed)
            .map_err(|e| JsValue::from_str(&format!("ed25519 → pkcs8: {e}")))?;

        // Per-identity random passphrase, stored next to the bag in
        // IndexedDB. An origin-scope compromise loses the identity; the wire
        // shape doesn't change if a future impl derives the passphrase from
        // a WebAuthn passkey or user input.
        let mut pw = [0u8; 32];
        let _ = getrandom::getrandom(&mut pw);

        let bag = SafeBag::encrypt(identity.cert_wire.clone(), &pkcs8, &pw)
            .map_err(|e| JsValue::from_str(&format!("safebag encrypt: {e}")))?;

        // Write bag before passphrase: if the passphrase put fails,
        // `try_restore` returns a schema-corruption error and prompts
        // re-join rather than silently dropping the identity.
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
