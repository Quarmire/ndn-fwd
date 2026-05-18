//! `SignedDataChainStore<T>` — append-only chain of signed NDN Data
//! packets.
//!
//! Substrate-correct storage for the dashboard's audit log (§4.6) and
//! schema journal (§2.4) per
//! `docs/notes/dashboard-security-design-2026-05-13.md` and the
//! kickoff at
//! `docs/notes/dashboard-security-v1-implementation-kickoff-2026-05-13.md`
//! (cross-stack design constraints §1–§4 — signed NDN Data, not JSON,
//! not CBOR; per-seq chain with `prev_entry_hash` in Content; NDN-TLV
//! encoded payload).
//!
//! ## Wire shape
//!
//! Each chain entry is a signed NDN Data packet whose Name is
//! `<chain_root>/seq=N` (typed `SequenceNumber` NameComponent). The
//! Content carries an ordered TLV stream:
//!
//! | Tag | Field              | Value                                      |
//! |-----|--------------------|--------------------------------------------|
//! | 0   | `schema_version`   | `u16` (NonNegativeInteger), pinned by `T`  |
//! | 1   | `authored_under`   | `Option<Hash>` — reserved (v1 = zero-len)  |
//! | 2   | `prev_entry_hash`  | 32-byte SHA-256 of prior entry's wire      |
//! | 3+  | type-defined       | `T::encode_payload_fields`                 |
//!
//! Tag IDs are wire identifiers. Once shipped, never reused; new fields
//! get new tag numbers (forward-compat discipline matches NDF's
//! payload-foundation §"Wire format").
//!
//! ## Chain semantics
//!
//! - Genesis entry: `seq=0`, `prev_entry_hash` = `[0u8; 32]`.
//! - Subsequent entry: `seq=N+1`, `prev_entry_hash` =
//!   `prior.implicit_digest()` (the standard NDN
//!   `ImplicitSha256DigestComponent` value over the full prior Data
//!   wire).
//! - `verify` walks the chain head→tail checking (a) `seq` monotonic
//!   by 1 from 0; (b) `prev_entry_hash` matches the prior entry's
//!   `implicit_digest`; (c) each entry's signature verifies against
//!   the supplied verifier.
//!
//! Per §11.10 of the design doc, the operator-posture (`MgmtAccessConfig`)
//! state is **not** stored via this primitive — it's forwarder-internal
//! config. Policy edits author an `AuditLogEntry` into the dashboard's
//! `AuditLogChain` instantiation; that's the §11.10 audit bridge.

#![allow(dead_code)] // primitive lands ahead of its UI consumers

use std::marker::PhantomData;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use ndn_tlv::{TlvReader, TlvWriter};
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 output. Matches NDN's `ImplicitSha256DigestComponent`.
pub type Hash = [u8; 32];

/// Reserved tag IDs every chained entry uses. Type-specific payloads
/// MUST start at [`tag::PAYLOAD_START`].
pub mod tag {
    /// `u16` schema version — pinned per `T`, bumped only on
    /// backward-incompatible field-set changes. Always tag 0 per the
    /// NDF substrate convention.
    pub const SCHEMA_VERSION: u64 = 0;
    /// Reserved `authored_under: Option<Hash>`. Empty in v1 (chain
    /// identity dispatch already implies the type); held open so v2
    /// can attach a SemanticManifest pointer without a wire bump.
    pub const AUTHORED_UNDER: u64 = 1;
    /// 32-byte chain linkage — SHA-256 of the prior entry's Data wire.
    pub const PREV_ENTRY_HASH: u64 = 2;
    /// First tag ID available for type-defined fields.
    pub const PAYLOAD_START: u64 = 3;
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("data wire: {0}")]
    DataWire(String),
    #[error("signer: {0}")]
    Sign(String),
    #[error("chain broken at seq={seq}: {reason}")]
    BrokenChain { seq: u64, reason: String },
    #[error("backend: {0}")]
    Backend(String),
}

/// Application payload chained inside the dashboard's signed Data
/// packets. Implementors own only their type-defined fields (tags 3+);
/// the primitive owns the reserved tags 0–2.
pub trait ChainEntry: Sized {
    /// Pinned per type; bumped only on backward-incompatible
    /// field-set changes. Written into tag 0 of every entry's Content.
    const SCHEMA_VERSION: u16;

    /// Encode the type-defined fields (tag IDs ≥ [`tag::PAYLOAD_START`])
    /// into `w` in canonical ascending-tag order.
    fn encode_payload_fields(&self, w: &mut TlvWriter);

    /// Decode the type-defined fields from a reader scoped to the
    /// payload-tail of the Content TLV stream. The primitive has
    /// already consumed tags 0–2 before handing the reader over.
    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError>;
}

/// Producer side. Carries the signature type, key locator, and sign
/// closure that [`ndn_packet::encode::DataBuilder::sign_sync`] needs.
pub trait DataSigner {
    fn sig_type(&self) -> SignatureType;
    fn key_locator(&self) -> Option<&Name>;
    fn sign(&self, region: &[u8]) -> Result<Bytes, ChainError>;
}

/// Consumer side. Verifies the NDN signature on a Data packet that
/// the chain has presented (chain hash linkage is verified by the
/// primitive itself; the verifier only attests to the per-packet
/// signature).
pub trait DataVerifier {
    fn verify(&self, data: &Data) -> bool;
}

/// Backend storing Data wires keyed by chain position. Implementations
/// are sync; async backends (IndexedDB) load the full chain once and
/// present a sync view afterwards.
pub trait ChainBackend {
    /// Return every entry wire in seq order (seq=0 first).
    fn load_all(&self) -> Result<Vec<Bytes>, ChainError>;
    /// Append one entry wire at the next seq position.
    fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError>;
}

/// The chain itself. Owns the in-memory cache of decoded Data packets
/// plus the backing store.
pub struct SignedDataChainStore<T: ChainEntry, B: ChainBackend> {
    chain_root: Name,
    backend: B,
    entries: Vec<Data>,
    _marker: PhantomData<T>,
}

impl<T: ChainEntry, B: ChainBackend> SignedDataChainStore<T, B> {
    /// Open the chain rooted at `chain_root`, replaying any persisted
    /// entries. Does NOT verify signatures — call [`Self::verify`].
    pub fn open(chain_root: Name, backend: B) -> Result<Self, ChainError> {
        let mut entries = Vec::new();
        for wire in backend.load_all()? {
            let data = Data::decode(wire)
                .map_err(|e| ChainError::DataWire(format!("decode persisted entry: {e:?}")))?;
            entries.push(data);
        }
        Ok(Self {
            chain_root,
            backend,
            entries,
            _marker: PhantomData,
        })
    }

    pub fn chain_root(&self) -> &Name {
        &self.chain_root
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Data] {
        &self.entries
    }

    /// Hash referencing the chain head — the value the next appended
    /// entry will carry as its `prev_entry_hash`. Zero for an empty
    /// chain.
    pub fn head_hash(&self) -> Hash {
        self.entries
            .last()
            .map(|d| d.implicit_digest())
            .unwrap_or([0u8; 32])
    }

    /// Append a new entry signed by `signer`. Returns the new entry's
    /// `implicit_digest` (the value any subsequent entry will use as
    /// its `prev_entry_hash`).
    pub fn append(&mut self, payload: T, signer: &dyn DataSigner) -> Result<Hash, ChainError> {
        let seq = self.entries.len() as u64;
        let prev = self.head_hash();

        // Build the entry Name: <chain_root>/seq=N (typed
        // SequenceNumber component per the NDN packet spec).
        let mut name = self.chain_root.clone();
        name = name.append_component(NameComponent::sequence_num(seq));

        // Encode the Content TLV stream: schema_version, authored_under
        // (reserved zero-length in v1), prev_entry_hash, then T's
        // type-defined fields (tags ≥ PAYLOAD_START).
        let mut w = TlvWriter::new();
        write_nni(&mut w, tag::SCHEMA_VERSION, u64::from(T::SCHEMA_VERSION));
        // v1 authored_under = None → zero-length value. The decoder
        // checks for length 0 (None) vs length 32 (Some(Hash)).
        w.write_tlv(tag::AUTHORED_UNDER, &[]);
        w.write_tlv(tag::PREV_ENTRY_HASH, &prev);
        payload.encode_payload_fields(&mut w);
        let content = w.finish();

        // Build + sign the Data packet through the standard codec.
        let sig_type = signer.sig_type();
        let key_locator = signer.key_locator().cloned();
        let mut sign_err: Option<ChainError> = None;
        let wire =
            DataBuilder::new(name, &content).sign_sync(sig_type, key_locator.as_ref(), |region| {
                match signer.sign(region) {
                    Ok(b) => b,
                    Err(e) => {
                        sign_err = Some(e);
                        Bytes::new()
                    }
                }
            });
        if let Some(e) = sign_err {
            return Err(e);
        }

        // Decode round-trip to populate the cached `Data` (cheap; the
        // Bytes are Arc-backed) and persist.
        let data = Data::decode(wire.clone())
            .map_err(|e| ChainError::DataWire(format!("decode self: {e:?}")))?;
        let digest = data.implicit_digest();
        self.backend.append(seq, wire)?;
        self.entries.push(data);
        Ok(digest)
    }

    /// Walk the chain from genesis to head; verify (a) seq monotonic
    /// by 1 starting at 0; (b) `prev_entry_hash` matches prior
    /// `implicit_digest`; (c) each entry's signature against
    /// `verifier`.
    pub fn verify(&self, verifier: &dyn DataVerifier) -> Result<(), ChainError> {
        let mut expected_prev: Hash = [0u8; 32];
        for (i, entry) in self.entries.iter().enumerate() {
            let seq = i as u64;
            // (a) seq monotonic
            let last_comp = entry
                .name
                .components()
                .last()
                .ok_or(ChainError::BrokenChain {
                    seq,
                    reason: "entry name has no components".into(),
                })?;
            let entry_seq = last_comp.as_sequence_num().ok_or(ChainError::BrokenChain {
                seq,
                reason: "last name component is not a SequenceNumber".into(),
            })?;
            if entry_seq != seq {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: format!("expected seq={seq}, name carries seq={entry_seq}"),
                });
            }
            // (b) chain linkage
            let parsed = ParsedHeader::decode(entry).map_err(|e| ChainError::BrokenChain {
                seq,
                reason: format!("header parse: {e}"),
            })?;
            if parsed.schema_version != T::SCHEMA_VERSION {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: format!(
                        "schema_version mismatch: entry={}, T::SCHEMA_VERSION={}",
                        parsed.schema_version,
                        T::SCHEMA_VERSION
                    ),
                });
            }
            if parsed.prev_entry_hash != expected_prev {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: "prev_entry_hash does not match prior entry's implicit_digest".into(),
                });
            }
            // (c) signature
            if !verifier.verify(entry) {
                return Err(ChainError::BrokenChain {
                    seq,
                    reason: "signature invalid".into(),
                });
            }
            expected_prev = entry.implicit_digest();
        }
        Ok(())
    }

    /// Decode an entry's payload (the type-defined fields, tags 3+).
    pub fn decode_entry(&self, index: usize) -> Result<T, ChainError> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| ChainError::Backend(format!("entry index {index} out of range")))?;
        let content = entry.content().cloned().unwrap_or_default();
        let mut reader = TlvReader::new(content);
        // Skip the reserved tags 0–2.
        let _ = ParsedHeader::read_from(&mut reader)
            .map_err(|e| ChainError::Decode(format!("header skip: {e}")))?;
        T::decode_payload_fields(&mut reader)
    }
}

struct ParsedHeader {
    schema_version: u16,
    authored_under: Option<Hash>,
    prev_entry_hash: Hash,
}

impl ParsedHeader {
    fn decode(data: &Data) -> Result<Self, String> {
        let content = data.content().cloned().unwrap_or_default();
        let mut reader = TlvReader::new(content);
        Self::read_from(&mut reader)
    }

    fn read_from(reader: &mut TlvReader) -> Result<Self, String> {
        let (t0, v0) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 0: {e:?}"))?;
        if t0 != tag::SCHEMA_VERSION {
            return Err(format!(
                "expected schema_version tag {}, got {t0}",
                tag::SCHEMA_VERSION
            ));
        }
        let schema_version = read_nni_u16(&v0)?;
        let (t1, v1) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 1: {e:?}"))?;
        if t1 != tag::AUTHORED_UNDER {
            return Err(format!(
                "expected authored_under tag {}, got {t1}",
                tag::AUTHORED_UNDER
            ));
        }
        let authored_under = match v1.len() {
            0 => None,
            32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&v1);
                Some(h)
            }
            other => return Err(format!("authored_under must be 0 or 32 bytes, got {other}")),
        };
        let (t2, v2) = reader
            .read_tlv()
            .map_err(|e| format!("read tag 2: {e:?}"))?;
        if t2 != tag::PREV_ENTRY_HASH {
            return Err(format!(
                "expected prev_entry_hash tag {}, got {t2}",
                tag::PREV_ENTRY_HASH
            ));
        }
        if v2.len() != 32 {
            return Err(format!(
                "prev_entry_hash must be 32 bytes, got {}",
                v2.len()
            ));
        }
        let mut prev_entry_hash = [0u8; 32];
        prev_entry_hash.copy_from_slice(&v2);
        Ok(Self {
            schema_version,
            authored_under,
            prev_entry_hash,
        })
    }
}

/// Write a NonNegativeInteger TLV (the standard NDN integer encoding —
/// 1, 2, 4, or 8 bytes big-endian, shortest form). Matches
/// `ndn-packet`'s internal `write_nni`.
fn write_nni(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_nni(value));
}

fn encode_nni(value: u64) -> Vec<u8> {
    if value <= u64::from(u8::MAX) {
        vec![value as u8]
    } else if value <= u64::from(u16::MAX) {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= u64::from(u32::MAX) {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn decode_nni(bytes: &[u8]) -> Result<u64, String> {
    match bytes.len() {
        1 => Ok(u64::from(bytes[0])),
        2 => Ok(u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))),
        4 => Ok(u64::from(u32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        8 => Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        n => Err(format!("NonNegativeInteger must be 1/2/4/8 bytes, got {n}")),
    }
}

fn read_nni_u16(bytes: &Bytes) -> Result<u16, String> {
    let v = decode_nni(bytes)?;
    if v > u64::from(u16::MAX) {
        return Err(format!("schema_version {v} does not fit in u16"));
    }
    Ok(v as u16)
}

// Public helper so [`ChainEntry`] impls can write 32-byte hashes,
// optional names, etc. without re-implementing the encoding.
pub fn sha256_of(bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ── MemoryStore — always available; the test backend ────────────────

#[derive(Default)]
pub struct MemoryStore {
    entries: Vec<Bytes>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl ChainBackend for MemoryStore {
    fn load_all(&self) -> Result<Vec<Bytes>, ChainError> {
        Ok(self.entries.clone())
    }
    fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError> {
        if seq != self.entries.len() as u64 {
            return Err(ChainError::Backend(format!(
                "memory backend: append at seq={seq}, expected {}",
                self.entries.len()
            )));
        }
        self.entries.push(wire);
        Ok(())
    }
}

// ── FileStore — desktop, one file per entry ─────────────────────────
//
// Per §11.1 of the design doc the desktop store lives under
// `$XDG_CONFIG_HOME/ndn-dashboard/<forwarder-id>/<chain>/`. Each entry
// is its own file named `<seq:020>.data` (zero-padded so a directory
// listing sorts in seq order). The Data packet wire is the file
// content. Atomicity: write `<seq>.data.tmp`, fsync, rename. A torn
// append leaves the prior chain intact.

#[cfg(feature = "desktop")]
#[allow(unused_imports)]
pub use file_store::FileStore;

#[cfg(feature = "desktop")]
mod file_store {
    use super::{ChainBackend, ChainError};
    use bytes::Bytes;
    use std::path::{Path, PathBuf};

    pub struct FileStore {
        dir: PathBuf,
    }

    impl FileStore {
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            Self { dir: dir.into() }
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        fn entry_path(&self, seq: u64) -> PathBuf {
            self.dir.join(format!("{seq:020}.data"))
        }
    }

    impl ChainBackend for FileStore {
        fn load_all(&self) -> Result<Vec<Bytes>, ChainError> {
            if !self.dir.exists() {
                return Ok(Vec::new());
            }
            let mut paths: Vec<PathBuf> = Vec::new();
            for ent in std::fs::read_dir(&self.dir)
                .map_err(|e| ChainError::Backend(format!("read_dir {}: {e}", self.dir.display())))?
            {
                let ent = ent.map_err(|e| ChainError::Backend(format!("read_dir entry: {e}")))?;
                let path = ent.path();
                if path.extension().is_some_and(|e| e == "data") {
                    paths.push(path);
                }
            }
            paths.sort();
            let mut out = Vec::with_capacity(paths.len());
            for p in &paths {
                let bytes = std::fs::read(p)
                    .map_err(|e| ChainError::Backend(format!("read {}: {e}", p.display())))?;
                out.push(Bytes::from(bytes));
            }
            Ok(out)
        }

        fn append(&mut self, seq: u64, wire: Bytes) -> Result<(), ChainError> {
            std::fs::create_dir_all(&self.dir).map_err(|e| {
                ChainError::Backend(format!("create_dir_all {}: {e}", self.dir.display()))
            })?;
            let final_path = self.entry_path(seq);
            let tmp_path = self.dir.join(format!("{seq:020}.data.tmp"));
            {
                use std::io::Write as _;
                let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
                    ChainError::Backend(format!("create {}: {e}", tmp_path.display()))
                })?;
                f.write_all(&wire).map_err(|e| {
                    ChainError::Backend(format!("write {}: {e}", tmp_path.display()))
                })?;
                f.sync_all().map_err(|e| {
                    ChainError::Backend(format!("fsync {}: {e}", tmp_path.display()))
                })?;
            }
            std::fs::rename(&tmp_path, &final_path).map_err(|e| {
                ChainError::Backend(format!(
                    "rename {} → {}: {e}",
                    tmp_path.display(),
                    final_path.display()
                ))
            })?;
            Ok(())
        }
    }
}

// ── IndexedDbStore — wasm32 scaffold ────────────────────────────────
//
// Real IDB read/write goes online when the audit-log UI lands; the
// pattern follows `crates/extension/ndn-pib-idb/src/wasm.rs`. The
// scaffold returns an error so downstream callers can refer to the
// symbol today without compiling against an unimplemented body.

#[cfg(target_arch = "wasm32")]
pub use indexed_db::IndexedDbStore;

#[cfg(target_arch = "wasm32")]
mod indexed_db {
    use super::ChainError;

    pub struct IndexedDbStore {
        _db_name: String,
        _chain_root: String,
    }

    impl IndexedDbStore {
        pub async fn open(db_name: &str, chain_root: &str) -> Result<Self, ChainError> {
            let _ = (db_name, chain_root);
            Err(ChainError::Backend(
                "IndexedDbStore not wired yet — tracked at \
                 docs/notes/dashboard-security-design-2026-05-13.md §11.1"
                    .into(),
            ))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use ndn_packet::SignatureType;

    // ── Test entry types ─────────────────────────────────────────────

    /// Minimal payload — single u64 field at tag 3 to exercise the
    /// reserved-tag-skipping logic.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEntry {
        n: u64,
    }

    const TAG_TEST_N: u64 = 3;

    impl ChainEntry for TestEntry {
        const SCHEMA_VERSION: u16 = 1;
        fn encode_payload_fields(&self, w: &mut TlvWriter) {
            w.write_tlv(TAG_TEST_N, &encode_nni(self.n));
        }
        fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
            let (t, v) = reader
                .read_tlv()
                .map_err(|e| ChainError::Decode(format!("TestEntry.n: {e:?}")))?;
            if t != TAG_TEST_N {
                return Err(ChainError::Decode(format!(
                    "expected tag {TAG_TEST_N}, got {t}"
                )));
            }
            let n = decode_nni(&v).map_err(ChainError::Decode)?;
            Ok(TestEntry { n })
        }
    }

    // ── Test signer/verifier (Ed25519, no NDN-cert envelope) ─────────

    struct TestSigner {
        key_locator: Name,
        signing: SigningKey,
    }

    impl TestSigner {
        fn from_seed(seed: [u8; 32], key_locator: Name) -> Self {
            Self {
                key_locator,
                signing: SigningKey::from_bytes(&seed),
            }
        }
        fn verifying(&self) -> VerifyingKey {
            self.signing.verifying_key()
        }
    }

    impl DataSigner for TestSigner {
        fn sig_type(&self) -> SignatureType {
            SignatureType::SignatureEd25519
        }
        fn key_locator(&self) -> Option<&Name> {
            Some(&self.key_locator)
        }
        fn sign(&self, region: &[u8]) -> Result<Bytes, ChainError> {
            Ok(Bytes::copy_from_slice(
                &self.signing.sign(region).to_bytes(),
            ))
        }
    }

    struct TestVerifier {
        verifying: VerifyingKey,
    }

    impl DataVerifier for TestVerifier {
        fn verify(&self, data: &Data) -> bool {
            let sig = data.sig_value();
            let Ok(arr): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            let signature = ed25519_dalek::Signature::from_bytes(&arr);
            self.verifying
                .verify(data.signed_region(), &signature)
                .is_ok()
        }
    }

    fn fixture() -> (Name, TestSigner, TestVerifier) {
        let root = Name::root().append(b"lab").append(b"audit");
        let signer = TestSigner::from_seed(
            [7u8; 32],
            Name::root()
                .append(b"lab")
                .append(b"alice")
                .append(b"KEY")
                .append(b"k1"),
        );
        let verifier = TestVerifier {
            verifying: signer.verifying(),
        };
        (root, signer, verifier)
    }

    #[test]
    fn empty_chain_head_is_zero() {
        let (root, _, _) = fixture();
        let store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        assert_eq!(store.head_hash(), [0u8; 32]);
        assert!(store.is_empty());
    }

    #[test]
    fn append_and_verify_three_entries() {
        let (root, signer, verifier) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        for n in 0..3u64 {
            store.append(TestEntry { n }, &signer).unwrap();
        }
        assert_eq!(store.len(), 3);
        store.verify(&verifier).expect("chain valid");

        // Decoded payloads round-trip.
        for i in 0..3 {
            let decoded = store.decode_entry(i).unwrap();
            assert_eq!(decoded.n, i as u64);
        }
    }

    #[test]
    fn entry_name_carries_typed_sequence_number() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 1 }, &signer).unwrap();
        store.append(TestEntry { n: 2 }, &signer).unwrap();
        let comps = store.entries()[1].name.components();
        let last = comps.last().expect("name has components");
        assert_eq!(last.typ, ndn_packet::tlv_type::SEQUENCE_NUM);
        assert_eq!(last.as_sequence_num(), Some(1));
    }

    #[test]
    fn prev_entry_hash_chains_via_implicit_digest() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 10 }, &signer).unwrap();
        let d0 = store.entries()[0].implicit_digest();
        store.append(TestEntry { n: 20 }, &signer).unwrap();
        let parsed = ParsedHeader::decode(&store.entries()[1]).unwrap();
        assert_eq!(parsed.prev_entry_hash, d0);
        assert_eq!(parsed.schema_version, TestEntry::SCHEMA_VERSION);
        assert!(
            parsed.authored_under.is_none(),
            "v1 leaves authored_under None"
        );
    }

    #[test]
    fn verify_catches_bad_signature() {
        let (root, signer, _) = fixture();
        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        store.append(TestEntry { n: 1 }, &signer).unwrap();
        // A different verifying key — signature verification must fail.
        let other = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let bad_verifier = TestVerifier { verifying: other };
        let err = store.verify(&bad_verifier).unwrap_err();
        match err {
            ChainError::BrokenChain { seq, reason } => {
                assert_eq!(seq, 0);
                assert!(reason.contains("signature"));
            }
            other => panic!("expected BrokenChain, got {other:?}"),
        }
    }

    #[test]
    fn schema_version_mismatch_breaks_verify() {
        let (root, signer, verifier) = fixture();

        // Construct an entry with TestEntry's tags but a bogus
        // schema_version=99 in tag 0. Reach below the primitive's API
        // for surgical wire control.
        let chain_name = root.clone();
        let entry_name = chain_name.append_component(NameComponent::sequence_num(0));
        let mut w = TlvWriter::new();
        write_nni(&mut w, tag::SCHEMA_VERSION, 99);
        w.write_tlv(tag::AUTHORED_UNDER, &[]);
        w.write_tlv(tag::PREV_ENTRY_HASH, &[0u8; 32]);
        w.write_tlv(TAG_TEST_N, &encode_nni(5));
        let content = w.finish();
        let wire = DataBuilder::new(entry_name, &content).sign_sync(
            signer.sig_type(),
            Some(&signer.key_locator),
            |region| signer.sign(region).unwrap(),
        );
        let data = Data::decode(wire.clone()).unwrap();

        let mut store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, MemoryStore::new()).unwrap();
        // Inject the bogus entry directly into the cache + backend so
        // verify walks it.
        store.entries.push(data);
        store.backend.entries.push(wire);
        let err = store.verify(&verifier).unwrap_err();
        match err {
            ChainError::BrokenChain { reason, .. } => assert!(reason.contains("schema_version")),
            other => panic!("expected BrokenChain, got {other:?}"),
        }
    }

    #[test]
    fn nni_round_trip_boundaries() {
        for v in [0u64, 1, 255, 256, 65_535, 65_536, u32::MAX as u64, u64::MAX] {
            let encoded = encode_nni(v);
            assert!(matches!(encoded.len(), 1 | 2 | 4 | 8));
            assert_eq!(decode_nni(&encoded).unwrap(), v);
        }
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn file_store_persists_chain() {
        let tmp = std::env::temp_dir().join(format!(
            "ndn-dashboard-chain-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);

        let (root, signer, verifier) = fixture();
        {
            let backend = FileStore::new(&tmp);
            let mut store: SignedDataChainStore<TestEntry, _> =
                SignedDataChainStore::open(root.clone(), backend).unwrap();
            for n in 0..3u64 {
                store.append(TestEntry { n }, &signer).unwrap();
            }
        }
        // Reopen + verify.
        let backend = FileStore::new(&tmp);
        let store: SignedDataChainStore<TestEntry, _> =
            SignedDataChainStore::open(root, backend).unwrap();
        assert_eq!(store.len(), 3);
        store.verify(&verifier).expect("persisted chain valid");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
