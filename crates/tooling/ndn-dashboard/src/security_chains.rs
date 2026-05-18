//! `AuditLogChain` + `SchemaJournalChain` — typed instantiations of
//! [`crate::signed_data_chain::SignedDataChainStore`] for the
//! dashboard's two Phase-A chains (§4.6 audit log + §2.4 schema
//! journal).
//!
//! Wire shape per the security-design kickoff §2/§4: each entry is a
//! signed NDN Data packet at `/<operator>/<chain-root>/seq=N`; Content
//! is NDN-TLV with tag 0 = `schema_version`, tag 1 = reserved
//! `authored_under` (empty in v1), tag 2 = `prev_entry_hash`, tags 3+
//! type-defined. Tag IDs below are wire identifiers — once shipped,
//! never reused.
//!
//! ## §11.10 audit bridge
//!
//! Mgmt-access posture is forwarder-internal config, not a substrate
//! chain. Every successful `policy-set` mutation appends an
//! [`AuditLogEntry`] with `verb = "security/policy-set"` and the new
//! posture's content_hash into the dashboard's local `AuditLogChain`,
//! so the policy edit history is reconstructable from the audit chain
//! even though the policy itself isn't chained.

#![allow(dead_code)] // typed instantiations land ahead of UI wiring

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::signed_data_chain::{ChainEntry, ChainError, MemoryStore, SignedDataChainStore};

// ── AuditLogEntry — §4.6 ────────────────────────────────────────────

/// One row of the security audit log. Tag IDs are wire identifiers;
/// see `docs/wire-formats/audit-log-entry.toml` for the cross-stack
/// consumer mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    /// Unix-epoch nanoseconds (NDN's TIMESTAMP convention) — when the
    /// dashboard observed the event.
    pub ts_unix_ns: u64,
    /// Outcome — one of "accepted" / "rejected" / "info" / "warning".
    pub outcome: AuditOutcome,
    /// Verb-ish subject identifier — e.g. `"security/policy-set"`,
    /// `"rib/register"`, `"security/anchor-add"`.
    pub subject: String,
    /// Free-form detail line, ≤ 512 bytes. Plain UTF-8.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Accepted,
    Rejected,
    Info,
    Warning,
}

impl AuditOutcome {
    fn code(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::Rejected => 1,
            Self::Info => 2,
            Self::Warning => 3,
        }
    }
    fn from_code(c: u8) -> Result<Self, String> {
        Ok(match c {
            0 => Self::Accepted,
            1 => Self::Rejected,
            2 => Self::Info,
            3 => Self::Warning,
            n => return Err(format!("AuditOutcome: unknown code {n}")),
        })
    }
}

/// Type-defined tag IDs for `AuditLogEntry`. Starts at
/// [`tag::PAYLOAD_START`].
pub mod audit_tag {
    pub const TS_UNIX_NS: u64 = 3;
    pub const OUTCOME: u64 = 4;
    pub const SUBJECT: u64 = 5;
    pub const DETAIL: u64 = 6;
}

impl ChainEntry for AuditLogEntry {
    const SCHEMA_VERSION: u16 = 1;

    fn encode_payload_fields(&self, w: &mut TlvWriter) {
        write_nni(w, audit_tag::TS_UNIX_NS, self.ts_unix_ns);
        w.write_tlv(audit_tag::OUTCOME, &[self.outcome.code()]);
        w.write_tlv(audit_tag::SUBJECT, self.subject.as_bytes());
        w.write_tlv(audit_tag::DETAIL, self.detail.as_bytes());
    }

    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
        let (t_ts, v_ts) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit ts: {e:?}")))?;
        require_tag(t_ts, audit_tag::TS_UNIX_NS, "ts_unix_ns")?;
        let ts_unix_ns = decode_nni(&v_ts).map_err(ChainError::Decode)?;

        let (t_o, v_o) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit outcome: {e:?}")))?;
        require_tag(t_o, audit_tag::OUTCOME, "outcome")?;
        if v_o.len() != 1 {
            return Err(ChainError::Decode(format!(
                "outcome must be 1 byte, got {}",
                v_o.len()
            )));
        }
        let outcome = AuditOutcome::from_code(v_o[0]).map_err(ChainError::Decode)?;

        let (t_s, v_s) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit subject: {e:?}")))?;
        require_tag(t_s, audit_tag::SUBJECT, "subject")?;
        let subject = bytes_to_string(&v_s, "subject")?;

        let (t_d, v_d) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("audit detail: {e:?}")))?;
        require_tag(t_d, audit_tag::DETAIL, "detail")?;
        let detail = bytes_to_string(&v_d, "detail")?;

        Ok(Self {
            ts_unix_ns,
            outcome,
            subject,
            detail,
        })
    }
}

/// `AuditLogChain` — the §4.6 chain typed over [`AuditLogEntry`].
pub type AuditLogChain<B> = SignedDataChainStore<AuditLogEntry, B>;

/// Convenience constructor for the in-memory variant (used by tests
/// and as a fallback before backends initialise).
pub fn open_audit_chain_in_memory(
    chain_root: ndn_packet::Name,
) -> Result<AuditLogChain<MemoryStore>, ChainError> {
    SignedDataChainStore::open(chain_root, MemoryStore::new())
}

// ── SchemaJournalEntry — §2.4 ────────────────────────────────────────

/// One row of the schema-journal chain. Records anchor / schema-rule
/// adds + removes with the responsible signed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaJournalEntry {
    pub ts_unix_ns: u64,
    pub kind: SchemaJournalKind,
    /// The anchor or rule name affected.
    pub subject_name: String,
    /// Operator identity name that initiated the change (the verb
    /// signer; mirrors the §3.1 chip's active identity).
    pub initiator_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaJournalKind {
    AnchorAdd,
    AnchorRemove,
    SchemaRuleAdd,
    SchemaRuleRemove,
}

impl SchemaJournalKind {
    fn code(self) -> u8 {
        match self {
            Self::AnchorAdd => 0,
            Self::AnchorRemove => 1,
            Self::SchemaRuleAdd => 2,
            Self::SchemaRuleRemove => 3,
        }
    }
    fn from_code(c: u8) -> Result<Self, String> {
        Ok(match c {
            0 => Self::AnchorAdd,
            1 => Self::AnchorRemove,
            2 => Self::SchemaRuleAdd,
            3 => Self::SchemaRuleRemove,
            n => return Err(format!("SchemaJournalKind: unknown code {n}")),
        })
    }
}

pub mod schema_tag {
    pub const TS_UNIX_NS: u64 = 3;
    pub const KIND: u64 = 4;
    pub const SUBJECT_NAME: u64 = 5;
    pub const INITIATOR_NAME: u64 = 6;
}

impl ChainEntry for SchemaJournalEntry {
    const SCHEMA_VERSION: u16 = 1;

    fn encode_payload_fields(&self, w: &mut TlvWriter) {
        write_nni(w, schema_tag::TS_UNIX_NS, self.ts_unix_ns);
        w.write_tlv(schema_tag::KIND, &[self.kind.code()]);
        w.write_tlv(schema_tag::SUBJECT_NAME, self.subject_name.as_bytes());
        w.write_tlv(schema_tag::INITIATOR_NAME, self.initiator_name.as_bytes());
    }

    fn decode_payload_fields(reader: &mut TlvReader) -> Result<Self, ChainError> {
        let (t_ts, v_ts) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal ts: {e:?}")))?;
        require_tag(t_ts, schema_tag::TS_UNIX_NS, "ts_unix_ns")?;
        let ts_unix_ns = decode_nni(&v_ts).map_err(ChainError::Decode)?;

        let (t_k, v_k) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal kind: {e:?}")))?;
        require_tag(t_k, schema_tag::KIND, "kind")?;
        if v_k.len() != 1 {
            return Err(ChainError::Decode(format!(
                "kind must be 1 byte, got {}",
                v_k.len()
            )));
        }
        let kind = SchemaJournalKind::from_code(v_k[0]).map_err(ChainError::Decode)?;

        let (t_s, v_s) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal subject: {e:?}")))?;
        require_tag(t_s, schema_tag::SUBJECT_NAME, "subject_name")?;
        let subject_name = bytes_to_string(&v_s, "subject_name")?;

        let (t_i, v_i) = reader
            .read_tlv()
            .map_err(|e| ChainError::Decode(format!("journal initiator: {e:?}")))?;
        require_tag(t_i, schema_tag::INITIATOR_NAME, "initiator_name")?;
        let initiator_name = bytes_to_string(&v_i, "initiator_name")?;

        Ok(Self {
            ts_unix_ns,
            kind,
            subject_name,
            initiator_name,
        })
    }
}

pub type SchemaJournalChain<B> = SignedDataChainStore<SchemaJournalEntry, B>;

pub fn open_schema_journal_in_memory(
    chain_root: ndn_packet::Name,
) -> Result<SchemaJournalChain<MemoryStore>, ChainError> {
    SignedDataChainStore::open(chain_root, MemoryStore::new())
}

// ── §11.10 audit-bridge helper ──────────────────────────────────────

/// Build the `AuditLogEntry` that records a successful `policy-set`
/// mutation. The dashboard appends this to its `AuditLogChain` when
/// `/localhost/nfd/security/policy-set` returns 200. `policy_content_hash`
/// is the SHA-256 of the canonical (TLV-encoded) `OperatorPosture`
/// the operator submitted; the bridge lets readers reconstruct the
/// full policy edit history from the audit chain even though the
/// policy itself isn't chained.
pub fn policy_set_audit_entry(
    ts_unix_ns: u64,
    initiator_name: &str,
    policy_content_hash: &[u8; 32],
) -> AuditLogEntry {
    let mut hex = String::with_capacity(64);
    for b in policy_content_hash {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
    }
    AuditLogEntry {
        ts_unix_ns,
        outcome: AuditOutcome::Accepted,
        subject: "security/policy-set".into(),
        detail: format!("initiator={initiator_name} policy_content_hash={hex}"),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn require_tag(actual: u64, expected: u64, field: &str) -> Result<(), ChainError> {
    if actual != expected {
        Err(ChainError::Decode(format!(
            "{field}: expected tag {expected}, got {actual}"
        )))
    } else {
        Ok(())
    }
}

fn bytes_to_string(bytes: &Bytes, field: &str) -> Result<String, ChainError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| ChainError::Decode(format!("{field}: invalid UTF-8: {e}")))
}

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

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_data_chain::{DataSigner, DataVerifier};
    use bytes::Bytes;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use ndn_packet::{Data, Name, SignatureType};

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
    struct TestVerifier(VerifyingKey);
    impl DataVerifier for TestVerifier {
        fn verify(&self, data: &Data) -> bool {
            let sig = data.sig_value();
            let Ok(arr): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            self.0
                .verify(
                    data.signed_region(),
                    &ed25519_dalek::Signature::from_bytes(&arr),
                )
                .is_ok()
        }
    }

    fn ed_fixture() -> (TestSigner, TestVerifier) {
        let s = TestSigner::from_seed(
            [11u8; 32],
            Name::root()
                .append(b"lab")
                .append(b"alice")
                .append(b"KEY")
                .append(b"k1"),
        );
        let v = TestVerifier(s.verifying());
        (s, v)
    }

    #[test]
    fn audit_chain_round_trip() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"audit");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_audit_chain_in_memory(root).unwrap();

        chain
            .append(
                AuditLogEntry {
                    ts_unix_ns: 1_700_000_000_000_000_000,
                    outcome: AuditOutcome::Accepted,
                    subject: "rib/register".into(),
                    detail: "by=/lab/alice/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();
        chain
            .append(
                AuditLogEntry {
                    ts_unix_ns: 1_700_000_000_000_000_001,
                    outcome: AuditOutcome::Rejected,
                    subject: "security/anchor-remove".into(),
                    detail: "sig invalid".into(),
                },
                &signer,
            )
            .unwrap();

        chain.verify(&verifier).expect("audit chain valid");
        assert_eq!(chain.len(), 2);

        let e0 = chain.decode_entry(0).unwrap();
        assert_eq!(e0.subject, "rib/register");
        assert_eq!(e0.outcome, AuditOutcome::Accepted);
        let e1 = chain.decode_entry(1).unwrap();
        assert_eq!(e1.outcome, AuditOutcome::Rejected);
        assert!(e1.detail.contains("sig invalid"));
    }

    #[test]
    fn schema_journal_round_trip() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"schema");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_schema_journal_in_memory(root).unwrap();

        chain
            .append(
                SchemaJournalEntry {
                    ts_unix_ns: 1_700_000_000_000_000_000,
                    kind: SchemaJournalKind::AnchorAdd,
                    subject_name: "/lab/router-ca/KEY/k0".into(),
                    initiator_name: "/lab/alice/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();
        chain
            .append(
                SchemaJournalEntry {
                    ts_unix_ns: 1_700_000_000_000_000_001,
                    kind: SchemaJournalKind::SchemaRuleRemove,
                    subject_name: "/lab/*/photos => /lab/*/KEY/*".into(),
                    initiator_name: "/lab/admin/KEY/k1".into(),
                },
                &signer,
            )
            .unwrap();

        chain.verify(&verifier).expect("journal chain valid");
        let e1 = chain.decode_entry(1).unwrap();
        assert_eq!(e1.kind, SchemaJournalKind::SchemaRuleRemove);
        assert_eq!(e1.initiator_name, "/lab/admin/KEY/k1");
    }

    /// §11.10 audit bridge — policy-set produces an AuditLogEntry the
    /// dashboard appends to its AuditLogChain. The bridge serialises
    /// the policy's content_hash into the detail line so the policy
    /// edit history is reconstructable from the audit chain.
    #[test]
    fn policy_set_bridge_emits_audit_entry() {
        let entry =
            policy_set_audit_entry(1_700_000_000_000_000_000, "/lab/alice/KEY/k1", &[0xab; 32]);
        assert_eq!(entry.subject, "security/policy-set");
        assert_eq!(entry.outcome, AuditOutcome::Accepted);
        assert!(entry.detail.contains("initiator=/lab/alice/KEY/k1"));
        assert!(entry.detail.contains("policy_content_hash=abab"));
        assert!(entry.detail.ends_with(&"ab".repeat(32)));
    }

    /// Audit-bridge entries round-trip cleanly through the chain.
    #[test]
    fn policy_set_bridge_entry_chains_into_audit_log() {
        let root = Name::root()
            .append(b"lab")
            .append(b"dashboard")
            .append(b"audit");
        let (signer, verifier) = ed_fixture();
        let mut chain = open_audit_chain_in_memory(root).unwrap();

        let entry =
            policy_set_audit_entry(1_700_000_000_000_000_000, "/lab/alice/KEY/k1", &[0x55; 32]);
        chain.append(entry.clone(), &signer).unwrap();
        chain.verify(&verifier).expect("audit valid");
        let decoded = chain.decode_entry(0).unwrap();
        assert_eq!(decoded, entry);
    }
}
