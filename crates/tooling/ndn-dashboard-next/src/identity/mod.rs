//! Dashboard-facing trust and identity view models.
//!
//! Trust semantics stay in `ndn-security`, `ndn-identity`, and `ndn-cert`.
//! This module only translates reusable state into operator-facing posture.

use crate::core::{AttachMode, FeatureState, ForwarderKind, ForwarderProfile, TrustPosture};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustContextSummary {
    pub namespace: String,
    pub identity: String,
    pub anchors: usize,
    pub schema_rules: usize,
    pub pending_approvals: usize,
    pub posture: TrustPosture,
    pub contexts: Vec<TrustContextRow>,
    pub identities: Vec<IdentityRow>,
    pub anchors_detail: Vec<AnchorRow>,
    pub schema_summaries: Vec<SchemaSummaryRow>,
    pub approvals: Vec<ApprovalRow>,
    pub safebag_import: SafeBagImportState,
    pub key_inventory: Vec<KeyInventoryRow>,
    pub validation_traces: Vec<ValidationTraceRow>,
    pub schema_reviews: Vec<SchemaReviewRow>,
    pub custody: CustodyWarning,
    pub adoption: AdoptionFlowState,
    pub enrollment: EnrollmentFlowState,
    pub validation_frame: Option<ValidationFrame>,
    pub did_frames: Vec<DidFrame>,
}

impl TrustContextSummary {
    pub fn from_profile(profile: &ForwarderProfile, posture: TrustPosture) -> Self {
        if profile.capabilities.trust_context == FeatureState::Unsupported {
            return Self {
                namespace: "unsupported".into(),
                identity: "not available".into(),
                anchors: 0,
                schema_rules: 0,
                pending_approvals: 0,
                posture,
                contexts: Vec::new(),
                identities: Vec::new(),
                anchors_detail: Vec::new(),
                schema_summaries: Vec::new(),
                approvals: Vec::new(),
                safebag_import: SafeBagImportState::unsupported(),
                key_inventory: Vec::new(),
                validation_traces: Vec::new(),
                schema_reviews: Vec::new(),
                custody: CustodyWarning::unsupported(profile),
                adoption: AdoptionFlowState::unsupported(),
                enrollment: EnrollmentFlowState::unsupported(),
                validation_frame: None,
                did_frames: Vec::new(),
            };
        }
        let contexts = context_rows(profile, posture);
        let identities = identity_rows(profile, posture);
        let anchors_detail = anchor_rows(profile);
        let schema_summaries = schema_rows(profile, posture);
        let approvals = approval_rows(profile, posture);
        let key_inventory = key_rows(profile, posture);
        let validation_traces = validation_rows(profile, posture);
        let schema_reviews = schema_review_rows(profile, posture);
        let did_frames = did_rows_from_identities(&identities);
        let namespace = contexts
            .first()
            .map(|row| row.namespace.clone())
            .unwrap_or_else(|| "/local/operator".into());
        let identity = identities
            .iter()
            .find(|row| row.active)
            .or_else(|| identities.first())
            .map(|row| row.name.clone())
            .unwrap_or_else(|| "not available".into());
        Self {
            namespace,
            identity,
            anchors: anchors_detail.len(),
            schema_rules: schema_summaries.iter().map(|row| row.rules).sum(),
            pending_approvals: approvals.len(),
            posture,
            contexts,
            identities,
            anchors_detail,
            schema_summaries,
            approvals,
            safebag_import: SafeBagImportState::preview(profile, posture),
            key_inventory,
            validation_traces,
            schema_reviews,
            custody: CustodyWarning::from_profile(profile, posture),
            adoption: AdoptionFlowState::fixture(profile, posture),
            enrollment: EnrollmentFlowState::fixture(profile, posture),
            validation_frame: Some(ValidationFrame::fixture(posture)),
            did_frames,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_security_keyring(
        profile: &ForwarderProfile,
        posture: TrustPosture,
        keyring: &ndn_security::Keyring,
    ) -> Self {
        let contexts = keyring.contexts();
        let context_rows = contexts
            .iter()
            .map(|context| TrustContextRow {
                namespace: context.namespace().to_string(),
                state: if context.enforces_hierarchy() {
                    "active"
                } else {
                    "ambient"
                },
                source: "ndn-security Keyring",
                posture,
            })
            .collect::<Vec<_>>();
        let anchors_detail = contexts
            .iter()
            .flat_map(|context| {
                context.anchors().iter().map(|anchor| AnchorRow {
                    name: anchor.value().name.to_string(),
                    fingerprint: format!(
                        "sha256:{}",
                        ndn_identity::Fingerprint::of_cert(anchor.value())
                    ),
                    origin: "TrustContext anchor",
                    state: if anchor.value().is_valid_now() {
                        "trusted"
                    } else {
                        "expired"
                    },
                })
            })
            .collect::<Vec<_>>();
        let schema_summaries = contexts
            .iter()
            .map(|context| {
                let schema = context.schema_snapshot();
                SchemaSummaryRow {
                    namespace: context.namespace().to_string(),
                    rules: schema.rules().len(),
                    strictness: if context.enforces_hierarchy() {
                        "hierarchical"
                    } else {
                        "ambient"
                    },
                    version: format!("v{}", context.version()),
                }
            })
            .collect::<Vec<_>>();
        let did_frames = contexts
            .iter()
            .flat_map(|context| {
                context
                    .anchors()
                    .iter()
                    .map(|anchor| DidFrame::from_certificate(anchor.value()))
            })
            .collect::<Vec<_>>();
        let adoption = AdoptionFlowState::from_security_contexts(&contexts);
        let enrollment = EnrollmentFlowState::from_security_contexts(&contexts);
        Self::from_live_parts(
            profile,
            posture,
            LiveTrustParts {
                contexts: context_rows,
                identities: Vec::new(),
                anchors_detail,
                schema_summaries,
                approvals: Vec::new(),
                key_inventory: Vec::new(),
                validation_traces: Vec::new(),
                schema_reviews: Vec::new(),
                validation_frame: None,
                did_frames,
                adoption,
                enrollment,
                custody: CustodyWarning::from_profile(profile, posture),
            },
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_identity_contexts(
        profile: &ForwarderProfile,
        posture: TrustPosture,
        contexts: &[ndn_identity::TrustContext],
    ) -> Self {
        let context_rows = contexts
            .iter()
            .map(|context| TrustContextRow {
                namespace: context.name.to_string(),
                state: "active",
                source: "ndn-identity TrustContext",
                posture,
            })
            .collect::<Vec<_>>();
        let identities = contexts
            .iter()
            .flat_map(|context| {
                context.identities.iter().map(|identity| IdentityRow {
                    name: identity.name.to_string(),
                    custodian: custodian_label(&identity.custodian),
                    certificate: identity_lifetime_label(&identity.lifetime),
                    active: true,
                    private_key_owned_by_dashboard: false,
                })
            })
            .collect::<Vec<_>>();
        let anchors_detail = contexts
            .iter()
            .flat_map(|context| {
                context.anchors.iter().map(|anchor| AnchorRow {
                    name: anchor.name.to_string(),
                    fingerprint: format!("sha256:{}", ndn_identity::Fingerprint::of_cert(anchor)),
                    origin: "TrustContext anchor",
                    state: if anchor.is_valid_now() {
                        "trusted"
                    } else {
                        "expired"
                    },
                })
            })
            .collect::<Vec<_>>();
        let schema_summaries = contexts
            .iter()
            .map(|context| SchemaSummaryRow {
                namespace: context.name.to_string(),
                rules: context.schema.rules().len(),
                strictness: "context",
                version: "live".to_string(),
            })
            .collect::<Vec<_>>();
        let key_inventory = contexts
            .iter()
            .flat_map(|context| {
                context.identities.iter().map(|identity| KeyInventoryRow {
                    identity: identity.name.to_string(),
                    key_name: identity.key_id.as_name().to_string(),
                    algorithm: "custodian",
                    storage: custodian_label(&identity.custodian),
                    certificate_state: identity_lifetime_label(&identity.lifetime),
                })
            })
            .collect::<Vec<_>>();
        let did_frames = contexts
            .iter()
            .flat_map(|context| context.anchors.iter().map(DidFrame::from_certificate))
            .collect::<Vec<_>>();
        let adoption = AdoptionFlowState::from_identity_contexts(contexts);
        let enrollment = EnrollmentFlowState::from_identity_contexts(contexts);
        Self::from_live_parts(
            profile,
            posture,
            LiveTrustParts {
                contexts: context_rows,
                identities,
                anchors_detail,
                schema_summaries,
                approvals: Vec::new(),
                key_inventory,
                validation_traces: Vec::new(),
                schema_reviews: Vec::new(),
                validation_frame: None,
                did_frames,
                adoption,
                enrollment,
                custody: CustodyWarning::from_profile(profile, posture),
            },
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_live_parts(
        _profile: &ForwarderProfile,
        posture: TrustPosture,
        parts: LiveTrustParts,
    ) -> Self {
        let namespace = parts
            .contexts
            .first()
            .map(|row| row.namespace.clone())
            .unwrap_or_else(|| "/".into());
        let identity = parts
            .identities
            .iter()
            .find(|row| row.active)
            .or_else(|| parts.identities.first())
            .map(|row| row.name.clone())
            .unwrap_or_else(|| "verification only".into());
        Self {
            namespace,
            identity,
            anchors: parts.anchors_detail.len(),
            schema_rules: parts.schema_summaries.iter().map(|row| row.rules).sum(),
            pending_approvals: parts.approvals.len(),
            posture,
            contexts: parts.contexts,
            identities: parts.identities,
            anchors_detail: parts.anchors_detail,
            schema_summaries: parts.schema_summaries,
            approvals: parts.approvals,
            safebag_import: SafeBagImportState::preview(_profile, posture),
            key_inventory: parts.key_inventory,
            validation_traces: parts.validation_traces,
            schema_reviews: parts.schema_reviews,
            custody: parts.custody,
            adoption: parts.adoption,
            enrollment: parts.enrollment,
            validation_frame: parts.validation_frame,
            did_frames: parts.did_frames,
        }
    }

    pub fn action_label(&self) -> &'static str {
        match self.posture {
            TrustPosture::Unsupported => "view compatibility notes",
            TrustPosture::None => "adopt trust context",
            TrustPosture::Ephemeral => "persist identity",
            TrustPosture::Valid => "review approvals",
            TrustPosture::Expired => "renew certificate",
            TrustPosture::Weakened => "review schema change",
            TrustPosture::Error => "inspect trust error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustContextRow {
    pub namespace: String,
    pub state: &'static str,
    pub source: &'static str,
    pub posture: TrustPosture,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRow {
    pub name: String,
    pub custodian: &'static str,
    pub certificate: &'static str,
    pub active: bool,
    pub private_key_owned_by_dashboard: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRow {
    pub name: String,
    pub fingerprint: String,
    pub origin: &'static str,
    pub state: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaSummaryRow {
    pub namespace: String,
    pub rules: usize,
    pub strictness: &'static str,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRow {
    pub subject: String,
    pub requester: String,
    pub challenge: &'static str,
    pub state: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeBagImportState {
    pub available: bool,
    pub summary: &'static str,
    pub warnings: Vec<&'static str>,
}

impl SafeBagImportState {
    fn unsupported() -> Self {
        Self {
            available: false,
            summary: "SafeBag import is unavailable for this attach target.",
            warnings: vec!["No dashboard-owned key storage is created."],
        }
    }

    fn preview(profile: &ForwarderProfile, posture: TrustPosture) -> Self {
        let browser = matches!(
            profile.attach_mode,
            AttachMode::BrowserEngine | AttachMode::RemoteWeb
        );
        let mut warnings = vec!["Private keys stay in reusable identity/custodian APIs."];
        if browser {
            warnings.push("Browser import requires a custodian-backed storage decision.");
        }
        if posture == TrustPosture::Ephemeral {
            warnings.push("Current identity is ephemeral; adoption should confirm persistence.");
        }
        Self {
            available: true,
            summary: "Ready to preview SafeBag metadata before handing it to the custodian.",
            warnings,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInventoryRow {
    pub identity: String,
    pub key_name: String,
    pub algorithm: &'static str,
    pub storage: &'static str,
    pub certificate_state: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationTraceRow {
    pub packet_name: String,
    pub signer: String,
    pub outcome: &'static str,
    pub rule: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationFrame {
    pub target: String,
    pub verdict: &'static str,
    pub failure: Option<String>,
    pub chain: Vec<ValidationChainStep>,
    pub rules: Vec<ValidationRuleRow>,
}

impl ValidationFrame {
    fn fixture(posture: TrustPosture) -> Self {
        Self {
            target: "/local/operator/status/%FE%01".into(),
            verdict: if matches!(posture, TrustPosture::Expired | TrustPosture::Error) {
                "invalid"
            } else {
                "valid"
            },
            failure: (posture == TrustPosture::Expired)
                .then(|| "certificate expired before the selected context could anchor it".into()),
            chain: vec![
                ValidationChainStep {
                    name: "/local/operator/dashboard/KEY/%01".into(),
                    signed_by: "/ndn/anchor/operator/KEY/%01".into(),
                    anchor: false,
                },
                ValidationChainStep {
                    name: "/ndn/anchor/operator/KEY/%01".into(),
                    signed_by: "/ndn/anchor/operator/KEY/%01".into(),
                    anchor: true,
                },
            ],
            rules: vec![ValidationRuleRow {
                data_pattern: "/local/operator/*".into(),
                key_pattern: "/local/operator/<KEY>".into(),
                matches: true,
            }],
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_chain_trace(trace: &ndn_security::validator::ChainTrace) -> Self {
        Self {
            target: trace.target.to_string(),
            verdict: if trace.failure.is_none() {
                "valid"
            } else {
                "invalid"
            },
            failure: trace.failure.as_ref().map(trace_failure_label),
            chain: trace
                .steps
                .iter()
                .map(|step| ValidationChainStep {
                    name: step.name.to_string(),
                    signed_by: step.signed_by.to_string(),
                    anchor: step.is_anchor,
                })
                .collect(),
            rules: trace
                .rules_applied
                .iter()
                .map(|rule| ValidationRuleRow {
                    data_pattern: rule.data_pattern.clone(),
                    key_pattern: rule.key_pattern.clone(),
                    matches: rule.matches,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationChainStep {
    pub name: String,
    pub signed_by: String,
    pub anchor: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationRuleRow {
    pub data_pattern: String,
    pub key_pattern: String,
    pub matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidFrame {
    pub did: String,
    pub source_name: String,
    pub verification_methods: usize,
    pub services: usize,
    pub also_known_as: Vec<String>,
}

impl DidFrame {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_certificate(cert: &ndn_security::Certificate) -> Self {
        let doc = ndn_security::cert_to_did_document(cert, None);
        Self {
            did: doc.id,
            source_name: cert.name.to_string(),
            verification_methods: doc.verification_methods.len(),
            services: doc.service.len(),
            also_known_as: doc.also_known_as,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaReviewRow {
    pub namespace: String,
    pub change: &'static str,
    pub posture: TrustPosture,
    pub operator_action: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyWarning {
    pub title: &'static str,
    pub detail: &'static str,
    pub owns_private_keys: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptionFlowState {
    pub available: bool,
    pub namespace_hint: String,
    pub fingerprint_hint: String,
    pub requires_oob_confirmation: bool,
    pub state: &'static str,
    pub next_action: &'static str,
}

impl AdoptionFlowState {
    fn unsupported() -> Self {
        Self {
            available: false,
            namespace_hint: "unsupported".into(),
            fingerprint_hint: "none".into(),
            requires_oob_confirmation: false,
            state: "unavailable",
            next_action: "attach to an ndn-rs TrustContext-capable target",
        }
    }

    fn fixture(profile: &ForwarderProfile, posture: TrustPosture) -> Self {
        let degraded = profile.capabilities.trust_context == FeatureState::Degraded;
        Self {
            available: true,
            namespace_hint: if degraded {
                "/sandbox".into()
            } else {
                "/local/operator".into()
            },
            fingerprint_hint: if posture == TrustPosture::None {
                "awaiting bootstrap ticket".into()
            } else {
                "sha256:7cc9...a14e".into()
            },
            requires_oob_confirmation: true,
            state: if posture == TrustPosture::None {
                "ready to adopt"
            } else {
                "pinned"
            },
            next_action: "compare fingerprint out-of-band before adoption",
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_security_contexts(contexts: &[std::sync::Arc<ndn_security::SignedTrustContext>]) -> Self {
        let Some(context) = contexts.first() else {
            return Self {
                available: true,
                namespace_hint: "/".into(),
                fingerprint_hint: "awaiting bootstrap ticket".into(),
                requires_oob_confirmation: true,
                state: "no adopted contexts",
                next_action: "scan or paste a bootstrap ticket",
            };
        };
        let fingerprint = context
            .anchors()
            .iter()
            .next()
            .map(|anchor| {
                format!(
                    "sha256:{}",
                    ndn_identity::Fingerprint::of_cert(anchor.value())
                )
            })
            .unwrap_or_else(|| "no anchor yet".into());
        Self {
            available: true,
            namespace_hint: context.namespace().to_string(),
            fingerprint_hint: fingerprint,
            requires_oob_confirmation: true,
            state: "adopted",
            next_action: "reject rollback and confirm any new anchor fingerprint",
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_identity_contexts(contexts: &[ndn_identity::TrustContext]) -> Self {
        let Some(context) = contexts.first() else {
            return Self {
                available: true,
                namespace_hint: "/".into(),
                fingerprint_hint: "awaiting bootstrap ticket".into(),
                requires_oob_confirmation: true,
                state: "no adopted contexts",
                next_action: "scan or paste a bootstrap ticket",
            };
        };
        Self {
            available: true,
            namespace_hint: context.name.to_string(),
            fingerprint_hint: format!("sha256:{}", context.anchor_fingerprint()),
            requires_oob_confirmation: true,
            state: "adopted",
            next_action: "compare fingerprint out-of-band before accepting updates",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentFlowState {
    pub available: bool,
    pub ca_endpoints: Vec<String>,
    pub challenge_summary: String,
    pub subject_hint: String,
    pub state: &'static str,
    pub next_action: &'static str,
}

impl EnrollmentFlowState {
    fn unsupported() -> Self {
        Self {
            available: false,
            ca_endpoints: Vec::new(),
            challenge_summary: "unavailable".into(),
            subject_hint: "none".into(),
            state: "unavailable",
            next_action: "attach to an ndn-rs or NDNCERT-capable target",
        }
    }

    fn fixture(profile: &ForwarderProfile, posture: TrustPosture) -> Self {
        let browser = matches!(
            profile.attach_mode,
            AttachMode::BrowserEngine | AttachMode::RemoteWeb
        );
        Self {
            available: profile.capabilities.trust_context.is_available(),
            ca_endpoints: vec!["/local/operator/CA".into()],
            challenge_summary: if browser {
                "browser-custodian + device-approval".into()
            } else {
                "token AND device-approval".into()
            },
            subject_hint: if posture == TrustPosture::Ephemeral {
                "/local/operator/dashboard/ephemeral".into()
            } else {
                "/local/operator/dashboard".into()
            },
            state: if posture == TrustPosture::Expired {
                "renewal needed"
            } else {
                "ready"
            },
            next_action: "run NDNCERT NEW/CHALLENGE through reusable enrollment APIs",
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_security_contexts(contexts: &[std::sync::Arc<ndn_security::SignedTrustContext>]) -> Self {
        let ca_endpoints = contexts
            .iter()
            .flat_map(|context| context.ca_endpoints().iter().map(ToString::to_string))
            .collect::<Vec<_>>();
        let challenge_summary = contexts
            .iter()
            .find_map(|context| context.enrollment_hint())
            .map(|hint| {
                let joiner = if hint.require_all { " AND " } else { " OR " };
                hint.challenges.join(joiner)
            })
            .filter(|summary| !summary.is_empty())
            .unwrap_or_else(|| "not advertised".into());
        Self {
            available: !ca_endpoints.is_empty(),
            ca_endpoints,
            challenge_summary,
            subject_hint: "select identity".into(),
            state: "discovered",
            next_action: "start NDNCERT enrollment with a custodian signer",
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_identity_contexts(contexts: &[ndn_identity::TrustContext]) -> Self {
        let ca_endpoints = contexts
            .iter()
            .flat_map(|context| context.ca_endpoints.iter().map(ToString::to_string))
            .collect::<Vec<_>>();
        let subject_hint = contexts
            .iter()
            .flat_map(|context| context.identities.iter())
            .find(|identity| identity.capabilities.enroll)
            .map(|identity| identity.name.to_string())
            .unwrap_or_else(|| "select identity".into());
        Self {
            available: !ca_endpoints.is_empty(),
            ca_endpoints,
            challenge_summary: "ask CA profile".into(),
            subject_hint,
            state: "discovered",
            next_action: "run NDNCERT NEW/CHALLENGE through ndn-cert",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TofuAdoptionRequest {
    pub bootstrap_fragment: String,
    pub confirmed_oob: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TofuAdoptionReport {
    pub namespace: String,
    pub fingerprint: String,
    pub adopted: bool,
    pub message: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn execute_tofu_adoption(
    keyring: &ndn_security::Keyring,
    context: std::sync::Arc<ndn_security::SignedTrustContext>,
    request: &TofuAdoptionRequest,
) -> Result<TofuAdoptionReport, String> {
    if !request.confirmed_oob {
        return Err("out-of-band fingerprint confirmation is required".into());
    }
    let ticket = ndn_cert::BootstrapTicket::from_fragment(&request.bootstrap_fragment)
        .map_err(|error| format!("invalid bootstrap ticket: {error}"))?;
    let fingerprint = ticket.anchor_fp_hex.clone();
    let namespace = ticket.namespace.clone();
    let adopted = ndn_cert::adopt_with_tofu(keyring, context, &ticket);
    if !adopted {
        return Err(
            "TOFU adoption rejected: namespace/fingerprint mismatch or anti-rollback refused it"
                .into(),
        );
    }
    Ok(TofuAdoptionReport {
        namespace,
        fingerprint: format!("sha256:{fingerprint}"),
        adopted,
        message: "TrustContext adopted after OOB fingerprint confirmation".into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentExecutionRequest {
    pub subject_name: String,
    pub validity_secs: u64,
    pub challenge: EnrollmentChallengeInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentChallengeInput {
    Token {
        token: String,
    },
    Possession {
        cert_name: String,
        signature: Vec<u8>,
    },
    Custom {
        challenge_type: String,
        parameters: serde_json::Map<String, serde_json::Value>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentExecutionReport {
    pub cert_name: String,
    pub fingerprint: String,
    pub state: &'static str,
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn execute_ndncert_enrollment(
    client: &mut ndn_identity::enroll::NdncertClient,
    signer: std::sync::Arc<dyn ndn_security::Signer>,
    request: EnrollmentExecutionRequest,
) -> Result<EnrollmentExecutionReport, String> {
    let name = request
        .subject_name
        .parse()
        .map_err(|error| format!("invalid subject name: {error}"))?;
    let challenge = match request.challenge {
        EnrollmentChallengeInput::Token { token } => ndn_identity::ChallengeParams::Token { token },
        EnrollmentChallengeInput::Possession {
            cert_name,
            signature,
        } => ndn_identity::ChallengeParams::Possession {
            cert_name,
            signature,
        },
        EnrollmentChallengeInput::Custom {
            challenge_type,
            parameters,
        } => ndn_identity::ChallengeParams::Custom {
            challenge_type,
            parameters,
        },
    };
    let cert = client
        .enroll(name, signer, request.validity_secs, challenge)
        .await
        .map_err(|error| format!("NDNCERT enrollment failed: {error}"))?;
    Ok(EnrollmentExecutionReport {
        cert_name: cert.name.to_string(),
        fingerprint: format!("sha256:{}", ndn_identity::Fingerprint::of_cert(&cert)),
        state: "issued",
    })
}

#[cfg(not(target_arch = "wasm32"))]
struct LiveTrustParts {
    contexts: Vec<TrustContextRow>,
    identities: Vec<IdentityRow>,
    anchors_detail: Vec<AnchorRow>,
    schema_summaries: Vec<SchemaSummaryRow>,
    approvals: Vec<ApprovalRow>,
    key_inventory: Vec<KeyInventoryRow>,
    validation_traces: Vec<ValidationTraceRow>,
    schema_reviews: Vec<SchemaReviewRow>,
    validation_frame: Option<ValidationFrame>,
    did_frames: Vec<DidFrame>,
    custody: CustodyWarning,
    adoption: AdoptionFlowState,
    enrollment: EnrollmentFlowState,
}

impl CustodyWarning {
    fn unsupported(profile: &ForwarderProfile) -> Self {
        let title = if matches!(profile.kind, ForwarderKind::Nfd | ForwarderKind::YaNfd) {
            "Compatibility target"
        } else {
            "Trust unavailable"
        };
        Self {
            title,
            detail: "This view does not create identity state for unsupported forwarders.",
            owns_private_keys: false,
        }
    }

    fn from_profile(profile: &ForwarderProfile, posture: TrustPosture) -> Self {
        match profile.attach_mode {
            AttachMode::BrowserEngine | AttachMode::RemoteWeb => Self {
                title: "Browser custodian required",
                detail: "Dashboard-next may request signing through browser-safe custodian APIs, but it must not own private key storage.",
                owns_private_keys: false,
            },
            _ if posture == TrustPosture::Ephemeral => Self {
                title: "Ephemeral identity",
                detail: "The active signer is temporary. Persist or adopt through reusable identity APIs before trusting long-lived operations.",
                owns_private_keys: false,
            },
            _ => Self {
                title: "Custodian boundary",
                detail: "Keys and trust policy remain in ndn-security, ndn-identity, ndn-cert, and custodian APIs.",
                owns_private_keys: false,
            },
        }
    }
}

fn context_rows(profile: &ForwarderProfile, posture: TrustPosture) -> Vec<TrustContextRow> {
    vec![
        TrustContextRow {
            namespace: "/local/operator".into(),
            state: if posture == TrustPosture::Valid {
                "active"
            } else {
                "needs review"
            },
            source: "ndn-security TrustContext",
            posture,
        },
        TrustContextRow {
            namespace: format!("/{}/mgmt", profile.kind.label().replace(' ', "-")),
            state: "read-only",
            source: "forwarder management profile",
            posture: if profile.capabilities.trust_context == FeatureState::Degraded {
                TrustPosture::Weakened
            } else {
                posture
            },
        },
    ]
}

fn identity_rows(profile: &ForwarderProfile, posture: TrustPosture) -> Vec<IdentityRow> {
    if posture == TrustPosture::None {
        return vec![IdentityRow {
            name: "no active identity".into(),
            custodian: "none",
            certificate: "missing",
            active: false,
            private_key_owned_by_dashboard: false,
        }];
    }
    let custodian = match profile.attach_mode {
        AttachMode::BrowserEngine | AttachMode::RemoteWeb => "browser custodian",
        AttachMode::Relay => "relay custodian",
        AttachMode::LocalDesktop => "desktop PIB/custodian",
    };
    vec![
        IdentityRow {
            name: "/local/operator/dashboard".into(),
            custodian,
            certificate: if posture == TrustPosture::Expired {
                "expired"
            } else {
                "valid"
            },
            active: true,
            private_key_owned_by_dashboard: false,
        },
        IdentityRow {
            name: "/local/operator/recovery".into(),
            custodian,
            certificate: "standby",
            active: false,
            private_key_owned_by_dashboard: false,
        },
    ]
}

fn anchor_rows(profile: &ForwarderProfile) -> Vec<AnchorRow> {
    if profile.capabilities.trust_context == FeatureState::Degraded {
        return vec![AnchorRow {
            name: "/sandbox/root".into(),
            fingerprint: "sha256:2f9b...sandbox".into(),
            origin: "browser fixture",
            state: "sandbox",
        }];
    }
    vec![
        AnchorRow {
            name: "/ndn/anchor/operator".into(),
            fingerprint: "sha256:7cc9...a14e".into(),
            origin: "configured anchor",
            state: "trusted",
        },
        AnchorRow {
            name: "/ndn/anchor/ca".into(),
            fingerprint: "sha256:51a2...90bf".into(),
            origin: "NDNCERT CA",
            state: "trusted",
        },
    ]
}

fn schema_rows(profile: &ForwarderProfile, posture: TrustPosture) -> Vec<SchemaSummaryRow> {
    vec![
        SchemaSummaryRow {
            namespace: "/local/operator/<KEY>".into(),
            rules: 3,
            strictness: if posture == TrustPosture::Weakened {
                "weakened"
            } else {
                "strict"
            },
            version: "v3".into(),
        },
        SchemaSummaryRow {
            namespace: format!("/{}/data", profile.kind.label().replace(' ', "-")),
            rules: if profile.capabilities.trust_context == FeatureState::Degraded {
                2
            } else {
                5
            },
            strictness: "compatible",
            version: "v1".into(),
        },
    ]
}

fn approval_rows(profile: &ForwarderProfile, posture: TrustPosture) -> Vec<ApprovalRow> {
    if posture != TrustPosture::Valid && posture != TrustPosture::Weakened {
        return Vec::new();
    }
    vec![ApprovalRow {
        subject: "/local/operator/device/phone/KEY/%01".into(),
        requester: "/local/operator/device/phone".into(),
        challenge: if matches!(
            profile.attach_mode,
            AttachMode::BrowserEngine | AttachMode::RemoteWeb
        ) {
            "browser-custodian"
        } else {
            "device-approval"
        },
        state: "pending operator review",
    }]
}

fn key_rows(profile: &ForwarderProfile, posture: TrustPosture) -> Vec<KeyInventoryRow> {
    identity_rows(profile, posture)
        .into_iter()
        .filter(|row| row.name != "no active identity")
        .map(|row| KeyInventoryRow {
            identity: row.name.clone(),
            key_name: format!("{}/KEY/%01", row.name),
            algorithm: "Ed25519",
            storage: row.custodian,
            certificate_state: row.certificate,
        })
        .collect()
}

fn validation_rows(_profile: &ForwarderProfile, posture: TrustPosture) -> Vec<ValidationTraceRow> {
    vec![
        ValidationTraceRow {
            packet_name: "/local/operator/status/%FE%01".into(),
            signer: "/local/operator/dashboard/KEY/%01".into(),
            outcome: if posture == TrustPosture::Expired {
                "expired cert"
            } else {
                "valid"
            },
            rule: "/local/operator/<KEY> signs /local/operator/*",
        },
        ValidationTraceRow {
            packet_name: "/localhost/nfd/faces/list".into(),
            signer: "/local/operator/dashboard/KEY/%01".into(),
            outcome: "valid management command",
            rule: "localhop command schema",
        },
    ]
}

fn schema_review_rows(_profile: &ForwarderProfile, posture: TrustPosture) -> Vec<SchemaReviewRow> {
    vec![SchemaReviewRow {
        namespace: "/local/operator".into(),
        change: if posture == TrustPosture::Weakened {
            "rule broadened"
        } else {
            "no pending change"
        },
        posture: if posture == TrustPosture::Weakened {
            TrustPosture::Weakened
        } else {
            TrustPosture::Valid
        },
        operator_action: if posture == TrustPosture::Weakened {
            "approve or reject schema weakening"
        } else {
            "monitor"
        },
    }]
}

fn did_rows_from_identities(identities: &[IdentityRow]) -> Vec<DidFrame> {
    identities
        .iter()
        .filter(|identity| identity.name.starts_with('/'))
        .map(|identity| DidFrame {
            did: format!("did:ndn:{}", identity.name.replace('/', "%2F")),
            source_name: identity.name.clone(),
            verification_methods: usize::from(identity.certificate != "missing"),
            services: 0,
            also_known_as: Vec::new(),
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn trace_failure_label(failure: &ndn_security::validator::TraceFailure) -> String {
    match failure {
        ndn_security::validator::TraceFailure::CertNotFound { name } => {
            format!("cert not found: {name}")
        }
        ndn_security::validator::TraceFailure::NoKeyLocator { name } => {
            format!("no KeyLocator in chain at {name}")
        }
        ndn_security::validator::TraceFailure::AnchorNotTrusted { name } => {
            format!("anchor not trusted: {name}")
        }
        ndn_security::validator::TraceFailure::ChainTooDeep { limit } => {
            format!("chain too deep: limit {limit}")
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn custodian_label(custodian: &ndn_identity::CustodianRef) -> &'static str {
    match custodian {
        ndn_identity::CustodianRef::InPage => "in-page custodian",
        ndn_identity::CustodianRef::BrowserExtension => "browser extension",
        ndn_identity::CustodianRef::OsKeyring => "OS keyring",
        ndn_identity::CustodianRef::Fob { .. } => "external fob",
        ndn_identity::CustodianRef::Remote { .. } => "remote signer",
        ndn_identity::CustodianRef::Tpm { .. } => "TPM",
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn identity_lifetime_label(lifetime: &ndn_identity::IdentityLifetime) -> &'static str {
    match lifetime {
        ndn_identity::IdentityLifetime::Persistent => "persistent",
        ndn_identity::IdentityLifetime::Ephemeral { .. } => "ephemeral",
        ndn_identity::IdentityLifetime::SessionScoped { .. } => "session",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fixtures;

    #[test]
    fn unsupported_profile_has_no_dashboard_owned_identity() {
        let summary =
            TrustContextSummary::from_profile(&fixtures::nfd_profile(), TrustPosture::Unsupported);
        assert_eq!(summary.identity, "not available");
        assert_eq!(summary.anchors, 0);
        assert!(!summary.custody.owns_private_keys);
        assert!(summary.identities.is_empty());
    }

    #[test]
    fn native_trust_summary_keeps_keys_out_of_dashboard() {
        let summary = TrustContextSummary::from_profile(
            &fixtures::ndnrs_profile(crate::core::PlatformKind::Desktop),
            TrustPosture::Valid,
        );
        assert_eq!(summary.anchors, 2);
        assert_eq!(summary.pending_approvals, 1);
        assert!(
            summary
                .identities
                .iter()
                .all(|row| !row.private_key_owned_by_dashboard)
        );
        assert!(!summary.key_inventory.is_empty());
    }

    #[test]
    fn browser_trust_summary_warns_about_custody() {
        let summary = TrustContextSummary::from_profile(
            &fixtures::browser_engine_profile(),
            TrustPosture::Ephemeral,
        );
        assert_eq!(summary.custody.title, "Browser custodian required");
        assert!(
            summary
                .safebag_import
                .warnings
                .iter()
                .any(|warning| warning.contains("custodian"))
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn security_keyring_snapshot_feeds_trust_view_without_identity_ownership() {
        use std::sync::Arc;

        let validator = ndn_security::Validator::new(ndn_security::TrustSchema::new());
        let context = ndn_security::SignedTrustContext::hierarchical("/lab".parse().unwrap())
            .with_version(4)
            .with_ca_endpoint("/lab/CA".parse().unwrap())
            .with_enrollment_hint(ndn_security::EnrollmentHint::hub_default());
        assert!(validator.adopt_context(Arc::new(context)));

        let summary = TrustContextSummary::from_security_keyring(
            &fixtures::ndnrs_profile(crate::core::PlatformKind::Desktop),
            TrustPosture::Valid,
            validator.keyring().as_ref(),
        );

        assert_eq!(summary.namespace, "/lab");
        assert_eq!(summary.identity, "verification only");
        assert_eq!(summary.enrollment.ca_endpoints, vec!["/lab/CA"]);
        assert!(summary.identities.is_empty());
        assert!(!summary.custody.owns_private_keys);
    }
}
