//! §5.2 NDNCERT enrollment wizard.
//!
//! Four-step wizard that surfaces the NDNCERT three-stage seam
//! (`NamespacePolicy → ChallengeHandler → IssuancePolicy`) at each
//! step so the operator *sees* what each gatekeeper decided. v1
//! wraps the existing `security/ca-enroll` mgmt verb — the wizard's
//! job is education, not new wire.
//!
//! Step 1 pins §11.9 (operator-vs-user identity) per the design
//! followup's provisional answer: ask the user. The dashboard
//! groups operator-roles under the primary identity in the tree;
//! the underlying choice (distinct DID vs. distinct cert vs.
//! controller-relationship) stays a v2 deepening — v1 only records
//! the user's selection in the wizard, surfaces it through the
//! enrollment, and leaves the cert chain shape untouched.

use crate::app::{AppCtx, DashCmd};
use crate::edu_gloss::EduGloss;
use crate::types::CaInfo;
use dioxus::prelude::*;

/// Wizard global open/close state. Mounted at the App level so the
/// CA tab's "Enroll new identity" button + any other entry point
/// can launch it without prop drilling.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnrollmentWizardState {
    pub open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    ChooseCa = 1,
    ChooseName = 2,
    Challenge = 3,
    Issuance = 4,
    /// Post-submission: wizard stays open and renders the CA's
    /// response. `DashCmd::SecurityEnroll`'s handler writes the
    /// outcome into `ENROLLMENT_RESULT`, which step 5 reads.
    Result = 5,
}

impl Step {
    fn label(self) -> &'static str {
        match self {
            Step::ChooseCa => "Choose CA",
            Step::ChooseName => "Choose name",
            Step::Challenge => "Prove identity",
            Step::Issuance => "Issuance",
            Step::Result => "Result",
        }
    }

    fn ordinal(self) -> u8 {
        self as u8
    }
}

/// Outcome of an in-flight enrollment, populated by the
/// `DashCmd::SecurityEnroll` dispatcher and rendered by step 5.
///
/// The current `security/ca-enroll` verb returns synchronously
/// after spawning the NDNCERT round-trip, so `Submitted` is the
/// terminal state most operators see today; the actual cert
/// install happens asynchronously in the forwarder. When a future
/// mgmt extension surfaces enrollment progress / completion, the
/// `InFlight` and `Issued` variants populate from that stream.
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollmentResult {
    /// The Issue button fired and the dispatcher is waiting on
    /// `security/ca-enroll`'s ControlResponse.
    Submitting,
    /// The CA accepted the request and spawned the round-trip.
    /// `text` is the verb's status_text echo for debug surfacing.
    Submitted { text: String },
    /// The CA actually issued the cert (future state — populates
    /// once the wire signals completion). `cert_name` is the
    /// installed cert's full name.
    #[allow(dead_code)]
    Issued { cert_name: String },
    /// Verb rejected the request, or the transport failed.
    Failed { reason: String },
}

/// §11.9 operator-vs-user identity selection. Pinned at step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRole {
    /// Identity is for managing this forwarder. Recorded so the
    /// dashboard can group operator-role keys under the primary
    /// identity in the tree.
    Operator,
    /// Identity is the user's general-purpose signing identity for
    /// content + commands outside forwarder management.
    Primary,
}

impl IdentityRole {
    fn label(self) -> &'static str {
        match self {
            IdentityRole::Operator => "Operator role",
            IdentityRole::Primary => "Primary identity",
        }
    }

    fn description(self) -> &'static str {
        match self {
            IdentityRole::Operator => {
                "Manages this forwarder (mgmt-access policy edits, anchor installs, …)."
            }
            IdentityRole::Primary => {
                "General-purpose signing identity for content + commands outside forwarder management."
            }
        }
    }
}

/// What the wizard renders as the "NamespacePolicy decision" in step 2.
/// The actual decision comes from the CA when we submit; this is the
/// client-side check the wizard runs locally so the user sees the
/// expected outcome before issuing the request.
#[derive(Debug, Clone, PartialEq)]
pub struct NamespacePolicyPreview {
    pub under_ca_namespace: bool,
    pub detail: String,
}

pub fn preview_namespace_policy(name: &str, ca_prefix: &str) -> NamespacePolicyPreview {
    let name = name.trim();
    let ca = ca_prefix.trim().trim_end_matches('/');
    if name.is_empty() || ca.is_empty() {
        return NamespacePolicyPreview {
            under_ca_namespace: false,
            detail: "Both name and CA prefix are required.".to_owned(),
        };
    }
    if !name.starts_with('/') {
        return NamespacePolicyPreview {
            under_ca_namespace: false,
            detail: format!("Name must start with `/` (got `{name}`)."),
        };
    }
    if name == ca || name.starts_with(&format!("{ca}/")) {
        NamespacePolicyPreview {
            under_ca_namespace: true,
            detail: format!("`{name}` is under the CA's namespace `{ca}`."),
        }
    } else {
        NamespacePolicyPreview {
            under_ca_namespace: false,
            detail: format!("`{name}` is not under the CA's namespace `{ca}`."),
        }
    }
}

#[component]
pub fn EnrollmentWizardModal(state: Signal<EnrollmentWizardState>) -> Element {
    let ctx = use_context::<AppCtx>();
    let ca_info = ctx.ca_info.read().clone();
    let mut state = state;

    let mut step: Signal<Step> = use_signal(|| Step::ChooseCa);
    let role: Signal<IdentityRole> = use_signal(|| IdentityRole::Operator);
    let ca_prefix: Signal<String> = use_signal(|| {
        ca_info
            .as_ref()
            .map(|c| c.ca_prefix.clone())
            .unwrap_or_default()
    });
    let want_name: Signal<String> = use_signal(String::new);
    let challenge_type: Signal<String> = use_signal(|| {
        ca_info
            .as_ref()
            .and_then(|c| c.challenges.first().cloned())
            .unwrap_or_else(|| "token".to_owned())
    });
    let challenge_param: Signal<String> = use_signal(String::new);
    let mut submit_error: Signal<Option<String>> = use_signal(|| None);

    if !state.read().open {
        return rsx! {};
    }

    let mut close = move || {
        state.write().open = false;
        step.set(Step::ChooseCa);
        submit_error.set(None);
        *crate::app_shared::ENROLLMENT_RESULT.write() = None;
    };

    let cur_step = *step.read();
    let cur_ca = ca_prefix.read().clone();
    let cur_name = want_name.read().clone();
    let cur_challenge = challenge_type.read().clone();
    let cur_role = *role.read();
    let ns_preview = preview_namespace_policy(&cur_name, &cur_ca);

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:120;display:flex;align-items:center;justify-content:center;",
            onclick: move |_| close(),
            div {
                style: "background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;width:min(620px,95vw);max-height:92vh;overflow-y:auto;",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;",
                    div {
                        div { style: "font-size:14px;font-weight:600;color:var(--text);",
                            "NDNCERT enrollment · Step {cur_step.ordinal()} of 5 — {cur_step.label()}"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;",
                            EduGloss { term: "NDNCERT" }
                            " · §5.2"
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| close(),
                        "Cancel"
                    }
                }

                // Progress chips
                StepBar { current: cur_step }

                // Step content
                match cur_step {
                    Step::ChooseCa => rsx! {
                        StepChooseCa { ca_info: ca_info.clone(), ca_prefix, role }
                    },
                    Step::ChooseName => rsx! {
                        StepChooseName {
                            ca_prefix: cur_ca.clone(),
                            want_name,
                            preview: ns_preview.clone(),
                        }
                    },
                    Step::Challenge => rsx! {
                        StepChallenge {
                            challenges: ca_info
                                .as_ref()
                                .map(|c| c.challenges.clone())
                                .unwrap_or_default(),
                            challenge_type,
                            challenge_param,
                        }
                    },
                    Step::Issuance => rsx! {
                        StepIssuance {
                            ca_prefix: cur_ca.clone(),
                            want_name: cur_name.clone(),
                            challenge_type: cur_challenge.clone(),
                            role: cur_role,
                            ca_info: ca_info.clone(),
                        }
                    },
                    Step::Result => rsx! {
                        StepResult {}
                    },
                }

                if let Some(err) = submit_error.read().clone() {
                    div { style: "font-size:11px;color:var(--red,#f85149);margin-top:10px;",
                        "{err}"
                    }
                }

                // Action row
                div { style: "display:flex;gap:8px;justify-content:flex-end;margin-top:14px;border-top:1px solid var(--border-subtle);padding-top:12px;",
                    if cur_step.ordinal() > 1 && cur_step != Step::Result {
                        button {
                            class: "btn btn-secondary btn-sm",
                            onclick: move |_| {
                                let cur = *step.read();
                                let prev = match cur {
                                    Step::Issuance => Step::Challenge,
                                    Step::Challenge => Step::ChooseName,
                                    Step::ChooseName => Step::ChooseCa,
                                    Step::ChooseCa | Step::Result => Step::ChooseCa,
                                };
                                step.set(prev);
                            },
                            "Back"
                        }
                    }
                    match cur_step {
                        Step::Result => rsx! {
                            button {
                                class: "btn btn-primary btn-sm",
                                onclick: move |_| close(),
                                "Close"
                            }
                        },
                        Step::Issuance => rsx! {
                            button {
                                class: "btn btn-primary btn-sm",
                                onclick: move |_| {
                                    *crate::app_shared::ENROLLMENT_RESULT.write() =
                                        Some(EnrollmentResult::Submitting);
                                    ctx.cmd.send(DashCmd::SecurityEnroll {
                                        ca_prefix: ca_prefix.read().clone(),
                                        challenge_type: challenge_type.read().clone(),
                                        challenge_param: challenge_param.read().clone(),
                                    });
                                    step.set(Step::Result);
                                },
                                "Issue"
                            }
                        },
                        _ => rsx! {
                            button {
                                class: "btn btn-primary btn-sm",
                                onclick: move |_| {
                                    submit_error.set(None);
                                    let cur = *step.read();
                                    match cur {
                                        Step::ChooseCa => {
                                            if ca_prefix.read().trim().is_empty() {
                                                submit_error.set(Some(
                                                    "Choose a CA before continuing.".to_owned(),
                                                ));
                                                return;
                                            }
                                            step.set(Step::ChooseName);
                                        }
                                        Step::ChooseName => {
                                            let prev = preview_namespace_policy(
                                                &want_name.read(),
                                                &ca_prefix.read(),
                                            );
                                            if !prev.under_ca_namespace {
                                                submit_error.set(Some(prev.detail));
                                                return;
                                            }
                                            step.set(Step::Challenge);
                                        }
                                        Step::Challenge => {
                                            if challenge_param.read().trim().is_empty() {
                                                submit_error.set(Some(
                                                    "Provide a challenge parameter (token / email / …) before continuing."
                                                        .to_owned(),
                                                ));
                                                return;
                                            }
                                            step.set(Step::Issuance);
                                        }
                                        Step::Issuance | Step::Result => {}
                                    }
                                },
                                "Next"
                            }
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn StepBar(current: Step) -> Element {
    let steps = [
        Step::ChooseCa,
        Step::ChooseName,
        Step::Challenge,
        Step::Issuance,
        Step::Result,
    ];
    rsx! {
        div { style: "display:flex;gap:6px;margin-bottom:14px;",
            for s in steps.iter() {
                {
                    let s = *s;
                    let is_active = s == current;
                    let is_past = s.ordinal() < current.ordinal();
                    let bg = if is_active {
                        "var(--accent-solid)"
                    } else if is_past {
                        "var(--green,#3fb950)33"
                    } else {
                        "var(--surface2)"
                    };
                    let fg = if is_active {
                        "var(--surface)"
                    } else if is_past {
                        "var(--green,#3fb950)"
                    } else {
                        "var(--text-muted)"
                    };
                    rsx! {
                        div {
                            style: "flex:1;padding:4px 8px;font-size:10px;text-align:center;background:{bg};color:{fg};border-radius:4px;",
                            "{s.ordinal()}. {s.label()}"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StepChooseCa(
    ca_info: Option<CaInfo>,
    ca_prefix: Signal<String>,
    role: Signal<IdentityRole>,
) -> Element {
    let mut ca_prefix = ca_prefix;
    let mut role = role;
    rsx! {
        div { style: "margin-bottom:14px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "Which Certificate Authority issues your zone's certs?"
            }
            input {
                style: "width:100%;font-family:var(--font-mono);font-size:11px;padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);",
                placeholder: "/lab/router-ca",
                value: "{ca_prefix}",
                oninput: move |e| ca_prefix.set(e.value()),
            }
            if let Some(ca) = ca_info.as_ref() {
                div { style: "margin-top:8px;padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:11px;",
                    div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                        "Known CA"
                    }
                    div { class: "mono", "{ca.ca_prefix}" }
                    if !ca.ca_info.is_empty() {
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;", "{ca.ca_info}" }
                    }
                    div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;",
                        "Max validity: {ca.max_validity_days}d · Challenges: "
                        if ca.challenges.is_empty() {
                            "(none reported)"
                        } else {
                            "{ca.challenges.join(\", \")}"
                        }
                    }
                }
            }
        }

        // §11.9 identity-role pin.
        div { style: "border-top:1px solid var(--border-subtle);padding-top:10px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "What is this identity for?"
                span { style: "color:var(--text-muted);margin-left:6px;font-weight:400;",
                    "(§11.9)"
                }
            }
            for opt in [IdentityRole::Operator, IdentityRole::Primary] {
                {
                    let cur = *role.read();
                    let is_on = cur == opt;
                    let border = if is_on { "var(--accent-solid)" } else { "var(--border-subtle)" };
                    let bg = if is_on { "var(--accent-dim)" } else { "transparent" };
                    let style = format!(
                        "display:flex;gap:8px;align-items:flex-start;padding:6px 8px;border:1px solid {border};background:{bg};border-radius:4px;margin-bottom:4px;cursor:pointer;font-size:11px;"
                    );
                    rsx! {
                        label { style: "{style}",
                            input {
                                r#type: "radio",
                                name: "identity-role",
                                checked: is_on,
                                oninput: move |_| role.set(opt),
                            }
                            div {
                                div { style: "color:var(--text);font-weight:600;", "{opt.label()}" }
                                div { style: "color:var(--text-muted);font-size:10px;margin-top:2px;",
                                    "{opt.description()}"
                                }
                            }
                        }
                    }
                }
            }
            div { style: "font-size:10px;color:var(--text-muted);margin-top:6px;",
                "Pinned per design followups §11.9 — the dashboard groups operator-role keys under the primary identity in the tree; the underlying cert-chain shape stays unchanged in v1."
            }
        }
    }
}

#[component]
fn StepChooseName(
    ca_prefix: String,
    want_name: Signal<String>,
    preview: NamespacePolicyPreview,
) -> Element {
    let mut want_name = want_name;
    let bd = if preview.under_ca_namespace {
        "var(--green,#3fb950)55"
    } else {
        "var(--yellow,#f5c518)55"
    };
    let bg = if preview.under_ca_namespace {
        "#00220022"
    } else {
        "#2a240022"
    };
    let preview_style = format!(
        "border:1px solid {bd};background:{bg};border-radius:6px;padding:10px;font-size:11px;"
    );
    let verdict_label = if preview.under_ca_namespace {
        "✓ ALLOWED (preview)"
    } else {
        "✗ NOT UNDER CA NAMESPACE"
    };
    rsx! {
        div { style: "margin-bottom:14px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "What name do you want a cert for?"
            }
            input {
                style: "width:100%;font-family:var(--font-mono);font-size:11px;padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);",
                placeholder: "/lab/alice",
                value: "{want_name}",
                oninput: move |e| want_name.set(e.value()),
            }
            div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;",
                "CA namespace: ", span { class: "mono", "{ca_prefix}" }
            }
        }
        div { style: "{preview_style}",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                "NamespacePolicy decision (client-side preview)"
            }
            div { style: "color:var(--text);font-weight:600;margin-bottom:4px;",
                "{verdict_label}"
            }
            div { style: "color:var(--text-muted);", "{preview.detail}" }
            div { style: "color:var(--text-muted);font-size:10px;margin-top:6px;",
                "The CA's authoritative decision arrives with the issuance response."
            }
        }
    }
}

#[component]
fn StepChallenge(
    challenges: Vec<String>,
    challenge_type: Signal<String>,
    challenge_param: Signal<String>,
) -> Element {
    let mut challenge_type = challenge_type;
    let mut challenge_param = challenge_param;
    let known: Vec<String> = if challenges.is_empty() {
        vec![
            "token".to_owned(),
            "email".to_owned(),
            "possession".to_owned(),
        ]
    } else {
        challenges
    };
    let cur = challenge_type.read().clone();
    rsx! {
        div { style: "margin-bottom:14px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "Which challenge will you complete?"
            }
            for c in known.iter() {
                {
                    let c = c.clone();
                    let is_on = cur == c;
                    let border = if is_on { "var(--accent-solid)" } else { "var(--border-subtle)" };
                    let bg = if is_on { "var(--accent-dim)" } else { "transparent" };
                    let style = format!(
                        "display:flex;gap:8px;align-items:center;padding:6px 8px;border:1px solid {border};background:{bg};border-radius:4px;margin-bottom:4px;cursor:pointer;font-size:11px;"
                    );
                    rsx! {
                        label { style: "{style}",
                            input {
                                r#type: "radio",
                                name: "challenge",
                                checked: is_on,
                                oninput: {
                                    let c = c.clone();
                                    move |_| challenge_type.set(c.clone())
                                },
                            }
                            span { class: "mono", "{c}" }
                        }
                    }
                }
            }
        }
        div { style: "margin-bottom:6px;",
            label { style: "font-size:11px;color:var(--text-muted);",
                "Challenge parameter (token / email / cert name)"
            }
            input {
                style: "width:100%;font-family:var(--font-mono);font-size:11px;padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);margin-top:4px;",
                value: "{challenge_param}",
                oninput: move |e| challenge_param.set(e.value()),
            }
        }
        div { style: "font-size:10px;color:var(--text-muted);",
            "The "
            EduGloss { term: "ChallengeHandler" }
            " decides whether your proof satisfies the challenge after submission."
        }
    }
}

#[component]
fn StepIssuance(
    ca_prefix: String,
    want_name: String,
    challenge_type: String,
    role: IdentityRole,
    ca_info: Option<CaInfo>,
) -> Element {
    let max_days = ca_info.as_ref().map(|c| c.max_validity_days).unwrap_or(0);
    let expected_attestation_kind = challenge_type.clone();
    rsx! {
        div { style: "margin-bottom:14px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "ChallengeHandler decision"
            }
            div { style: "padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:11px;color:var(--text-muted);",
                "Decided after submission. The CA writes a "
                EduGloss { term: "ChallengeAttestation" }
                " for the satisfied challenge into the issued cert's signed "
                span { class: "mono", "AdditionalDescription" }
                " — surfaced under "
                span { class: "mono", "challenge_attestations" }
                " in the §4.2 trust-path inspector after issuance."
            }
        }
        div { style: "margin-bottom:14px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                EduGloss { term: "IssuancePolicy" }
                " decision (preview)"
            }
            div { style: "padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:11px;",
                if max_days > 0 {
                    div { "✓ Validity cap " span { class: "mono", "{max_days}d" } " (from CA profile)" }
                }
                div { "✓ Issuer signs as " span { class: "mono", "{ca_prefix}" } }
                div { "✓ Expected attestation kind: " span { class: "mono", "{expected_attestation_kind}" } }
                div { style: "color:var(--text-muted);margin-top:4px;font-size:10px;",
                    "Final policy lives forwarder-side. Defaults to "
                    span { class: "mono", "AcceptAllIssuance" }
                    "; deployments installing "
                    span { class: "mono", "RequireAttestationKind" }
                    " (ndn-cert) reject issuance when the expected attestation isn't recorded."
                }
            }
        }
        div {
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                "Cert preview"
            }
            div { style: "padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:11px;",
                div { "Identity: " span { class: "mono", "{want_name}" } }
                div { "CA: " span { class: "mono", "{ca_prefix}" } }
                div { "Challenge: " span { class: "mono", "{challenge_type}" } }
                div { "Role: " span { class: "mono", "{role.label()}" } }
            }
        }
    }
}

#[component]
fn StepResult() -> Element {
    let result = crate::app_shared::ENROLLMENT_RESULT.read().clone();
    match result {
        None | Some(EnrollmentResult::Submitting) => rsx! {
            div { style: "padding:18px;text-align:center;",
                div { style: "font-size:32px;color:var(--text-muted);margin-bottom:10px;",
                    "⏳"
                }
                div { style: "font-size:13px;color:var(--text);font-weight:600;margin-bottom:6px;",
                    "Submitting to CA…"
                }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;",
                    "The dashboard fired ", span { class: "mono", "security/ca-enroll" },
                    " and is waiting on the CA's ControlResponse. NDNCERT proceeds asynchronously inside the forwarder once the verb returns."
                }
            }
        },
        Some(EnrollmentResult::Submitted { text }) => rsx! {
            div { style: "padding:14px;",
                div { style: "display:flex;gap:10px;align-items:flex-start;margin-bottom:10px;",
                    div { style: "font-size:24px;color:var(--green,#3fb950);", "✓" }
                    div { style: "flex:1;",
                        div { style: "font-size:13px;color:var(--text);font-weight:600;",
                            "Enrollment submitted"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;line-height:1.5;",
                            "The CA accepted the request. The forwarder's enrollment task is now talking NDNCERT to the CA in the background; the cert lands in the PIB on success."
                        }
                    }
                }
                if !text.is_empty() {
                    div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:11px;color:var(--text-muted);",
                        span { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-right:6px;",
                            "ControlResponse"
                        }
                        span { class: "mono", "{text}" }
                    }
                }
                div { style: "font-size:10px;color:var(--text-muted);margin-top:10px;font-style:italic;",
                    "Watch the §4.1 Identities tab — the new cert appears there once the round-trip finishes. The §4.6 audit log records the issuance event."
                }
            }
        },
        Some(EnrollmentResult::Issued { cert_name }) => rsx! {
            div { style: "padding:14px;",
                div { style: "display:flex;gap:10px;align-items:flex-start;",
                    div { style: "font-size:24px;color:var(--green,#3fb950);", "✓" }
                    div { style: "flex:1;",
                        div { style: "font-size:13px;color:var(--text);font-weight:600;",
                            "Certificate issued"
                        }
                        div { class: "mono", style: "font-size:11px;color:var(--purple);margin-top:6px;word-break:break-all;",
                            "{cert_name}"
                        }
                    }
                }
            }
        },
        Some(EnrollmentResult::Failed { reason }) => rsx! {
            div { style: "padding:14px;",
                div { style: "display:flex;gap:10px;align-items:flex-start;",
                    div { style: "font-size:24px;color:var(--red,#f85149);", "✗" }
                    div { style: "flex:1;",
                        div { style: "font-size:13px;color:var(--text);font-weight:600;",
                            "Enrollment failed"
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:6px;line-height:1.5;",
                            "{reason}"
                        }
                    }
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_namespace_policy_accepts_strict_subname() {
        let p = preview_namespace_policy("/lab/alice", "/lab/router-ca");
        assert!(!p.under_ca_namespace, "alice is NOT under router-ca");

        let p = preview_namespace_policy("/lab/alice", "/lab");
        assert!(p.under_ca_namespace, "alice is under /lab");

        let p = preview_namespace_policy("/lab/alice/sub", "/lab/alice");
        assert!(p.under_ca_namespace);
    }

    #[test]
    fn preview_namespace_policy_rejects_empty_inputs() {
        assert!(!preview_namespace_policy("", "/lab").under_ca_namespace);
        assert!(!preview_namespace_policy("/lab/alice", "").under_ca_namespace);
    }

    #[test]
    fn preview_namespace_policy_requires_leading_slash() {
        let p = preview_namespace_policy("lab/alice", "/lab");
        assert!(!p.under_ca_namespace);
        assert!(p.detail.contains('/'));
    }

    #[test]
    fn preview_namespace_policy_handles_trailing_slash_on_ca() {
        let p = preview_namespace_policy("/lab/alice", "/lab/");
        assert!(
            p.under_ca_namespace,
            "trailing slash on CA shouldn't matter"
        );
    }

    #[test]
    fn preview_namespace_policy_exact_name_match() {
        let p = preview_namespace_policy("/lab", "/lab");
        assert!(
            p.under_ca_namespace,
            "exact match counts as under-namespace"
        );
    }

    #[test]
    fn identity_role_label_and_description() {
        for r in [IdentityRole::Operator, IdentityRole::Primary] {
            assert!(!r.label().is_empty());
            assert!(!r.description().is_empty());
        }
    }

    #[test]
    fn step_ordinals_are_one_indexed_and_increasing() {
        assert_eq!(Step::ChooseCa.ordinal(), 1);
        assert_eq!(Step::ChooseName.ordinal(), 2);
        assert_eq!(Step::Challenge.ordinal(), 3);
        assert_eq!(Step::Issuance.ordinal(), 4);
        assert_eq!(Step::Result.ordinal(), 5);
    }

    #[test]
    fn enrollment_result_variants_compare_by_value() {
        // Sanity: PartialEq across the variants the wizard branches on.
        assert_eq!(EnrollmentResult::Submitting, EnrollmentResult::Submitting);
        assert_ne!(
            EnrollmentResult::Submitted {
                text: "started".into(),
            },
            EnrollmentResult::Submitting,
        );
        assert_eq!(
            EnrollmentResult::Failed {
                reason: "nope".into()
            },
            EnrollmentResult::Failed {
                reason: "nope".into()
            },
        );
        assert_ne!(
            EnrollmentResult::Failed { reason: "a".into() },
            EnrollmentResult::Failed { reason: "b".into() },
        );
    }

    #[test]
    fn step_result_is_last_step() {
        // Pin that Result is the terminal step the wizard can reach.
        let all = [
            Step::ChooseCa,
            Step::ChooseName,
            Step::Challenge,
            Step::Issuance,
            Step::Result,
        ];
        let max = all.iter().map(|s| s.ordinal()).max().unwrap();
        assert_eq!(max, Step::Result.ordinal());
    }
}
