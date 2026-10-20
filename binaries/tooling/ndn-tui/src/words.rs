//! Every word the TUI shows for a code: refusal codes, details, link
//! details, next-step classes, events, relations and roles. One table.
//!
//! The daemon answers with codes and facts (`ndn-rs/docs/specs/mgmt-trust.md`);
//! the words are this module's. A sentence says what happened and, where it
//! helps, what to do in the TUI's own terms (the "Trusted prefixes",
//! "Connections" and "Node" screens, a prefix's screen; following a prefix,
//! joining, creating an invite, approving), never a host's commands or
//! configuration. A parameter that is missing drops its clause.
//!
//! Internally a code is worded as a *phrase*: lower-case start, no final
//! period, so it can be quoted inside another (a refusal's cause, a link
//! detail's causes); [`finish`] makes the shown sentence of it.

use ndn_cert::invites::TokenDenial;
use ndn_cert::report::{
    ContextChange, Decision, Detail, EnrollmentEnd, MembershipChange, MembershipEvent,
    MembershipRelation, NextStep, Params, RenewalFailure, TrustEvent, TrustRefusal,
};
use ndn_mgmt_wire::LinkDetail;
use ndn_mgmt_wire::events::LinkEvent;
use ndn_namespace::root::{SecretKind, SecretPurpose, SecretRequest, VersionChange};

/// The sentence for `code` with `params`; `None` for a code this table does
/// not know.
pub fn sentence(code: &str, params: &Params) -> Option<String> {
    phrase(code, params, &[]).map(|p| finish(&p))
}

/// A refusal in the TUI's words (its neutral sentence for an unknown code).
pub fn refusal(r: &TrustRefusal) -> String {
    sentence(&r.code, &r.params).unwrap_or_else(|| r.reason.clone())
}

/// A detail in the TUI's words.
pub fn detail(d: &Detail) -> String {
    sentence(&d.code, &d.params).unwrap_or_else(|| d.text.clone())
}

/// A link detail in the TUI's words, its causes worded in place.
pub fn link_detail(d: &LinkDetail) -> String {
    let words = |detail: &LinkDetail, causes: &[String]| {
        let w = W {
            code: detail.code.as_str(),
            p: &detail.params,
            causes,
        };
        link_phrase(&w).or_else(|| phrase(&detail.code, &detail.params, causes))
    };
    finish(&d.render(&words))
}

/// What the person can do next, by class.
pub fn next_step(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "Nothing to do.",
        NextStep::RetryLater => "Try again later.",
        NextStep::FixRequest => "Correct what was given and try again.",
        NextStep::GetInvite => "Get a new invite from a device that can add devices.",
        NextStep::Adopt => "Follow the trusted prefix first (Trusted prefixes).",
        NextStep::Enroll => "Join the trusted prefix (again).",
        NextStep::AskAdmin => "Have a device that can add devices approve it.",
        NextStep::Refresh => "Check the trusted prefix for updates.",
        NextStep::UseOtherDevice => "Do it on the main device or a device that can add devices.",
        NextStep::FixLocal => "Fix this device's setup: its key storage, settings or permissions.",
        NextStep::ProvideSecret => "Enter the right passphrase, PIN or recovery words.",
        NextStep::Wait => "Wait for what is under way.",
        NextStep::Other => "See the message.",
    }
}

/// One trust event as a line of the event log; `None` for an unknown kind.
pub fn trust_event(e: &TrustEvent) -> Option<String> {
    let line = match e {
        TrustEvent::ApprovalRequested { ca, request, role } => format!(
            "a device asks {ca} to approve it{} (request {request}): approve or deny it",
            role.as_deref()
                .map(|r| format!(" as {}", a_role(r)))
                .unwrap_or_default()
        ),
        TrustEvent::ApprovalDecided {
            ca,
            request,
            decision,
        } => {
            let how = match decision {
                Decision::Approved => "approved",
                Decision::Denied => "denied",
                Decision::Unknown => "decided",
            };
            format!("request {request} at {ca} was {how}")
        }
        TrustEvent::InviteCreated { ca, id, role } => format!(
            "an invite{} was created at {ca} (invite {id})",
            role.as_deref()
                .map(|r| format!(" for {}", a_role(r)))
                .unwrap_or_default()
        ),
        TrustEvent::InviteWithdrawn { ca, id } => format!("invite {id} at {ca} was withdrawn"),
        TrustEvent::InviteRedeemed { ca, id, role } => format!(
            "a device joined at {ca} with invite {id}{}",
            role.as_deref()
                .map(|r| format!(" as {}", a_role(r)))
                .unwrap_or_default()
        ),
        TrustEvent::CertificateIssued {
            ca,
            certificate,
            role,
        } => format!(
            "{ca} certified a device{}: {certificate}",
            role.as_deref()
                .map(|r| format!(" as {}", a_role(r)))
                .unwrap_or_default()
        ),
        TrustEvent::ContextUpdated {
            namespace,
            held_version,
            version,
            how,
            revoked,
        } => {
            let was = held_version
                .map(|v| format!(" (was version {v})"))
                .unwrap_or_default();
            let how = match how {
                ContextChange::Adopt => ", followed from its link",
                ContextChange::Refresh => ", found by a check for updates",
                ContextChange::Update => ", made on this device",
                ContextChange::Sync => ", received from another device",
                ContextChange::Unknown => "",
            };
            let revokes = if revoked.is_empty() {
                String::new()
            } else {
                format!("; it revokes {}", revoked.join(", "))
            };
            format!("{namespace} is now at version {version}{was}{how}{revokes}")
        }
        TrustEvent::MembershipChanged(m) => membership_line(m),
        TrustEvent::EnrollmentEnded {
            namespace,
            identity,
            state,
            ..
        } => {
            let how = match state {
                EnrollmentEnd::Denied => "was denied",
                EnrollmentEnd::Expired => "expired undecided",
                EnrollmentEnd::Failed => "could not be finished",
                EnrollmentEnd::Unknown => "ended",
            };
            format!("the request to join {namespace} as {identity} {how}")
        }
        TrustEvent::RenewalFailed { key, state, .. } => match state {
            RenewalFailure::Refused => format!(
                "renewing {key} was refused; the current certificate stays in use until it expires"
            ),
            RenewalFailure::Failed => format!(
                "renewing {key} failed; it is tried again, and the current certificate stays in \
                 use until it expires"
            ),
            RenewalFailure::Unknown => format!("renewing {key} failed"),
        },
        TrustEvent::Unknown => return None,
    };
    Some(finish(&line))
}

/// One links event as a line of the event log; `None` for an unknown kind.
pub fn link_event(e: &LinkEvent) -> Option<String> {
    let line = match e {
        LinkEvent::LinkChanged(state) => {
            let who = match &state.device {
                Some(device) => format!("{} ({device})", state.label),
                None => state.label.clone(),
            };
            let now = if !state.paths.is_empty() {
                let paths: Vec<String> = state.paths.iter().map(|p| path_label(p)).collect();
                format!("is up over {}", paths.join(" and "))
            } else if state.asleep {
                "is asleep behind its relay".to_owned()
            } else if let Some(down) = &state.down {
                let why = phrase(down, &Params::new(), &[]).unwrap_or_else(|| down.clone());
                format!("is down: {why}")
            } else {
                "is not connected".to_owned()
            };
            format!("the connection {who} {now}")
        }
        LinkEvent::LinkGone { label, .. } => format!("the connection {label} is no longer listed"),
        LinkEvent::Unknown => return None,
    };
    Some(finish(&line))
}

/// This device's relation to a trusted prefix, with its role there.
pub fn relation(relation: MembershipRelation, role: &str) -> &'static str {
    match relation {
        MembershipRelation::Owner => "owner (main device)",
        MembershipRelation::Following => "following",
        MembershipRelation::Member => match role {
            "admin" => "can add devices",
            "guest" => "guest",
            "node" => "always-on helper",
            _ => "member",
        },
    }
}

/// A role of a trusted prefix's layout (`admin`, `member`, `guest`, `node`).
pub fn role(role: &str) -> String {
    match role {
        "admin" => "can add devices".to_owned(),
        "member" => "member".to_owned(),
        "guest" => "guest".to_owned(),
        "node" => "always-on helper".to_owned(),
        other => other.to_owned(),
    }
}

/// Where a root key is kept (`os-keyring`, `sealed-file`, `yubikey-piv`,
/// `file`).
pub fn root_store(kind: &str) -> String {
    match kind {
        "os-keyring" => "the system keychain".to_owned(),
        "sealed-file" => "a passphrase-protected file".to_owned(),
        "yubikey-piv" => "a security key (YubiKey)".to_owned(),
        "file" => "a plain file (unprotected)".to_owned(),
        other => other.to_owned(),
    }
}

/// A connection's mode (`always`, `on-demand`, `on-demand:<secs>`, `off`).
pub fn link_mode(mode: &str) -> String {
    match mode {
        "always" => "always on".to_owned(),
        "off" => "off".to_owned(),
        m if m == "on-demand" || m.starts_with("on-demand:") => "on demand".to_owned(),
        other => other.to_owned(),
    }
}

/// The prompt for a secret a root operation asks for. Asking again to
/// confirm a new secret (`request.confirm`) is the caller's.
pub fn secret_prompt(request: &SecretRequest) -> String {
    let what = match request.kind {
        SecretKind::RootPassphrase => "Main-device passphrase",
        SecretKind::RootPin => "Main-device security key PIN",
        SecretKind::KitPassphrase => "Recovery kit passphrase",
        SecretKind::KitPin => "Recovery key PIN",
        SecretKind::KitWords => "Recovery words (24 words)",
    };
    let purpose = match &request.purpose {
        SecretPurpose::CreateRoot => "to protect the new main-device key".to_owned(),
        SecretPurpose::SignVersion(change) => {
            let change = match change {
                VersionChange::Revoke { name } => format!("revoking {name}"),
                VersionChange::AddKit { namespace } => {
                    format!("adding a recovery kit to {namespace}")
                }
                VersionChange::RevokeKit { key } => format!("revoking the recovery kit {key}"),
                VersionChange::UpdateSchema { namespace } => {
                    format!("updating the trust rules of {namespace}")
                }
            };
            format!("to sign a new version {change}")
        }
        SecretPurpose::MoveRoot => "to move the main-device key".to_owned(),
        SecretPurpose::SealRoot => "to protect the main-device key in its new place".to_owned(),
        SecretPurpose::CreateKit { namespace } => format!("to make a recovery key for {namespace}"),
        SecretPurpose::SealKit => "to protect the new recovery kit".to_owned(),
        SecretPurpose::CheckKit { namespace } => {
            format!("to check the recovery kit of {namespace} (nothing is signed)")
        }
        SecretPurpose::Recover { namespace } => format!("to recover {namespace}"),
    };
    format!("{what} {purpose}")
}

// --- phrases -------------------------------------------------------------

/// A code with its params and its causes' phrases (link details only).
struct W<'a> {
    code: &'a str,
    p: &'a Params,
    causes: &'a [String],
}

impl<'a> W<'a> {
    /// The param `key`, when set and not blank.
    fn get(&self, key: &str) -> Option<&'a str> {
        let p: &'a Params = self.p;
        p.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
    }

    fn or(&self, key: &str, fallback: &'a str) -> &'a str {
        self.get(key).unwrap_or(fallback)
    }

    /// `before` value `after` when `key` is set; empty otherwise.
    fn wrap(&self, key: &str, before: &str, after: &str) -> String {
        self.get(key)
            .map(|v| format!("{before}{v}{after}"))
            .unwrap_or_default()
    }

    /// ` (value)` when `key` is set.
    fn paren(&self, key: &str) -> String {
        self.wrap(key, " (", ")")
    }

    /// `: error` when the param `error` is set.
    fn error(&self) -> String {
        self.wrap("error", ": ", "")
    }

    /// `noun value`, or the bare `noun`.
    fn named(&self, key: &str, noun: &str) -> String {
        match self.get(key) {
            Some(v) => format!("{noun} {v}"),
            None => noun.to_owned(),
        }
    }

    /// `version N`, or `fallback`.
    fn version_or(&self, key: &str, fallback: &str) -> String {
        match self.get(key) {
            Some(v) => format!("version {v}"),
            None => fallback.to_owned(),
        }
    }

    /// `a member`, `an always-on helper`, … for the role in `key`, or
    /// `fallback`.
    fn a_role(&self, key: &str, fallback: &str) -> String {
        self.get(key)
            .map(a_role)
            .unwrap_or_else(|| fallback.to_owned())
    }

    /// The cause in words: the code named by the param `cause` (it shares
    /// these params), else the first of a link detail's causes.
    fn cause(&self) -> Option<String> {
        let p: &'a Params = self.p;
        self.get("cause")
            .filter(|c| *c != self.code)
            .and_then(|c| phrase(c, p, &[]))
            .or_else(|| self.causes.first().cloned())
    }

    /// `: cause`, when there is one.
    fn why(&self) -> String {
        self.cause().map(|c| format!(": {c}")).unwrap_or_default()
    }

    /// `: cause`, else `: <param key>`, else nothing.
    fn because(&self, key: &str) -> String {
        self.cause()
            .or_else(|| self.get(key).map(str::to_owned))
            .map(|c| format!(": {c}"))
            .unwrap_or_default()
    }

    /// `: cause; cause; …` of a link detail's causes.
    fn all_causes(&self) -> String {
        if self.causes.is_empty() {
            String::new()
        } else {
            format!(": {}", self.causes.join("; "))
        }
    }

    /// ` for N` as a duration, when `key` holds seconds.
    fn secs(&self, key: &str, before: &str, after: &str) -> String {
        self.get(key)
            .map(|s| format!("{before}{}{after}", duration(s)))
            .unwrap_or_default()
    }

    /// `before N after` as a duration, when `key` holds milliseconds.
    fn millis(&self, key: &str, before: &str, after: &str) -> String {
        self.get(key)
            .map(|ms| {
                let shown = match ms.parse::<f64>() {
                    Ok(ms) => duration(&(ms / 1000.0).to_string()),
                    Err(_) => ms.to_owned(),
                };
                format!("{before}{shown}{after}")
            })
            .unwrap_or_default()
    }
}

/// The phrase of `code`; `None` for a code this table does not know.
fn phrase(code: &str, p: &Params, causes: &[String]) -> Option<String> {
    let w = W { code, p, causes };
    trust_phrase(&w)
        .or_else(|| detail_phrase(&w))
        .or_else(|| approval_phrase(&w))
        .or_else(|| invite_phrase(&w))
        .or_else(|| root_phrase(&w))
        .or_else(|| data_phrase(&w))
        .or_else(|| link_phrase(&w))
}

/// The gate, adopt / refresh / update, enroll and renew refusals.
fn trust_phrase(w: &W<'_>) -> Option<String> {
    let ns = w.or("namespace", "the trusted prefix");
    let s = match w.code {
        "not-at-runtime" => match w.get("operation") {
            Some("ca-info") => "this device runs no certificate authority".to_owned(),
            Some("yubikey") => "this build cannot use security keys (YubiKey)".to_owned(),
            op => match op.and_then(operation) {
                Some(op) => {
                    format!("this device does not {op} while it runs: do it on another device")
                }
                None => {
                    "this device does not do that while it runs: do it on another device".to_owned()
                }
            },
        },
        "missing-parameter" => {
            let what = match w.get("parameter") {
                Some("Uri") => "a link or value",
                Some("Name") => "a name",
                Some("ContextData") => "the signed version",
                _ => "something it needs",
            };
            let to = w
                .get("operation")
                .and_then(operation)
                .map(|o| format!(" to {o}"))
                .unwrap_or_default();
            format!("the request{to} is missing {what}")
        }
        "trust-change-over-localhop" => "trust changes are made on the device itself, not from a \
                                         neighbouring device: do it on that device"
            .to_owned(),
        "trust-change-unidentified" => format!(
            "this connection does not say which user it comes from, so it cannot change what this \
             device trusts: connect on the device itself as {}",
            operators(w)
        ),
        "trust-change-not-operator" => format!(
            "{} may not change what this device trusts: only {} may",
            user(w),
            operators(w)
        ),
        "command-not-operator" => format!(
            "{} is not an operator of this device{}",
            user(w),
            if w.get("anchor_configured") == Some("true") {
                ", and it takes only signed commands from others"
            } else {
                ""
            }
        ),
        "command-signer-unverifiable" => "the command is signed, but this device has no trusted \
                                          key to check command signatures with: send it unsigned"
            .to_owned(),
        "command-no-anchor" => "this command must be signed by a key this device trusts for \
                                commands, and it trusts none"
            .to_owned(),
        "command-unsigned" => "this command must be signed with a key".to_owned(),
        "command-signature-refused" => {
            format!("the command's signature was refused{}", w.error())
        }
        "command-signer-pending" => {
            "the signing certificate is not known yet: try again in a moment".to_owned()
        }
        "validation-disabled" => {
            "validation is off on this device, so it manages no trust rules".to_owned()
        }

        "context-not-held" => format!(
            "this device does not follow {ns}: follow it on the Trusted prefixes screen first"
        ),
        "link-invalid" => format!(
            "the link cannot be read{}: check it and paste it again",
            w.paren("error")
        ),
        "context-unreachable" => format!(
            "the trust settings of {ns} could not be fetched{}. Try again later",
            w.error()
        ),
        "trust-change-in-progress" => format!(
            "another change to this trusted prefix is under way{}: wait for it to finish",
            w.paren("error")
        ),
        "context-refused" => format!(
            "the trust settings of {ns} failed their checks{}: make sure the link is the right one",
            w.paren("error")
        ),
        "different-root" => format!(
            "this device follows {ns} with another main device{} than the link expects{}; the one \
             it follows stays",
            w.wrap("held", " (fingerprint ", ")"),
            w.wrap("expected", " (fingerprint ", ")")
        ),
        "context-superseded" => format!(
            "a newer version of {ns}{} arrived meanwhile and is kept{}",
            w.wrap("now", " (version ", ")"),
            w.wrap("version", " instead of version ", "")
        ),
        "context-not-stored" => format!(
            "{} holds until this device restarts: it could not be saved{}{}",
            version_of(w, "version", ns),
            w.wrap("location", " to ", ""),
            w.error()
        ),
        "update-invalid" => format!("this is not a version of a trusted prefix{}", w.error()),
        "update-refused" => format!(
            "the new version of {ns} does not follow the version held{}{}",
            w.wrap("held_version", " (version ", ")"),
            w.error()
        ),
        "context-changed-meanwhile" => format!(
            "the trust settings of {ns} changed meanwhile{}: make the change again from the \
             current version",
            w.wrap("now", " (now version ", ")")
        ),

        "not-an-enroll-link" => format!(
            "this is neither an invite nor a trusted prefix's link{}",
            w.error()
        ),
        "enroll-busy" => format!("another join of {ns} is under way: wait for it"),
        "identity-invalid" => format!(
            "{} is not a device name of the form <prefix>/<role>/<device> in {ns}",
            w.named("identity", "the name")
        ),
        "identity-outside-invite" => match w.get("prefix") {
            Some(prefix) => format!(
                "the invite admits devices under {prefix} only{}",
                w.wrap("identity", ", not ", "")
            ),
            None => format!(
                "{} is outside what the invite admits{}",
                w.named("identity", "the name"),
                w.error()
            ),
        },
        "invite-for-another-role" => format!(
            "this invite is for {}, not for {}: get an invite for the right role",
            w.a_role("invite_role", "another role"),
            w.a_role("role", "this one")
        ),
        "role-by-invite" => format!(
            "in {ns}, {} joins with an invite: get one from a device that can add devices",
            w.a_role("role", "a device of this role")
        ),
        "role-needs-invite-and-approval" => format!(
            "in {ns}, {} joins with an invite and an approval: get an invite first",
            w.a_role("role", "a device of this role")
        ),
        "already-certified" => {
            let judged = match w.get("judged_version") {
                Some(v) => format!(
                    " (checked against version {v}; whether a newer version revokes it could not \
                     be checked{})",
                    w.because("judged_detail")
                ),
                None => String::new(),
            };
            format!(
                "this device has joined {ns} already{}{judged}. Join again only to replace its key",
                w.wrap("still_valid", ": ", "")
            )
        }
        "keys-unreadable" => format!("the device's keys could not be read{}", w.error()),
        "requests-unreadable" => format!(
            "the device's join requests could not be read or saved{}",
            w.error()
        ),
        "key-not-generated" => format!(
            "no device key could be made{}{}",
            w.wrap("location", " in ", ""),
            w.error()
        ),
        "invite-invalid" => format!(
            "this invite cannot be used{}{}: get a new one",
            w.wrap("namespace", " for ", ""),
            w.paren("error")
        ),
        "invite-refused" => {
            let why = w
                .get("error")
                .map(|e| {
                    TokenDenial::of_reason(e)
                        .and_then(|d| phrase(d.as_str(), &Params::new(), &[]))
                        .unwrap_or_else(|| e.to_owned())
                })
                .map(|e| format!(": {e}"))
                .unwrap_or_default();
            format!("the invite was refused{why}{}", adopted(w))
        }
        "device-name-invalid" => format!("the device name is not valid{}", w.error()),
        "device-name-taken" => "that device name is taken already: choose another".to_owned(),
        "ca-unreachable" => format!(
            "the certificate authority could not be reached{}{}. Try again later",
            w.error(),
            adopted(w)
        ),
        "ca-refused" => format!(
            "the certificate authority refused the request{}{}",
            w.error(),
            adopted(w)
        ),
        "request-expired" => format!("the join request expired{}: join again", w.paren("error")),
        "request-denied" => format!("the join request was denied{}", w.error()),
        "issued-certificate-refused" => format!(
            "the certificate issued failed its checks{}: check the trusted prefix for updates and \
             join again",
            w.paren("error")
        ),
        "signing-failed" => format!(
            "a key could not sign{}{}",
            w.wrap("ca", " for the certificate authority ", ""),
            w.error()
        ),
        "request-not-recorded" => format!(
            "the certificate authority holds the join request{}, but this device could not save \
             it{}{}: join again",
            w.wrap("code", " (code ", ")"),
            w.wrap("location", " in ", ""),
            w.error()
        ),
        "certificate-not-kept" => {
            let spent = match w.get("spent") {
                Some("invite") => ". The invite is used up: get a new one",
                Some("approval") => ". The approval is used up: ask again",
                _ => "",
            };
            format!(
                "{} could not be saved{}{}; nothing changed{spent}",
                w.named("certificate", "the certificate"),
                w.wrap("location", " in ", ""),
                w.error()
            )
        }

        "renewal-keys-unreadable" => {
            format!("the certificates to renew could not be read{}", w.error())
        }
        "nothing-to-renew" => {
            "this device holds no certificate to renew: join a trusted prefix first".to_owned()
        }
        _ => return None,
    };
    Some(s)
}

/// The details of outcomes (refresh, update, renew, enroll, requests) and
/// the approval listing's notes.
fn detail_phrase(w: &W<'_>) -> Option<String> {
    let ns = w.or("namespace", "the trusted prefix");
    let s = match w.code {
        "refresh-source" => "this is the main device: new versions are made here".to_owned(),
        "refresh-current" => format!("up to date{}", w.wrap("version", " (version ", ")")),
        "refresh-upstream-older" => format!(
            "what answered{} is older than the version held{}; it is kept{}",
            w.wrap("offered", " (version ", ")"),
            w.wrap("held", " (version ", ")"),
            w.secs(
                "freshness_secs",
                ". An older answer may be served for up to ",
                ""
            )
        ),
        "refresh-behind" => format!(
            "what answered{} is older than {}{}{}",
            w.wrap("answered", " (version ", ")"),
            w.version_or("verified", "a version known to exist"),
            w.wrap("by", " (known from ", ")"),
            w.secs(
                "freshness_secs",
                ". An older answer may be served for up to ",
                ""
            )
        ),
        "refresh-unreachable" => {
            format!("nothing answered for the newest version{}", w.error())
        }
        "refresh-failed" => format!("the check failed{}", w.error()),
        "context-updated" => format!(
            "took {}{}{}{}{}",
            w.version_or("version", "a newer version"),
            w.wrap("signer", " (signed by ", ")"),
            w.wrap("walked", " through versions ", ""),
            kept(w),
            ca_tail(w)
        ),
        "update-adopted" => format!(
            "took {}, made on this device{}{}{}{}",
            w.version_or("version", "the new version"),
            w.wrap("signer", " (signed by ", ")"),
            w.wrap("held", " after version ", ""),
            kept(w),
            ca_tail(w)
        ),
        "update-already-taken" => format!(
            "{} was taken already{}",
            w.version_or("version", "this version"),
            w.wrap("held", " (version ", " is held)")
        ),
        "context-check-timed-out" => format!(
            "checking {ns} took {}: it is checked again later",
            w.get("budget_secs")
                .map(|s| format!("longer than {}", duration(s)))
                .unwrap_or_else(|| "too long".to_owned())
        ),
        "renewal-revoked" => format!(
            "not renewed: the trusted prefix revokes {}",
            w.or("key", "the key")
        ),
        "renewal-key-unavailable" => format!(
            "not renewed: {} cannot sign{}",
            w.named("key", "the key"),
            w.error()
        ),
        "renewal-refused" => format!(
            "the certificate authority refused the renewal{}; renewing again does not help",
            w.error()
        ),
        "renewal-failed" => format!("the renewal failed{}; it is tried again", w.error()),
        "renewal-not-stored" => format!(
            "{} could not be saved{}{}",
            w.named("certificate", "the renewed certificate"),
            w.wrap("location", " in ", ""),
            w.error()
        ),
        "next-start-unsigned" => format!(
            "this device started without an identity: it signs as {} after a restart",
            w.or("identity", "its new identity")
        ),
        "next-start-configured-identity" => format!(
            "this device's settings fix its identity{}; {} is recorded as the default",
            w.wrap("configured", " as ", ""),
            w.or("identity", "the new one")
        ),
        "next-start-routing-key" => format!(
            "routing keeps its startup key until a restart; neighbours must trust {}",
            w.or("key", "that key")
        ),
        "next-start-not-activated" => format!(
            "{} is saved but not in use yet{}",
            w.named("identity", "the identity"),
            w.error()
        ),
        "request-unanswered" => format!(
            "the certificate authority never answered{} before it expired{}",
            w.wrap("request", " request ", ""),
            w.paren("expired")
        ),
        "request-ended" => {
            let what = w
                .cause()
                .or_else(|| w.get("error").map(str::to_owned))
                .unwrap_or_else(|| "the request ended".to_owned());
            let key = match (w.get("key"), w.get("deleted")) {
                (Some(key), Some("true")) => format!("; its key {key} was deleted"),
                (Some(key), _) => format!(
                    "; its key {key} could not be deleted{}{}",
                    w.paren("delete_error"),
                    w.wrap("location", ": delete it from ", "")
                ),
                (None, _) => String::new(),
            };
            format!("{what}{key}")
        }
        "request-names-no-ca" => {
            "the request record names no valid trusted prefix or certificate authority".to_owned()
        }
        "request-names-no-key" => "the request record names no valid trusted prefix, \
                                   certificate authority, identity or key"
            .to_owned(),
        "request-key-gone" => format!(
            "{} is gone{}",
            w.named("key", "the request's key"),
            w.wrap("why", ": ", "")
        ),

        "approvals-ca-unreachable" => format!(
            "the certificate authority of {ns} could not be asked{}; try again when it is up",
            w.error()
        ),
        "approvals-not-listed" => format!(
            "the certificate authority of {ns} refused to list its requests{}",
            w.because("error")
        ),
        _ => return None,
    };
    Some(s)
}

/// Deciding and listing approval requests.
fn approval_phrase(w: &W<'_>) -> Option<String> {
    let ca = w.named("ca", "the certificate authority");
    let s = match w.code {
        "nothing-to-approve" => "this device takes no approval requests: approve on the main \
                                 device or on a device that can add devices"
            .to_owned(),
        "approval-target-missing" => "choose a request to approve or deny".to_owned(),
        "approval-not-found" => format!("no such request{}", w.paren("target")),
        "approval-unknown-target" => format!(
            "{} is neither a request id nor a six-digit code",
            w.get("target")
                .map(|t| format!("\"{t}\""))
                .unwrap_or_else(|| "that".to_owned())
        ),
        "approval-no-code-match" => format!(
            "no pending request shows the code{}: compare it with the code on the new device",
            w.wrap("code", " ", "")
        ),
        "approval-not-pending" => {
            let at = match w.get("scope") {
                Some("local-and-administered") => {
                    " at this device's certificate authority or at those of the trusted prefixes \
                     it adds devices to"
                }
                Some("administered") => {
                    " at the certificate authorities of the trusted prefixes this device adds \
                     devices to"
                }
                _ => "",
            };
            format!(
                "no pending request matches{}{at}{}",
                w.wrap("target", " ", ""),
                w.wrap(
                    "unasked",
                    "; not every certificate authority could be asked: ",
                    ""
                )
            )
        }
        "approval-ambiguous" => match w.get("matches") {
            Some(matches) => format!(
                "several pending requests match{}: {matches}. Approve or deny by request id",
                w.wrap("target", " ", "")
            ),
            None => format!(
                "several pending requests show the code{}: approve or deny by request id",
                w.wrap("code", " ", "")
            ),
        },
        "approval-conflict" => "the request was decided differently meanwhile".to_owned(),
        "approval-decided" => {
            let state = match w.get("state") {
                Some("approved") => "approved",
                Some("denied") => "denied",
                _ => "decided",
            };
            format!(
                "{} was {state} already; a decision is final",
                w.named("request", "the request")
            )
        }
        "approval-expired" => format!(
            "{} expired undecided{}; the device must ask again",
            w.named("request", "the request"),
            w.paren("expired")
        ),
        "approval-unauthorized" => format!(
            "this device may not decide or list these requests{}: use the main device or a device \
             that can add devices",
            w.paren("error")
        ),
        "approval-bad-decision" => format!("the decision was not accepted{}", w.error()),
        "approval-not-recorded" => format!(
            "the certificate authority could not save the decision{}; nothing changed. Try again",
            w.error()
        ),
        "approval-refused-by-ca" => format!("{ca} refused{}", w.because("error")),
        "approval-ca-unreachable" => {
            format!("{ca} could not be asked{}. Try again later", w.error())
        }
        "approval-ca-bad-answer" => format!(
            "the answer of {ca} could not be read or trusted{}. Try again later",
            w.error()
        ),
        "approvals-unlisted" => format!(
            "no approval requests could be listed{}. Try again later",
            w.wrap("notes", ": ", "")
        ),
        _ => return None,
    };
    Some(s)
}

/// Invites (create, list, withdraw), the denials of an invite's token, and
/// the issued-certificate listing.
fn invite_phrase(w: &W<'_>) -> Option<String> {
    let ns = w.or("namespace", "the trusted prefix");
    let s = match w.code {
        "invite-no-ca" => "this device runs no certificate authority, so it creates no invites: \
                           create invites on the main device"
            .to_owned(),
        "invite-several-cas" => format!(
            "this device invites to several trusted prefixes{}: choose one",
            w.paren("namespaces")
        ),
        "invite-ca-unknown" => format!(
            "this device cannot invite to {}{}",
            w.or("requested", "that trusted prefix"),
            w.wrap("namespaces", "; it invites to ", "")
        ),
        "invite-request-invalid" => format!("the invite request is not valid{}", w.error()),
        "invite-role-unknown" => format!(
            "{} is not a role of this trusted prefix",
            w.get("role")
                .map(|r| format!("\"{r}\""))
                .unwrap_or_else(|| "that".to_owned())
        ),
        "invite-role-needs-approval" => format!(
            "in {ns}, {} is added only with an approval, never with an invite",
            w.a_role("role", "a device of this role")
        ),
        "invite-expiry-invalid" => format!(
            "that invite lifetime{} is not valid",
            w.secs("ttl_secs", " (", ")")
        ),
        "invite-device-invalid" => format!(
            "{} is not a valid device name{}",
            w.get("device")
                .map(|d| format!("\"{d}\""))
                .unwrap_or_else(|| "that".to_owned()),
            w.error()
        ),
        "invite-unknown" => format!("this invite is not known here{}", w.paren("id")),
        "invite-already-redeemed" => format!(
            "{} was used already{}: to undo it, revoke the device it added",
            w.named("id", "the invite"),
            w.wrap("redeemed_for", " by ", "")
        ),
        "invite-already-withdrawn" => {
            format!("{} was withdrawn already", w.named("id", "the invite"))
        }
        "invite-not-recorded" => format!(
            "the certificate authority could not save the change to the invite, so nothing \
             changed{}. Try again",
            w.error()
        ),
        "invite-not-made" => format!("no invite could be created{}", w.error()),
        "invite-missing" => "no invite was given".to_owned(),
        "invite-redeemed" => "this invite was used already".to_owned(),
        "invite-withdrawn" => "this invite was withdrawn".to_owned(),
        "invite-expired" => "this invite expired".to_owned(),
        "invite-out-of-scope" => "the name asked for is outside what this invite allows".to_owned(),

        "issued-no-ca" => {
            "this device runs no certificate authority, so it issued no certificates".to_owned()
        }
        "issued-ca-unknown" => format!(
            "this device runs no certificate authority of {}{}",
            w.or("requested", "that trusted prefix"),
            w.wrap("namespaces", "; it runs those of ", "")
        ),
        _ => return None,
    };
    Some(s)
}

/// Inspecting the Data under a name.
fn data_phrase(w: &W<'_>) -> Option<String> {
    let s = match w.code {
        "data-valid" => format!(
            "signed by {}{}: the signature verifies and its certificates lead to a trusted main \
             device",
            w.or("signer", "a trusted key"),
            w.wrap("namespace", ", vouched for by ", "")
        ),
        "data-digest-only" => {
            "intact (it carries a matching digest), but no signer vouches for it".to_owned()
        }
        "data-invalid" => format!("the data fails validation{}", w.error()),
        "data-refused" => {
            let why = match w.get("refusal") {
                Some("chain") => ": its certificates do not lead to a trusted main device",
                Some("revoked") => ": a key on its chain is revoked",
                Some("bad-signature") => ": its signature does not verify",
                Some("schema") => ": its signer may not sign this name",
                Some("untrusted-root") => ": it leads to a main device this device does not trust",
                Some("context") => ": the trust settings of its trusted prefix refused it",
                Some("unverifiable") => ": it could not be checked yet",
                _ => "",
            };
            let later = if w.get("final") == Some("false") {
                "; it may pass once its certificates arrive"
            } else {
                ""
            };
            format!("this device refused the data, so it was not kept to inspect{why}{later}")
        }
        "data-chain-incomplete" => format!(
            "{} could not be had in time{}",
            w.named("certificate", "a certificate on its chain"),
            w.millis("timeout_ms", " (waited ", ")")
        ),
        "data-unchecked" => "this device validates nothing: validation is off".to_owned(),
        "data-not-found" => {
            let nack = match w.get("nack") {
                Some("no-route") => "; there is no route for it",
                Some("congestion") => "; the path is congested",
                Some("duplicate") => "; the request was a duplicate",
                Some("not-yet") => "; it is not available yet",
                Some(_) => "; the request was turned back",
                None => "",
            };
            format!(
                "nothing{} reached this device in time{}{nack}{}",
                w.wrap("name", " under ", ""),
                w.millis("timeout_ms", " (waited ", ")"),
                w.error()
            )
        }
        _ => return None,
    };
    Some(s)
}

/// The root-device library's refusals (made on the main device).
fn root_phrase(w: &W<'_>) -> Option<String> {
    let ns = w.or("namespace", "the trusted prefix");
    let version = w.wrap("version", " (version ", ")");
    let secret = secret_label(w.get("secret"));
    let s = match w.code {
        "pib-unreadable" => format!(
            "the key storage{} could not be opened",
            w.wrap("pib", " at ", "")
        ),
        "root-local-failure" => format!("a local failure stopped it{}", w.error()),
        "not-root-device" => {
            "this device holds no main-device key: do this on the main device".to_owned()
        }
        "no-longer-root" => format!(
            "this device is no longer the main device of {ns}{version}: it was recovered elsewhere"
        ),
        // The link meaning (param `namespaces`) is the link table's.
        "namespace-not-held" if w.get("namespaces").is_none() => format!(
            "this device does not follow {ns}: follow it on the Trusted prefixes screen first"
        ),
        "no-namespace-held" => "this device follows no trusted prefix yet".to_owned(),
        "several-namespaces" => format!(
            "this device holds several trusted prefixes{}: choose one",
            w.paren("namespaces")
        ),
        "other-namespace-root" => format!(
            "this device is the main device of {} only, not of {}",
            w.or("namespace", "other trusted prefixes"),
            w.or("requested", "this one")
        ),
        "root-bad-request" => format!(
            "the request does not fit the trusted prefix's layout{}",
            w.error()
        ),
        "secret-unavailable" => {
            format!("nothing was entered for the {secret}, or the two entries differ")
        }
        "secret-needed" => format!(
            "{} is kept in {}: enter its {secret}",
            w.named("key", "the main-device key"),
            w.get("store")
                .map(root_store)
                .unwrap_or_else(|| "protected key storage".to_owned())
        ),
        "wrong-secret" => format!("that {secret} is wrong{}", w.wrap("path", " for ", "")),
        "bad-recovery-words" => format!("the recovery words are wrong{}", w.error()),
        "keychain-unavailable" => format!(
            "the system keychain is not reachable{}",
            w.wrap("reason", ": ", "")
        ),
        "no-default-root-store" => format!(
            "the system keychain is not reachable{}: choose where to keep the main-device key",
            w.paren("reason")
        ),
        "keychain-entry-missing" => format!(
            "the system keychain lost the entry that protects the main-device key{}",
            w.paren("path")
        ),
        "token-in-use" => format!(
            "{} holds a key the new one must not share it with: use another security key",
            w.named("serial", "the security key")
        ),
        "slot-in-use" => format!(
            "{}{} is in use: making a key there would destroy the one it holds",
            w.named("slot", "the slot"),
            w.wrap("serial", " of security key ", "")
        ),
        "root-store-not-built" => format!(
            "this build cannot keep keys in {}: use another device",
            w.get("store")
                .map(root_store)
                .unwrap_or_else(|| "that storage".to_owned())
        ),
        "token-failed" => format!("the security key failed{}", w.error()),
        "kit-token-too-old" => format!(
            "this security key's firmware{} is too old for a recovery kit",
            w.paren("firmware")
        ),
        "root-store-failed" => format!("the main-device key storage is unusable{}", w.error()),
        "root-store-unmovable" => format!(
            "the main-device key cannot be moved{}{}{}",
            w.get("from")
                .map(|s| format!(" from {}", root_store(s)))
                .unwrap_or_default(),
            w.get("to")
                .map(|s| format!(" to {}", root_store(s)))
                .unwrap_or_default(),
            w.wrap("reason", ": ", "")
        ),
        "root-not-unlocked" => format!(
            "the main-device key was not unlocked{}; nothing was signed",
            w.because("error")
        ),
        "already-initialized" => format!("{ns} is set up on this device already"),
        "namespace-policy-refused" => {
            format!("those trusted prefix rules are refused{}", w.error())
        }
        "revoke-outside-namespace" => format!(
            "{} is outside every trusted prefix this device is the main device of",
            w.named("name", "the name")
        ),
        "revoke-other-namespace" => format!(
            "{} is in {}, not in {}",
            w.named("name", "the name"),
            w.or("namespace", "another trusted prefix"),
            w.or("requested", "the one chosen")
        ),
        "revoke-namespace-ca" => format!(
            "{} is the certificate authority of {ns}: revoke devices one by one",
            w.named("name", "the name")
        ),
        "revoke-none-issued" => format!(
            "no certificate was issued under {}",
            w.or("name", "that device name")
        ),
        "revoke-refused" => format!(
            "{} cannot be revoked{}",
            w.named("name", "that key"),
            w.error()
        ),
        "nothing-to-sign" => format!(
            "{} has everything asked already: nothing to sign",
            w.version_or("version", "the current version")
        ),
        "not-a-kit" => format!(
            "{} is not a recovery kit{}",
            w.named("path", "the file"),
            w.wrap("reason", ": ", "")
        ),
        "kit-other-namespace" => format!(
            "this kit recovers {}, not {}",
            w.or("kit", "another trusted prefix"),
            w.or("namespace", "this one")
        ),
        "kit-not-an-anchor" => format!(
            "the kit's key{} is not a recovery key of {ns}{version}",
            w.wrap("key", " ", "")
        ),
        "not-a-recovery-kit" => format!(
            "{} is not a recovery kit of {ns}{version}",
            w.named("key", "the key")
        ),
        "kit-file-exists" => format!("a file is in the way{}", w.wrap("path", " at ", "")),
        "kit-not-added" => format!(
            "the kit was made, but no version listing it was signed{}; nothing changed{}",
            w.because("error"),
            w.wrap("removed", " and the kit file ", " was removed")
        ),
        "signer-not-an-anchor" => format!(
            "{} is not a main-device key of {ns}{version}",
            w.named("key", "the signing key")
        ),
        "already-root-device" => format!(
            "this device is the main device of {ns} already{}: nothing to recover",
            w.get("store")
                .map(|s| format!(" (its key is in {})", root_store(s)))
                .unwrap_or_default()
        ),
        "ca-present" => format!(
            "this key storage holds a certificate authority of the trusted prefix already{}",
            w.paren("path")
        ),
        "kept-kits-need-compromised" => {
            "kits are kept only when the old main device is marked as compromised".to_owned()
        }
        "device-store-mismatch" => format!(
            "the running device holds {} of {ns}, but its key storage holds {}",
            w.version_or("version", "a version"),
            w.version_or("stored", "another or none")
        ),
        "held-context-invalid" => format!(
            "the saved {} of {ns} does not verify",
            w.version_or("version", "version")
        ),
        "newest-behind" => format!(
            "a newer version of {ns} exists{}{}: check it for updates first, or the recovery \
             would split the trusted prefix",
            w.wrap("held_version", " than version ", ""),
            w.because("detail")
        ),
        "newest-unconfirmed" => format!(
            "whether {} of {ns} is the newest is unknown{}",
            w.version_or("held_version", "the version held"),
            w.because("detail")
        ),
        "recover-on-root-device" => {
            format!("this device is the main device of {ns}: nothing to recover")
        }
        "newest-failed" => format!(
            "the newest version of {ns} could not be fetched{}",
            w.because("detail")
        ),
        "newest-not-held" => {
            format!("this device does not follow {ns} and has no fingerprint to follow it with")
        }
        "newest-not-adopted" => format!(
            "following {ns} with the kit's fingerprint was refused{}",
            w.wrap("reason", ": ", "")
        ),
        "device-not-running" => format!(
            "the device is not running{}{}",
            w.wrap("address", " at ", ""),
            w.error()
        ),
        "device-unreachable" => format!(
            "the running device cannot be used{}{}",
            w.wrap("address", " at ", ""),
            w.error()
        ),
        "device-pib-unknown" => format!(
            "the running device did not say which key storage it uses{}",
            w.error()
        ),
        "device-other-pib" => format!(
            "the running device uses other key storage{} than this one{}: a version made here \
             must not go there",
            w.paren("device_pib"),
            w.paren("pib")
        ),
        "device-failed" => format!("the exchange with the running device failed{}", w.error()),
        "hand-over-refused" => {
            let why = w
                .get("device_code")
                .filter(|c| *c != w.code)
                .and_then(|c| phrase(c, &Params::new(), &[]))
                .or_else(|| w.get("reason").map(str::to_owned))
                .map(|y| format!(": {y}"))
                .unwrap_or_default();
            format!(
                "the running device did not take {}{why}",
                w.version_or("version", "the version")
            )
        }
        "hand-over-unreadable" => format!(
            "the running device's answer could not be read{}; it may have taken {}",
            w.error(),
            w.version_or("version", "the version")
        ),
        "hand-over-failed" => format!(
            "handing {} over failed{}; it may still be taken",
            w.version_or("version", "the version"),
            w.wrap("failure", ": ", "")
        ),
        "hand-over-unanswered" => format!(
            "the running device never answered{}; it may still take {}",
            w.paren("waits"),
            w.version_or("version", "the version")
        ),
        "version-not-stored" => format!(
            "no device runs, and the version could not be saved for its next start{}",
            w.error()
        ),
        "version-not-taken" => format!(
            "{} was not taken{}; nothing changed",
            w.version_or("version", "the signed version"),
            w.because("error")
        ),
        "hand-over-unknown" => format!(
            "whether the running device took {} is not known{}; it may still. Check again once \
             it is idle",
            w.version_or("version", "the version"),
            w.because("error")
        ),
        "schema-not-generated" => format!(
            "the trust rules of {ns} could not be generated{}",
            w.error()
        ),
        "schema-narrowing" => format!(
            "the update narrows what devices of {ns} may do{}: it is signed only if you agree to \
             narrow it",
            w.wrap("removed", " (it removes ", ")")
        ),
        "schema-unreadable" => format!(
            "part of the trust rules{} cannot be read{}",
            w.paren("blob"),
            w.error()
        ),
        "no-context-governs" => format!(
            "no trusted prefix this device follows covers {}: follow it first",
            w.or("name", "that name")
        ),
        _ => return None,
    };
    Some(s)
}

/// The links module: its command refusals and answers, and every link
/// detail (`ndn_mgmt_wire::link_code`).
fn link_phrase(w: &W<'_>) -> Option<String> {
    let ns = w.or("namespace", "the trusted prefix");
    let version = w.wrap("version", " (version ", ")");
    let peer = w.named("peer", "the other device");
    let relay = w.named("relay", "the relay");
    let s = match w.code {
        // command refusals
        "links-unknown-verb" => format!(
            "this device does not know that connection action{}",
            w.paren("verb")
        ),
        "links-not-running" => "this device runs no device links: it has no key".to_owned(),
        "link-label-missing" => "choose a connection".to_owned(),
        "link-mode-invalid" => format!(
            "{} is not a connection mode: choose always on, on demand (with an optional idle \
             time) or off",
            w.get("mode")
                .map(|m| format!("\"{m}\""))
                .unwrap_or_else(|| "that".to_owned())
        ),
        "link-not-found" => match w.get("label") {
            Some(label) => format!("no connection is called {label}"),
            None => "no such connection".to_owned(),
        },
        "link-not-configured" => format!(
            "{} connected in by itself and is not set up here, so it cannot be controlled: add it \
             on the Connections screen as a device or relay to link with",
            w.named("label", "the device")
        ),
        "link-mode-missing" => "choose a mode for the connection".to_owned(),
        "link-idle-out-of-range" => format!(
            "the idle time{} must be between {} and {}",
            w.secs("idle_secs", " (", ")"),
            duration(w.or("min", "10")),
            duration(w.or("max", "86400"))
        ),

        // command answers
        "linking" => format!(
            "connecting{} now; it stays wanted until you disconnect it",
            w.wrap("label", " to ", "")
        ),
        "link-released" => format!(
            "{} is no longer asked for: an off connection closes now, an on-demand one once \
             idle, and an always-on one stays up (set it to off to close it)",
            w.named("label", "the connection")
        ),
        "link-mode-set" => format!(
            "{} is now {}{} until this device restarts",
            w.named("label", "the connection"),
            w.get("mode")
                .map(link_mode)
                .unwrap_or_else(|| "in its new mode".to_owned()),
            w.secs("idle_secs", ", closing after ", " idle")
        ),

        // direct-path state
        "direct-up" => format!("a direct path{} is up", w.wrap("remote", " to ", "")),
        "direct-ended" => format!(
            "the direct path{} ended{}; traffic goes through {relay} until the next attempt",
            w.wrap("remote", " to ", ""),
            w.why()
        ),
        "direct-ended-peer-punches" => {
            format!("the direct path ended{}; {peer} tries again", w.why())
        }
        "direct-linked" => {
            "linked over a known address: no direct-path attempt is needed".to_owned()
        }
        "direct-waiting-for-relay" => {
            format!("waiting for the link to {relay} to try a direct path")
        }
        "direct-off-peer-entry" | "direct-refused-peer-entry" => format!(
            "this device's connection settings for {} turn direct paths off",
            w.or("peer", "that device")
        ),
        "direct-off-policy" => format!("the rules of {ns}{version} turn direct paths off"),
        "direct-off-roles" => format!(
            "the rules of {ns}{version} allow no direct path between {} and {}; traffic goes \
             through the relay",
            w.a_role("role", "this device's role"),
            w.a_role("peer_role", "the other device's role")
        ),
        "direct-full" => format!(
            "this device has {} direct paths up already; traffic goes through the relay",
            w.or("up", w.or("max", "all its"))
        ),
        "direct-members-first" => "other devices that sent traffic more recently get the free \
                                   direct paths first"
            .to_owned(),
        "direct-punching" => format!("trying a direct path through {relay}"),
        "direct-peer-punching" => format!("{peer} is trying a direct path"),
        "direct-peer-punches-again" => {
            format!("the last attempt failed{}; {peer} tries again", w.why())
        }
        "direct-repunching" => "this device's network changed: trying a direct path again from \
                                its new address"
            .to_owned(),

        // why a punch made no direct path
        "punch-relay-down" => "the relay's link is down".to_owned(),
        "punch-no-socket" => format!(
            "there is no link socket to try a direct path from{}",
            w.error()
        ),
        "punch-no-key" | "link-no-key" => {
            format!("this device has no usable link key{}", w.error())
        }
        "punch-answer-not-validated" => format!(
            "this device cannot check the answer of {}: it does not follow that device's trusted \
             prefix or lacks its certificates",
            w.or("device", "the other device")
        ),
        "punch-unrouted" => format!(
            "nothing routes the request to {} now",
            w.or("device", "the other device")
        ),
        "punch-unanswered" => format!(
            "{} did not answer{}: is it running and linked to the relay?",
            w.named("device", "the other device"),
            w.error()
        ),
        "punch-refused-by-peer" => format!(
            "{peer} refused the direct path{}",
            w.wrap("text", ": \"", "\"")
        ),
        "punch-answer-unusable" => format!("the answer of {peer} cannot be used{}", w.why()),
        "punch-socket-unbound" => format!("the link socket has no address{}", w.error()),
        "punch-unreachable" => format!(
            "{peer} offered no address this device can reach{}",
            w.wrap("socket", " from ", "")
        ),
        "punch-busy" => format!(
            "this device runs as many direct-path attempts as it can at once{}",
            w.paren("max")
        ),
        "punch-ended" => "the attempt ended".to_owned(),
        "punch-no-probe" => format!(
            "nothing arrived from {peer}{}{}: both networks drop unsolicited traffic or change \
             ports per destination",
            w.secs("secs", " within ", ""),
            w.wrap("probed", " (probes sent: ", ")")
        ),
        "punch-no-handshake" => format!(
            "probes from {peer} arrived{}, but no connection came up{}: the way back stays closed",
            w.paren("heard"),
            w.secs("secs", " within ", "")
        ),
        "punch-nothing-to-dial" => format!("{peer} offered no address to dial"),
        "punch-dials-failed" => format!("every attempt to reach {peer} failed{}", w.all_causes()),
        "punch-dial-failed" => format!(
            "dialling {} failed{}",
            w.or("address", "an address"),
            w.why()
        ),
        "answer-empty" => "the answer is empty".to_owned(),
        "answer-malformed" => format!("the answer cannot be read{}", w.error()),
        "answer-bad-key" => format!("the answer names no link key{}", w.error()),
        "answer-bad-signature" => format!("the answer's signature does not verify{}", w.error()),
        "answer-wrong-key" => format!(
            "the answer is signed by another key{} than the relay listed{}",
            w.paren("key"),
            w.paren("expected")
        ),
        "answer-unconfirmed" => format!(
            "this device has not joined the trusted prefix of {} and cannot confirm it",
            w.or("peer", "the other device")
        ),
        "answer-wrong-device" => format!(
            "the answer's certificate is of {}, not of {}",
            w.or("presented", "another device"),
            w.or("device", "the device tried")
        ),

        // why this device refused a punch
        "punch-clock" => {
            let off = match (
                w.get("signed_at_ms").and_then(|v| v.parse::<i128>().ok()),
                w.get("now_ms").and_then(|v| v.parse::<i128>().ok()),
            ) {
                (Some(at), Some(now)) => {
                    format!(
                        " (off by {})",
                        duration(&((at - now).abs() / 1000).to_string())
                    )
                }
                _ => String::new(),
            };
            format!(
                "the request's time is too far from this device's clock{off}: a replay, or a \
                 clock is wrong"
            )
        }
        "punch-replay" => "the request repeats an earlier one".to_owned(),
        "punch-rate" => format!(
            "too many requests from one key{}; try again later",
            w.get("burst")
                .map(|b| format!(
                    " (at most {b} at once{})",
                    w.secs("refill_secs", ", then one more every ", "")
                ))
                .unwrap_or_default()
        ),
        "punch-enrollment-only" => format!(
            "{} could connect only to join, which no direct path carries: it joins first",
            w.named("device", "the other device")
        ),
        "punch-sessions-full" => format!(
            "this device runs as many direct-path attempts as it can at once{}; try again later",
            w.paren("max")
        ),
        "punch-no-candidate" => "the request offers no address".to_owned(),
        "punch-no-socket-for" => format!(
            "this device has no link socket for {}{}",
            w.or("address", "the address offered"),
            w.error()
        ),

        // why a link did not come up, or ended
        "down-links-in" => "it connects to this device: there is no address to dial".to_owned(),
        "down-standby-relay" => "a standby relay, not needed now".to_owned(),
        "down-off" | "relay-off" => "off: it connects when asked".to_owned(),
        "down-on-demand" => format!(
            "on demand and closed: it connects on traffic or when this device is in use{}",
            w.secs("idle_secs", " (closes after ", " idle)")
        ),
        "down-dialling" => "connecting".to_owned(),
        "dial-failed" => format!(
            "the last attempt failed{}; trying again{}",
            w.why(),
            w.secs("retry_secs", " in ", "")
        ),
        "peer-shutting-down" => "the other device is shutting down".to_owned(),
        "link-tls" => format!("the secure handshake failed{}", w.error()),
        "link-connect" => format!("the connection could not be made{}", w.error()),
        "link-unexpected-key" => format!(
            "the other device presented another key{} than expected{}",
            w.paren("presented"),
            w.paren("expected")
        ),
        "link-closed-by-peer" => format!(
            "the other device closed the link{}{}",
            w.wrap("text", ": \"", "\""),
            w.wrap("reason", " (close code ", ")")
        ),
        "link-closed-here" => {
            let why = w
                .cause()
                .map(|c| format!(": {c}"))
                .unwrap_or_else(|| w.wrap("text", ": \"", "\""));
            format!(
                "this device closed the link{why}{}",
                w.wrap("reason", " (close code ", ")")
            )
        }
        "link-protocol" => format!("the other device broke the link protocol{}", w.error()),
        "link-timeout" => "the exchange timed out".to_owned(),
        "link-io" => format!("an input/output error{}", w.error()),

        // why this device refused a link
        "certificate-undecodable" => format!("its certificate cannot be read{}", w.error()),
        "certificate-for-another-key" => format!(
            "{} is for another key{}",
            w.named("certificate", "its certificate"),
            w.wrap("key", " than ", "")
        ),
        "membership-undecodable" => {
            format!("a membership certificate cannot be read{}", w.error())
        }
        "membership-not-bound" => format!(
            "a membership{} is not bound to this link (forged or replayed){}",
            w.paren("certificate"),
            w.error()
        ),
        "binding-unavailable" => format!(
            "this device cannot bind its memberships to the link{}",
            w.error()
        ),
        "issuer-undecodable" => format!("an issuer certificate cannot be read{}", w.error()),
        "key-revoked" => format!("{} is revoked in {ns}{version}", w.named("key", "the key")),
        "issuer-revoked" => format!(
            "the issuer{} of its certificate is revoked in {ns}{version}",
            w.wrap("issuer", " ", "")
        ),
        "root-collides" => format!(
            "{} belongs to another main device{} under {ns}, which this relay holds: the names \
             collide",
            w.named("certificate", "its certificate"),
            w.paren("root")
        ),
        "not-expected-key" => format!(
            "this device expects another key{} for {}{}",
            w.paren("expected"),
            w.or("peer", "that device"),
            w.wrap("key", ", not ", "")
        ),
        "not-expected-device" => format!(
            "this device expects {} here{}",
            w.or("expected", "another device"),
            w.wrap("devices", ", not ", "")
        ),
        "expected-device-unconfirmed" => {
            let device = w.or("device", "that device");
            format!(
                "this device expects {device} and cannot confirm the other device is it{}. It \
                 connects once it follows the trusted prefix of {device}, or once its connection \
                 settings name that device's key",
                w.why()
            )
        }
        "role-may-not-link" => format!(
            "the rules of {ns}{version} do not let {} link",
            w.a_role("role", "a device of this role")
        ),
        "role-may-not-relay" => format!(
            "the rules of {ns}{version} do not let {} relay for others",
            w.a_role("role", "a device of this role")
        ),
        "not-served-no-certificate" => {
            let serves = match w.get("policy") {
                Some("listed") => "this relay serves its own and listed trusted prefixes",
                Some("open") => "this open relay serves any trusted prefix",
                _ => "this relay serves trusted prefixes",
            };
            format!(
                "{serves}: it routes device names by certificate, and the other device sent \
                 none{}. It joins a trusted prefix, or add its key{} on the Connections screen",
                w.causes
                    .first()
                    .map(|c| format!("; {c}"))
                    .unwrap_or_default(),
                w.wrap("key", " ", "")
            )
        }
        "unrecognized-key" => format!(
            "{} is of no trusted prefix this device follows{} and not one it expects{}{}. The \
             other device joins a trusted prefix, or add its key on the Connections screen",
            w.named("key", "the key"),
            w.paren("held"),
            w.causes
                .first()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            w.causes
                .get(1)
                .map(|c| format!("; {c}"))
                .unwrap_or_default()
        ),
        "namespace-collides" => format!(
            "this relay serves {ns} for another main device{} now",
            w.paren("bound_root")
        ),
        "quota-namespace-links" => format!(
            "{ns} has as many links at this relay as it may{}",
            w.paren("max")
        ),
        "quota-links" => format!(
            "this relay's links for other trusted prefixes are at the limit{}",
            w.paren("max")
        ),
        "not-served-uncertified" => format!(
            "this relay follows {ns} but has not joined it, so it does not serve {}",
            w.or("device", "it")
        ),
        "not-served-unlisted" => {
            format!("this relay does not serve {ns}: its main device is not on the relay's list")
        }
        "not-served-own" => format!(
            "this relay serves only its own trusted prefixes{}",
            w.wrap("namespace", ", not ", "")
        ),
        "enrollment-links-full" => format!(
            "the relay's places for joining devices are full{}; the device tries again by itself",
            w.paren("max")
        ),
        "enrollment-possible" => format!(
            "a device can join {} over this relay while it shows no certificate of another \
             trusted prefix",
            w.or("namespaces", "a trusted prefix")
        ),
        "path-not-taken" => "the other device did not take the direct path".to_owned(),
        "path-no-punch" => "this device has no such direct-path attempt any more".to_owned(),
        "path-enrollment-only" => "a direct path carries full links only, and this device admits \
                                   the other device only to join"
            .to_owned(),
        "path-taken" => "another path came up first".to_owned(),
        "link-exists" => "these two devices are linked already".to_owned(),

        // why a certificate identifies nobody here
        "no-certificate" => "it sent no certificate".to_owned(),
        "not-device-certificate" => format!(
            "{} is not a device certificate of {ns}",
            w.named("certificate", "its certificate")
        ),
        "certificate-expired" => format!(
            "{} is outside its validity period: that device renews it on its Node screen",
            w.named("certificate", "its certificate")
        ),
        "certificate-unauthenticated" => format!(
            "{} is not signed by a key of {ns}",
            w.named("certificate", "its certificate")
        ),
        "certificate-invalid" => format!(
            "{} does not check out under {ns}{version}{}",
            w.named("certificate", "its certificate"),
            w.error()
        ),
        "certificate-chain-unknown" => format!(
            "the issuers of {} were not sent and are not known here",
            w.or("certificate", "its certificate")
        ),
        "foreign-no-root" => format!(
            "{} is of a trusted prefix this device does not follow, and no main-device \
             certificate came with it",
            w.named("certificate", "its certificate")
        ),
        "foreign-root-no-namespace" => format!(
            "the main-device certificate{} names no trusted prefix",
            w.wrap("root", " ", "")
        ),
        "foreign-not-device-certificate" => format!(
            "{} is not a device certificate of {ns}{}",
            w.named("certificate", "its certificate"),
            w.wrap("root", " (main device ", ")")
        ),
        "foreign-root-invalid-namespace" => format!(
            "the main-device certificate{} names no valid trusted prefix",
            w.wrap("root", " ", "")
        ),
        "foreign-root-expired" => format!(
            "the main-device certificate{} is outside its validity period",
            w.wrap("root", " ", "")
        ),
        "foreign-certificate-invalid" => format!(
            "{} does not check out against its main device{}{}",
            w.named("certificate", "its certificate"),
            w.paren("root"),
            w.error()
        ),
        "foreign-chain-incomplete" => format!(
            "the certificates sent do not reach the main device of {}",
            w.or("certificate", "its certificate")
        ),
        "namespace-not-held" => format!(
            "this device expects a particular device here, and the certificates are of trusted \
             prefixes it does not follow{}",
            w.paren("namespaces")
        ),

        // why a relay admits no enrollment link
        "no-enrollment-link" => format!(
            "this relay admits no device to join either{}",
            w.all_causes()
        ),
        "enrollment-links-off" => format!("the rules of {ns} turn joining over relays off"),
        "enrollment-no-ca" => format!("{ns} names no certificate authority to join at"),
        "enrollment-role-may-not-relay" => format!(
            "the rules of {ns} do not let {} relay",
            w.a_role("role", "this relay's role")
        ),
        "enrollment-no-certificate" => format!("this relay has not joined {ns}"),
        "enrollment-no-namespace" => "this relay follows no trusted prefix".to_owned(),

        // relays and serving
        "relay-linked" => format!("linked{}", w.wrap("cost", "; its routes cost ", "")),
        "relay-down" => format!(
            "down{}; trying again with backoff{}",
            w.why(),
            w.wrap("standing_in", "; standing in: ", "")
        ),
        "relay-chosen" => "chosen; connecting".to_owned(),
        "relay-chosen-on-demand" => {
            "chosen; it connects on traffic or when this device is in use".to_owned()
        }
        "relay-down-not-needed" => format!(
            "down{}, and not needed while {} preferred relays are chosen",
            w.why(),
            w.or("chosen", "more")
        ),
        "relay-standby" => format!(
            "standby: {} preferred relays are chosen{}",
            w.or("chosen", "more"),
            w.wrap("count", " (", " wanted)")
        ),
        "serve-own" => "this relay serves its own trusted prefixes".to_owned(),
        "serve-listed" => format!(
            "this relay serves its own trusted prefixes and those of listed main devices{}{}",
            w.paren("listed"),
            quotas(w)
        ),
        "serve-open" => format!("this relay serves every trusted prefix{}", quotas(w)),
        _ => return None,
    };
    Some(s)
}

// --- helpers ---------------------------------------------------------------

/// The shown sentence of a phrase: capitalized, ending in a full stop.
fn finish(phrase: &str) -> String {
    let phrase = phrase.trim();
    let mut chars = phrase.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out: String = first.to_uppercase().chain(chars).collect();
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// What a trust-admin verb does, for "this device does not …" (the verb's
/// name, with or without its module).
fn operation(op: &str) -> Option<&'static str> {
    Some(match op.rsplit('/').next().unwrap_or(op) {
        "context-adopt" => "follow trusted prefixes",
        "enroll" => "join trusted prefixes",
        "enroll-status" => "track join requests",
        "context-refresh" => "check trusted prefixes for updates",
        "context-update" => "take new versions of trusted prefixes",
        "renew" => "renew certificates",
        "memberships" => "list its trusted prefixes",
        "approvals" | "list-approvals" | "approve" | "deny" => "take approval requests",
        "invite-create" => "create invites",
        "invite-list" => "list invites",
        "invite-withdraw" => "withdraw invites",
        "data-inspect" => "inspect data",
        "issued-list" => "list issued certificates",
        _ => return None,
    })
}

/// The user a gate refusal is about.
fn user(w: &W<'_>) -> String {
    w.get("uid")
        .map(|uid| format!("the user with uid {uid}"))
        .unwrap_or_else(|| "this user".to_owned())
}

/// Who operates this device, from a gate refusal's params.
fn operators(w: &W<'_>) -> String {
    let own = format!("its own user{}", w.wrap("daemon_uid", " (uid ", ")"));
    match w.get("groups") {
        Some(groups) => format!("{own}, root or a member of {groups}"),
        None => format!("{own} or root"),
    }
}

/// `; this device follows <prefix> now` when an enrollment adopted one on
/// the way.
fn adopted(w: &W<'_>) -> String {
    w.get("adopted_namespace")
        .map(|ns| {
            format!(
                "; this device follows {ns} now{}",
                w.wrap("adopted_version", " (version ", ")")
            )
        })
        .unwrap_or_default()
}

/// `version N of <prefix>`, or the prefix.
fn version_of(w: &W<'_>, key: &str, ns: &str) -> String {
    match w.get(key) {
        Some(v) => format!("version {v} of {ns}"),
        None => ns.to_owned(),
    }
}

/// How a version taken was kept: saved (and shared), or held for this run.
fn kept(w: &W<'_>) -> String {
    if w.get("stored").is_some() {
        let shared = match w.get("published") {
            Some("true") => " and shared with other devices",
            Some("false") => "; other devices do not fetch it from this one",
            _ => "",
        };
        format!("; saved{shared}")
    } else {
        w.cause()
            .or_else(|| w.get("error").map(str::to_owned))
            .map(|why| format!("; it holds until this device restarts: {why}"))
            .unwrap_or_default()
    }
}

/// What a version taken changed at this device's certificate authority.
fn ca_tail(w: &W<'_>) -> String {
    let mut out = w.wrap(
        "ca_revoked",
        "; this device's certificate authority no longer serves ",
        ", and their device names are free again",
    );
    if let Some(e) = w.get("ca_not_persisted") {
        out.push_str(&format!(
            "; the certificate authority could not save that ({e}): it holds until this device \
             restarts"
        ));
    }
    out
}

/// `, up to …` of a relay's quotas.
fn quotas(w: &W<'_>) -> String {
    let parts: Vec<String> = [
        ("links_total", "links in all"),
        ("links_per_namespace", "links per trusted prefix"),
        ("interests_per_key", "Interests per second per key"),
        (
            "interests_per_namespace",
            "Interests per second per trusted prefix",
        ),
    ]
    .into_iter()
    .filter_map(|(key, what)| w.get(key).map(|v| format!("{v} {what}")))
    .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(", up to {}", parts.join(", "))
    }
}

/// A secret named by a refusal's `secret` param.
fn secret_label(secret: Option<&str>) -> &'static str {
    match secret {
        Some("root-passphrase") => "main-device passphrase",
        Some("root-pin") => "security key PIN",
        Some("kit-passphrase") => "recovery kit passphrase",
        Some("kit-pin") => "recovery key PIN",
        Some("kit-words") => "recovery words",
        _ => "secret",
    }
}

/// A role as a noun with its article: `a member`, `an always-on helper`.
pub fn a_role(role: &str) -> String {
    let noun = match role {
        "" => "device".to_owned(),
        "admin" => "device that can add devices".to_owned(),
        "member" => "member".to_owned(),
        "guest" => "guest".to_owned(),
        "node" => "always-on helper".to_owned(),
        other => format!("device with the role {other}"),
    };
    let article = if noun.starts_with(|c: char| "aeiou".contains(c)) {
        "an"
    } else {
        "a"
    };
    format!("{article} {noun}")
}

/// A path kind of a link (`direct`, `link`, `relay`).
fn path_label(path: &str) -> String {
    match path {
        "direct" => "a direct path".to_owned(),
        "link" => "its own link".to_owned(),
        "relay" => "a relay".to_owned(),
        other => other.to_owned(),
    }
}

/// Seconds as a short duration (`45 seconds`, `5 minutes`, `3 days`); the
/// value as given when it is no number.
fn duration(secs: &str) -> String {
    let Ok(s) = secs.trim().parse::<f64>() else {
        return secs.to_owned();
    };
    if !s.is_finite() || s < 0.0 {
        return secs.to_owned();
    }
    let (n, unit) = if s < 120.0 {
        (s, "second")
    } else if s < 7_200.0 {
        (s / 60.0, "minute")
    } else if s < 172_800.0 {
        (s / 3_600.0, "hour")
    } else {
        (s / 86_400.0, "day")
    };
    let n = n.round() as u64;
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// A membership change as a log line (a phrase).
fn membership_line(m: &MembershipEvent) -> String {
    let ns = &m.namespace;
    let v = m.version;
    let key = m
        .key
        .as_deref()
        .map(|k| format!(" with key {k}"))
        .unwrap_or_default();
    let valid = m
        .valid_until
        .as_deref()
        .map(|t| format!(", valid until {t}"))
        .unwrap_or_default();
    match m.change {
        MembershipChange::Adopted => format!("this device follows {ns} now (version {v})"),
        MembershipChange::Enrolled => format!(
            "this device joined {ns}{key}{valid}{}",
            m.request
                .as_deref()
                .map(|r| format!(" after request {r} was approved"))
                .unwrap_or_default()
        ),
        MembershipChange::Renewed => {
            format!("this device's certificate in {ns} was renewed{key}{valid}")
        }
        MembershipChange::Revoked => format!(
            "version {v} of {ns} revokes this device's key{}{}; now: {}",
            m.key
                .as_deref()
                .map(|k| format!(" {k}"))
                .unwrap_or_default(),
            m.revoked
                .as_deref()
                .map(|r| format!(" (through {r})"))
                .unwrap_or_default(),
            relation(m.relation, "")
        ),
        MembershipChange::RootChanged => format!(
            "{ns} has a new main device (version {v}{})",
            m.replaced_version
                .map(|r| format!(", replacing version {r}"))
                .unwrap_or_default()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use ndn_cert::report::{RefusalCode, code};
    use ndn_mgmt_wire::events::LinkState;
    use ndn_mgmt_wire::link_code;

    const SPEC: &str = include_str!("../../../../../ndn-rs/docs/specs/mgmt-trust.md");

    /// The token denial codes the spec names in prose (Invites).
    const TOKEN_DENIALS: &[&str] = &[
        "invite-missing",
        "invite-unknown",
        "invite-redeemed",
        "invite-withdrawn",
        "invite-expired",
        "invite-out-of-scope",
        "invite-not-recorded",
    ];

    /// What no shown text may contain: a host's commands, flags or
    /// configuration, the library's "namespace" (the TUI says "trusted
    /// prefix"), a "pin" for an expected fingerprint, and the marks of a
    /// clause left half-filled.
    const FORBIDDEN: &[&str] = &[
        "ndn-fwd",
        "ndn-ctl",
        "ndn-sec",
        " --",
        "[[",
        ".toml",
        "namespace",
        " pin",
        "pinned",
        "{",
        "}",
        "  ",
        " .",
        " ,",
        "()",
    ];

    #[derive(Clone, Copy)]
    enum Table {
        Codes,
        Next,
        Kind,
        Change,
        Other,
    }

    /// The codes, next-step values, event kinds, membership changes and
    /// param names of the spec's tables.
    #[derive(Default)]
    struct Spec {
        codes: BTreeSet<String>,
        next: BTreeSet<String>,
        kinds: BTreeSet<String>,
        changes: BTreeSet<String>,
        params: BTreeSet<String>,
    }

    fn is_kebab(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !s.starts_with('-')
            && !s.ends_with('-')
    }

    /// The code of a first cell that is exactly one backticked kebab-case
    /// token.
    fn single_code(cell: &str) -> Option<&str> {
        let inner = cell.strip_prefix('`')?.strip_suffix('`')?;
        is_kebab(inner).then_some(inner)
    }

    fn spec() -> Spec {
        let mut out = Spec::default();
        let mut table: Option<(Table, Option<usize>)> = None;
        for line in SPEC.lines() {
            let line = line.trim();
            if !line.starts_with('|') {
                table = None;
                continue;
            }
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let Some((kind, params_col)) = table else {
                let kind = match cells[0] {
                    "code" | "note code" => Table::Codes,
                    "`next`" => Table::Next,
                    "`kind`" => Table::Kind,
                    "`change`" => Table::Change,
                    _ => Table::Other,
                };
                table = Some((kind, cells.iter().position(|c| *c == "params")));
                continue;
            };
            let Some(code) = single_code(cells[0]) else {
                continue;
            };
            match kind {
                Table::Codes => {
                    out.codes.insert(code.to_owned());
                    if let Some(cell) = params_col.and_then(|i| cells.get(i)) {
                        let names = cell.split('`').skip(1).step_by(2).filter(|k| {
                            !k.is_empty()
                                && k.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
                                })
                        });
                        out.params.extend(names.map(str::to_owned));
                    }
                }
                Table::Next => {
                    out.next.insert(code.to_owned());
                }
                Table::Kind => {
                    out.kinds.insert(code.to_owned());
                }
                Table::Change => {
                    out.changes.insert(code.to_owned());
                }
                Table::Other => {}
            }
        }
        out
    }

    /// Every code a sentence is owed for: the spec's tables, the link
    /// catalogue and the token denials.
    fn all_codes(spec: &Spec) -> BTreeSet<String> {
        spec.codes
            .iter()
            .cloned()
            .chain(link_code::ALL.iter().map(|c| (*c).to_owned()))
            .chain(TOKEN_DENIALS.iter().map(|c| (*c).to_owned()))
            .collect()
    }

    fn membership(change: MembershipChange) -> MembershipEvent {
        MembershipEvent {
            namespace: "/home/bob".into(),
            relation: MembershipRelation::Member,
            change,
            version: 4,
            key: Some("/home/bob/member/phone/KEY/1".into()),
            revoked: Some("/home/bob/member/phone/KEY/1".into()),
            replaced_version: Some(3),
            valid_until: Some("2027-01-01T00:00:00Z".into()),
            request: Some("r1".into()),
        }
    }

    fn trust_samples() -> Vec<TrustEvent> {
        let ca = || "/home/bob/CA".to_owned();
        vec![
            TrustEvent::ApprovalRequested {
                ca: ca(),
                request: "r1".into(),
                role: Some("admin".into()),
            },
            TrustEvent::ApprovalDecided {
                ca: ca(),
                request: "r1".into(),
                decision: Decision::Approved,
            },
            TrustEvent::InviteCreated {
                ca: ca(),
                id: "i1".into(),
                role: Some("member".into()),
            },
            TrustEvent::InviteWithdrawn {
                ca: ca(),
                id: "i1".into(),
            },
            TrustEvent::InviteRedeemed {
                ca: ca(),
                id: "i1".into(),
                role: None,
            },
            TrustEvent::CertificateIssued {
                ca: ca(),
                certificate: "/home/bob/member/phone/KEY/1/NDNCERT/v=1".into(),
                role: Some("member".into()),
            },
            TrustEvent::ContextUpdated {
                namespace: "/home/bob".into(),
                held_version: Some(3),
                version: 4,
                how: ContextChange::Update,
                revoked: vec!["/home/bob/member/phone/KEY/1".into()],
            },
            TrustEvent::MembershipChanged(membership(MembershipChange::Enrolled)),
            TrustEvent::EnrollmentEnded {
                namespace: "/home/bob".into(),
                identity: "/home/bob/member/phone".into(),
                request: "r1".into(),
                state: EnrollmentEnd::Denied,
            },
            TrustEvent::RenewalFailed {
                key: "/home/bob/member/phone/KEY/1".into(),
                state: RenewalFailure::Failed,
                code: Some("renewal-failed".into()),
            },
        ]
    }

    fn link_samples() -> Vec<LinkEvent> {
        vec![
            LinkEvent::LinkChanged(LinkState {
                label: "pi".into(),
                key: Some("ab12".into()),
                device: Some("/home/bob/node/pi".into()),
                paths: Vec::new(),
                direct: "none".into(),
                mode: Some("always".into()),
                relay: None,
                asleep: false,
                down: Some("dial-failed".into()),
            }),
            LinkEvent::LinkGone {
                label: "pi".into(),
                key: None,
            },
        ]
    }

    /// The `kind` of an event's JSON.
    fn kind_of(json: serde_json::Value) -> String {
        json["kind"].as_str().unwrap().to_owned()
    }

    /// Every code the spec's tables list, every link code and every token
    /// denial has a sentence; every next step has a phrase; every event
    /// kind and membership change has a log line.
    #[test]
    fn every_spec_code_has_words() {
        let spec = spec();
        assert!(
            spec.codes.len() > 150,
            "the spec's code tables were not found ({} codes)",
            spec.codes.len()
        );
        let missing: Vec<String> = all_codes(&spec)
            .into_iter()
            .filter(|c| sentence(c, &Params::new()).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "no sentence for: {}",
            missing.join(", ")
        );

        assert!(spec.next.len() >= 13, "the next-step table was not found");
        for value in &spec.next {
            let step: NextStep =
                serde_json::from_value(serde_json::Value::String(value.clone())).unwrap();
            assert!(
                value == "other" || step != NextStep::Other,
                "`{value}` reads as no known next step"
            );
            assert!(!next_step(step).is_empty(), "no phrase for `{value}`");
        }

        let trust: BTreeMap<String, TrustEvent> = trust_samples()
            .into_iter()
            .map(|e| (kind_of(serde_json::to_value(&e).unwrap()), e))
            .collect();
        let links: BTreeMap<String, LinkEvent> = link_samples()
            .into_iter()
            .map(|e| (kind_of(serde_json::to_value(&e).unwrap()), e))
            .collect();
        assert!(!spec.kinds.is_empty(), "the event tables were not found");
        let unworded: Vec<&String> = spec
            .kinds
            .iter()
            .filter(|kind| {
                trust.get(*kind).and_then(trust_event).is_none()
                    && links.get(*kind).and_then(link_event).is_none()
            })
            .collect();
        assert!(
            unworded.is_empty(),
            "no log line for event kinds {unworded:?}"
        );

        assert!(
            !spec.changes.is_empty(),
            "the membership change table was not found"
        );
        for value in &spec.changes {
            let change: MembershipChange =
                serde_json::from_value(serde_json::Value::String(value.clone()))
                    .unwrap_or_else(|e| panic!("membership change `{value}`: {e}"));
            let event = TrustEvent::MembershipChanged(membership(change));
            assert!(trust_event(&event).is_some(), "no log line for `{value}`");
        }
        assert_eq!(trust_event(&TrustEvent::Unknown), None);
        assert_eq!(link_event(&LinkEvent::Unknown), None);
    }

    fn assert_clean(what: &str, text: &str) {
        assert!(!text.trim().is_empty(), "{what}: empty");
        for bad in FORBIDDEN {
            assert!(!text.contains(bad), "{what}: {bad:?} in {text:?}");
        }
    }

    /// No sentence, with its params missing or all set, names a host's
    /// commands or configuration, says "namespace" or "pin", or leaves a
    /// clause half-filled; a trust sentence never says "network".
    #[test]
    fn sentences_name_no_host_and_drop_missing_clauses() {
        let spec = spec();
        assert!(spec.params.len() > 50, "the spec's params were not found");
        let filled = |value: &str| -> Params {
            spec.params
                .iter()
                .map(|k| (k.clone(), value.to_owned()))
                .collect()
        };
        let param_sets = [Params::new(), filled("1"), filled("/home/bob/node/pi")];
        for code in all_codes(&spec) {
            for params in &param_sets {
                let Some(text) = sentence(&code, params) else {
                    continue;
                };
                assert_clean(&code, &text);
                if !link_code::ALL.contains(&code.as_str()) {
                    assert!(!text.contains("network"), "{code}: \"network\" in {text:?}");
                }
            }
        }

        for step in [
            NextStep::None,
            NextStep::RetryLater,
            NextStep::FixRequest,
            NextStep::GetInvite,
            NextStep::Adopt,
            NextStep::Enroll,
            NextStep::AskAdmin,
            NextStep::Refresh,
            NextStep::UseOtherDevice,
            NextStep::FixLocal,
            NextStep::ProvideSecret,
            NextStep::Wait,
            NextStep::Other,
        ] {
            assert_clean("next step", next_step(step));
        }
        for event in trust_samples() {
            assert_clean("trust event", &trust_event(&event).unwrap());
        }
        for change in [
            MembershipChange::Adopted,
            MembershipChange::Enrolled,
            MembershipChange::Renewed,
            MembershipChange::Revoked,
            MembershipChange::RootChanged,
        ] {
            let event = TrustEvent::MembershipChanged(membership(change));
            assert_clean("membership event", &trust_event(&event).unwrap());
        }
        for event in link_samples() {
            assert_clean("link event", &link_event(&event).unwrap());
        }
        for r in ["admin", "member", "guest", "node"] {
            assert_clean("role", &role(r));
            for rel in [
                MembershipRelation::Owner,
                MembershipRelation::Following,
                MembershipRelation::Member,
            ] {
                assert_clean("relation", relation(rel, r));
            }
        }
        for store in ["os-keyring", "sealed-file", "yubikey-piv", "file"] {
            assert_clean("root store", &root_store(store));
        }

        let name = |uri: &str| uri.parse::<ndn_packet::Name>().unwrap();
        let purposes = [
            SecretPurpose::CreateRoot,
            SecretPurpose::SignVersion(VersionChange::Revoke {
                name: name("/home/bob/member/phone"),
            }),
            SecretPurpose::SignVersion(VersionChange::AddKit {
                namespace: name("/home/bob"),
            }),
            SecretPurpose::SignVersion(VersionChange::RevokeKit {
                key: name("/home/bob/KEY/kit"),
            }),
            SecretPurpose::SignVersion(VersionChange::UpdateSchema {
                namespace: name("/home/bob"),
            }),
            SecretPurpose::MoveRoot,
            SecretPurpose::SealRoot,
            SecretPurpose::CreateKit {
                namespace: name("/home/bob"),
            },
            SecretPurpose::SealKit,
            SecretPurpose::CheckKit {
                namespace: name("/home/bob"),
            },
            SecretPurpose::Recover {
                namespace: name("/home/bob"),
            },
        ];
        for kind in [
            SecretKind::RootPassphrase,
            SecretKind::RootPin,
            SecretKind::KitPassphrase,
            SecretKind::KitPin,
            SecretKind::KitWords,
        ] {
            for purpose in &purposes {
                let request = SecretRequest {
                    kind,
                    purpose: purpose.clone(),
                    confirm: false,
                };
                assert_clean("secret prompt", &secret_prompt(&request));
            }
        }
    }

    /// A link detail's causes are worded in place, under a parent this
    /// table words and under one it does not know.
    #[test]
    fn link_causes_are_worded_in_place() {
        let cause = LinkDetail::new(link_code::LINK_TLS, "the TLS handshake failed: bad record")
            .with("error", "bad record");
        let cause_words = phrase(link_code::LINK_TLS, &cause.params, &[]).unwrap();

        let mut known =
            LinkDetail::new(link_code::DIAL_FAILED, "the last dial failed:").with("retry_secs", 30);
        known.append(" ", cause.clone());
        assert!(link_detail(&known).contains(&cause_words));

        let mut newer = LinkDetail::new("some-newer-code", "Something new happened:");
        newer.append(" ", cause);
        let shown = link_detail(&newer);
        assert!(shown.contains(&cause_words) && shown.contains("Something new happened"));
    }

    /// A refusal wrapping a cause, or carrying a token denial, words it in
    /// place; an unknown code shows its neutral sentence.
    #[test]
    fn causes_and_denials_are_worded_and_unknown_codes_fall_back() {
        let denied = TrustRefusal::new(code::INVITE_REFUSED, "neutral")
            .with("error", TokenDenial::Expired.reason("the invite expired"));
        let denial_words = phrase("invite-expired", &Params::new(), &[]).unwrap();
        assert!(refusal(&denied).contains(&denial_words));

        let cause: Params = [("budget_secs".to_owned(), "8".to_owned())]
            .into_iter()
            .collect();
        let wrapped = TrustRefusal::new(code::ALREADY_CERTIFIED, "neutral")
            .with("namespace", "/home/bob")
            .with("judged_version", 3)
            .with_cause("context-check-timed-out", &cause);
        let cause_words = phrase("context-check-timed-out", &wrapped.params, &[]).unwrap();
        assert!(refusal(&wrapped).contains(&cause_words));

        let newer = TrustRefusal::new(
            RefusalCode::new("some-newer-code", 400, false, NextStep::Other),
            "the neutral sentence",
        );
        assert_eq!(refusal(&newer), "the neutral sentence");
        let detail_newer = Detail::new("some-newer-detail", "the neutral text");
        assert_eq!(detail(&detail_newer), "the neutral text");
    }
}
