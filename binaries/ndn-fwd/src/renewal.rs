//! Renewing this node's certificates before they expire: `ndn-fwd renew`
//! (the `security/renew` management verb) and the renewal timer (`[security]
//! renew_before`).
//!
//! Every certificate a namespace CA issued to a device key in this node's PIB
//! (`keys/*/certs/`, what `ndn-fwd enroll` stores) is renewed at its
//! namespace's CA with [`ndn_identity::renew_via_engine`]: the CA re-certifies
//! the same key on proof of the current certificate, with no invite
//! ([`ndn_cert::renewal`]). The renewal carries the certificate's issuer
//! chain (walked from what this node kept, [`ndn_cert::issuers`]), so a later
//! CA of the namespace — after its root device was replaced through a
//! recovery kit — renews a certificate the earlier CA issued. The new
//! certificate has a new name (`<key>/NDNCERT/<version>`); it is stored in
//! the PIB beside the old one (kept until it expires), its issuer chain is
//! kept, it is cached for validation and served
//! ([`crate::own_certs::OwnCertificates`]). The node keeps signing with the
//! same key and KeyLocator (the key name), which verifiers resolve to the
//! newest valid certificate, so nothing else changes.
//!
//! The timer renews a certificate once its remaining validity falls below
//! `renew_before` (a third of its lifetime by default). A duration at least
//! the lifetime of the certificates the CA issues would make each one due as
//! it is issued: those are renewed once a third of their lifetime is left,
//! with a WARN, once. A key is not renewed again before the certificate its
//! last renewal issued is due. A failed attempt is retried after a growing,
//! jittered backoff (30–60 s, doubling up to 30–60 min; 30–60 min after a
//! refusal) and logged as a WARN with the days the certificate has left; a
//! PIB the daemon cannot read is logged as a WARN and retried likewise. A
//! certificate that expired, a key the CA revoked and a role it does not
//! renew (guest, by default) cannot be renewed: the device needs a new
//! invite. An expired one is reported once, as an ERROR.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ndn_cert::roles::parse_device_key;
use ndn_config::RenewBeforeConfig;
use ndn_identity::RenewBefore;
use ndn_mgmt::{RenewalInfo, RenewalState, TrustRefusal};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib};
use tokio_util::sync::CancellationToken;

use crate::context_adopt::{TrustAdmin, refusal};
use crate::enroll::iso;

/// The first scan runs this soon after start, once faces and routes are up.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(10);
/// The longest the timer sleeps between scans (it also wakes on an
/// enrollment or a renewal).
const MAX_WAIT: Duration = Duration::from_secs(3_600);
const MIN_WAIT: Duration = Duration::from_secs(1);
/// Backoff base after a failed attempt.
const RETRY_BASE: Duration = Duration::from_secs(60);
/// Backoff exponent after a refusal: the cap (an hour).
const REFUSED_BACKOFF: u32 = 6;

/// A certificate a namespace CA issued to one of this node's keys.
struct Held {
    key: Name,
    data: Data,
    cert: Certificate,
}

/// The certificates the PIB stores for device keys `/<ns>/<role>/<device>`
/// of a namespace whose trust context this node holds, issued by a CA
/// (`/<prefix>/CA/KEY/…`); none when there is no PIB yet. Err: the PIB
/// cannot be read (why, with its path).
fn held_certificates(admin: &TrustAdmin) -> Result<Vec<Held>, String> {
    let unreadable = |e: ndn_security::PibError| {
        format!("cannot read the PIB {}: {e}", admin.pib_root.display())
    };
    let pib = match FilePib::open(&admin.pib_root) {
        Ok(pib) => pib,
        Err(ndn_security::PibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(unreadable(e)),
    };
    let namespaces: Vec<Name> = admin
        .keyring
        .contexts()
        .iter()
        .map(|c| c.namespace().clone())
        .collect();
    let mut held = Vec::new();
    for key in pib.list_keys().map_err(unreadable)? {
        if !namespaces.iter().any(|ns| parse_device_key(ns, &key).is_some()) {
            continue;
        }
        let Some(wire) = pib.get_issued_cert(&key).map_err(unreadable)? else {
            continue;
        };
        let decoded = Data::decode(wire)
            .map_err(|e| e.to_string())
            .and_then(|data| Certificate::decode(&data).map(|cert| (data, cert)).map_err(|e| e.to_string()));
        let (data, cert) = match decoded {
            Ok(decoded) => decoded,
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    key = %key,
                    pib = %admin.pib_root.display(),
                    error = %e,
                    "the stored certificate of this key does not decode; it is not renewed"
                );
                continue;
            }
        };
        if ndn_cert::issuing_ca_prefix(&cert).is_some() {
            held.push(Held { key, data, cert });
        }
    }
    Ok(held)
}

/// Renew `held` and keep the new certificate: PIB, validation cache,
/// served by name. The failure's state says whether retrying can help.
async fn renew_one(admin: &TrustAdmin, held: &Held) -> Result<Certificate, (RenewalState, String)> {
    let failed = |why: String| (RenewalState::Failed, why);
    if admin.keyring.context_for(&held.cert.name).is_revoked(&held.cert.name) {
        return Err((
            RenewalState::Refused,
            format!(
                "the trust context of its namespace revokes {}; a revoked key is never renewed: \
                 enroll a new key with a new invite",
                held.key
            ),
        ));
    }
    let pib = FilePib::open(&admin.pib_root)
        .map_err(|e| failed(format!("cannot open the PIB {}: {e}", admin.pib_root.display())))?;
    let signer = pib
        .get_signer(&held.key)
        .map_err(|e| failed(format!("the key {} cannot sign: {e}", held.key)))?;
    // The issuer certificates kept in `<pib>/issuers/` answer the walk of the
    // current certificate's chain first: after a recovery nobody else may serve
    // the earlier CA's certificate.
    let kept: Vec<Data> = ndn_cert::issuers::stored_issuer_certs(&admin.pib_root)
        .into_iter()
        .filter_map(|wire| Data::decode(wire).ok())
        .collect();
    let issued =
        ndn_identity::renew_via_engine(&admin.engine, &admin.keyring, &held.data, &kept, signer)
            .await
            .map_err(|e| {
                let state = if e.is_final() {
                    RenewalState::Refused
                } else {
                    RenewalState::Failed
                };
                (state, e.to_string())
            })?;
    pib.store_issued_cert(&held.key, issued.data.raw()).map_err(|e| {
        failed(format!(
            "the CA issued {}, but storing it in {} failed ({e}); the current certificate stays \
             in use until it expires",
            issued.cert.name,
            admin.pib_root.display()
        ))
    })?;
    // The new certificate's issuer chain, kept and served as at enrollment.
    if let Err(e) = ndn_cert::issuers::keep_issuer_certs(&admin.pib_root, &issued.issuers) {
        tracing::warn!(
            target: "security",
            error = %e,
            "renewed, but the issuer certificates of its chain were not kept"
        );
    }
    if let Some(mgr) = admin.engine.security() {
        mgr.cert_cache().insert(issued.cert.clone());
    }
    if let Some(own) = &admin.own_certs {
        own.serve(issued.data.raw().clone());
        for issuer in &issued.issuers {
            own.serve(issuer.raw().clone());
        }
    }
    admin.certificates_changed.notify_one();
    tracing::info!(
        target: "security",
        key = %held.key,
        previous = %held.cert.name,
        certificate = %issued.cert.name,
        valid_until = %iso(issued.cert.valid_until),
        "certificate renewed (same key); stored, served and signing with it"
    );
    Ok(issued.cert)
}

fn info(held: &Held, result: &Result<Certificate, (RenewalState, String)>) -> RenewalInfo {
    let mut info = RenewalInfo {
        key: held.key.to_string(),
        state: RenewalState::Renewed,
        previous: held.cert.name.to_string(),
        previous_valid_until: iso(held.cert.valid_until),
        certificate: None,
        valid_until: None,
        validity_secs: None,
        detail: String::new(),
    };
    match result {
        Ok(cert) => {
            info.certificate = Some(cert.name.to_string());
            info.valid_until = Some(iso(cert.valid_until));
            info.validity_secs =
                Some(cert.valid_until.saturating_sub(cert.valid_from) / 1_000_000_000);
        }
        Err((state, detail)) => {
            info.state = *state;
            info.detail = detail.clone();
        }
    }
    info
}

/// `security/renew`: renew every certificate a namespace CA issued to this
/// node's keys now, whatever their remaining validity.
pub(crate) async fn renew_now(admin: &TrustAdmin) -> Result<Vec<RenewalInfo>, TrustRefusal> {
    let _one_at_a_time = admin.renewing.lock().await;
    let held = held_certificates(admin).map_err(|why| {
        refusal(
            500,
            format!("{why}: nothing was renewed. Make the PIB readable by this daemon, then renew again"),
        )
    })?;
    if held.is_empty() {
        return Err(refusal(
            404,
            format!(
                "this node holds no certificate a namespace CA issued to it in {}: nothing to \
                 renew. Enroll first (`ndn-fwd enroll <invite>`)",
                admin.pib_root.display()
            ),
        ));
    }
    let mut out = Vec::with_capacity(held.len());
    for h in &held {
        let result = renew_one(admin, h).await;
        if let Err((_, why)) = &result {
            tracing::warn!(target: "security", key = %h.key, error = %why, "certificate not renewed");
        }
        out.push(info(h, &result));
    }
    Ok(out)
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Renew each held certificate once its remaining validity falls below
/// `renew_before`, until `cancel`. `Off`: never (only `ndn-fwd renew`).
pub(crate) fn spawn_periodic(
    admin: std::sync::Arc<TrustAdmin>,
    renew_before: RenewBeforeConfig,
    cancel: CancellationToken,
) {
    let before = match renew_before {
        RenewBeforeConfig::Off => {
            tracing::info!(
                target: "security",
                "[security] renew_before = 0: certificates are renewed only by `ndn-fwd renew`"
            );
            return;
        }
        RenewBeforeConfig::Fraction(f) => RenewBefore::Fraction(f),
        RenewBeforeConfig::Before(d) => RenewBefore::Remaining(d),
    };
    tracing::info!(target: "security", renew_before = ?before, "renewing certificates before they expire");
    tokio::spawn(async move {
        // Per certificate: consecutive failures and when to try again.
        let mut retry: HashMap<Name, (u32, Instant)> = HashMap::new();
        // Per key: when the certificate its last renewal issued is due. The
        // key is not renewed again before then, whichever certificate the
        // PIB reports as its current one.
        let mut renewed: HashMap<Name, u64> = HashMap::new();
        // Expired certificates, reported once.
        let mut expired: HashSet<Name> = HashSet::new();
        // Keys whose certificates are shorter than `renew_before`, reported once.
        let mut short_lived: HashSet<Name> = HashSet::new();
        // Consecutive scans that could not read the PIB.
        let mut unreadable: u32 = 0;
        let mut wait = FIRST_CHECK_AFTER;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
                _ = admin.certificates_changed.notified() => {}
            }
            let held = match held_certificates(&admin) {
                Ok(held) => {
                    unreadable = 0;
                    held
                }
                Err(why) => {
                    unreadable += 1;
                    wait = ndn_identity::backoff_delay(RETRY_BASE, unreadable - 1);
                    tracing::warn!(
                        target: "security",
                        error = %why,
                        retry_in_secs = wait.as_secs(),
                        "no certificate is renewed while the PIB cannot be read; they expire unless \
                         it becomes readable"
                    );
                    continue;
                }
            };
            retry.retain(|name, _| held.iter().any(|h| *h.cert.name == *name));
            renewed.retain(|key, _| held.iter().any(|h| h.key == *key));
            let mut next = MAX_WAIT;
            for h in &held {
                let name = (*h.cert.name).clone();
                let now = now_ns();
                if before.exceeds_lifetime(h.cert.valid_from, h.cert.valid_until)
                    && short_lived.insert(h.key.clone())
                {
                    tracing::warn!(
                        target: "security",
                        key = %h.key,
                        certificate = %name,
                        validity_days = (h.cert.valid_until.saturating_sub(h.cert.valid_from)) / 86_400_000_000_000,
                        renew_before = ?before,
                        "[security] renew_before is at least the lifetime of the certificates this \
                         CA issues; renewing them once a third of their lifetime is left instead"
                    );
                }
                let due_at = before
                    .renew_at(h.cert.valid_from, h.cert.valid_until)
                    .max(renewed.get(&h.key).copied().unwrap_or(0));
                if now < due_at {
                    next = next.min(Duration::from_nanos(due_at - now));
                    continue;
                }
                if expired.contains(&name) {
                    continue;
                }
                if let Some((_, at)) = retry.get(&name) {
                    let left = at.saturating_duration_since(Instant::now());
                    if !left.is_zero() {
                        next = next.min(left);
                        continue;
                    }
                }
                let result = {
                    let _one_at_a_time = admin.renewing.lock().await;
                    renew_one(&admin, h).await
                };
                let (state, why) = match result {
                    Ok(issued) => {
                        retry.remove(&name);
                        renewed.insert(h.key.clone(), before.renew_at(issued.valid_from, issued.valid_until));
                        continue;
                    }
                    Err(failure) => failure,
                };
                let days_left = (h.cert.valid_until as f64 - now_ns() as f64) / 86_400e9;
                if days_left <= 0.0 {
                    tracing::error!(
                        target: "security",
                        key = %h.key,
                        certificate = %name,
                        expired_at = %iso(h.cert.valid_until),
                        "certificate expired and was not renewed in time: renewal needs a \
                         current certificate, so this device needs a new invite to enroll again"
                    );
                    expired.insert(name);
                    continue;
                }
                let failures = retry.get(&name).map_or(0, |(n, _)| *n) + 1;
                let exponent = if state == RenewalState::Refused {
                    REFUSED_BACKOFF
                } else {
                    failures - 1
                };
                let delay = ndn_identity::backoff_delay(RETRY_BASE, exponent);
                tracing::warn!(
                    target: "security",
                    key = %h.key,
                    certificate = %name,
                    days_left = %format!("{days_left:.1}"),
                    valid_until = %iso(h.cert.valid_until),
                    attempts = failures,
                    retry_in_secs = delay.as_secs(),
                    error = %why,
                    "certificate renewal failed; the certificate works until it expires"
                );
                retry.insert(name, (failures, Instant::now() + delay));
                next = next.min(delay);
            }
            wait = next.clamp(MIN_WAIT, MAX_WAIT);
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::enroll::tests::{node, request};

    /// The certificate the PIB at `pib` stores for `key`.
    fn stored(pib: &std::path::Path, key: &Name) -> Certificate {
        let pib = FilePib::open(pib).unwrap();
        let wire = pib.get_issued_cert(key).unwrap().unwrap();
        Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
    }

    /// `ndn-fwd renew` on an enrolled node: the same key gets a new
    /// certificate, under a new name, from the CA without a token; the PIB
    /// stores it beside the old one, and the node keeps signing with that key.
    #[tokio::test]
    async fn renew_keeps_the_key_and_stores_the_new_certificate() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = enrolled.key.parse().unwrap();
        let (signing_before, _) = node.admin.signing.as_ref().unwrap().current();
        let before = stored(device.path(), &key);
        // Validity periods are stored to the second.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let results = renew_now(&node.admin).await.expect("a node holding a certificate renews");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.state, RenewalState::Renewed, "{}", r.detail);
        assert_eq!(r.key, enrolled.key);

        let after = stored(device.path(), &key);
        assert!(after.valid_until > before.valid_until, "the PIB holds the new certificate");
        assert_eq!(after.public_key, before.public_key, "for the same key");
        assert_ne!(after.name, before.name, "a renewed certificate has its own name");
        let pib = FilePib::open(device.path()).unwrap();
        assert_eq!(pib.valid_cert_wires(&key).unwrap().len(), 2, "the old one is kept until it expires");
        assert_eq!(pib.list_keys().unwrap(), vec![key.clone()], "no new key");
        let (signing_after, _) = node.admin.signing.as_ref().unwrap().current();
        assert_eq!(signing_after, signing_before, "the node keeps signing with the same key");
        node.shutdown.shutdown().await;
    }

    /// A key the root device revoked at its CA is refused, the stored
    /// certificate stays as it was, and a node with nothing to renew says so.
    #[tokio::test]
    async fn a_revoked_key_is_refused_and_nothing_changes() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        assert_eq!(renew_now(&node.admin).await.unwrap_err().status_code, 404);

        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = enrolled.key.parse().unwrap();
        let before = stored(device.path(), &key);
        node.ca.revoke_issued_under(&key);

        let results = renew_now(&node.admin).await.unwrap();
        assert_eq!(results[0].state, RenewalState::Refused, "{:?}", results[0]);
        let after = stored(device.path(), &key);
        assert_eq!(after.valid_until, before.valid_until, "the stored certificate is kept");
        node.shutdown.shutdown().await;
    }

    /// The renewal timer renews a certificate that is due, without being
    /// asked.
    #[tokio::test]
    async fn the_timer_renews_a_due_certificate() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = enrolled.key.parse().unwrap();
        let before = stored(device.path(), &key);
        let crate::enroll::tests::Node {
            admin, shutdown, ..
        } = node;
        let admin = Arc::new(admin);
        // Validity periods are stored to the second.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        // Due at once: renew while nearly the whole lifetime is left.
        let cancel = CancellationToken::new();
        spawn_periodic(
            Arc::clone(&admin),
            RenewBeforeConfig::Fraction(0.999_999),
            cancel.clone(),
        );
        admin.certificates_changed.notify_one();
        let renewed = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let now = stored(device.path(), &key);
                if now.valid_until > before.valid_until {
                    return now;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the timer renews the due certificate");
        assert_eq!(renewed.public_key, before.public_key, "for the same key");
        cancel.cancel();
        shutdown.shutdown().await;
    }

    /// A `renew_before` longer than the lifetime the CA issues never makes
    /// the timer renew in a loop (each new certificate due as it is issued).
    #[tokio::test]
    async fn renew_before_longer_than_the_lifetime_does_not_renew_in_a_loop() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = enrolled.key.parse().unwrap();
        let lifetime = Duration::from_secs(enrolled.validity_secs);
        let crate::enroll::tests::Node {
            admin, shutdown, ..
        } = node;
        let admin = Arc::new(admin);
        let cancel = CancellationToken::new();
        spawn_periodic(
            Arc::clone(&admin),
            RenewBeforeConfig::Before(lifetime + Duration::from_secs(86_400)),
            cancel.clone(),
        );
        admin.certificates_changed.notify_one();
        tokio::time::sleep(Duration::from_secs(4)).await;
        let pib = FilePib::open(device.path()).unwrap();
        assert!(pib.valid_cert_wires(&key).unwrap().len() <= 2, "renewed at most once");
        cancel.cancel();
        shutdown.shutdown().await;
    }

    /// A PIB the daemon cannot read is refused as unreadable, not as a node
    /// holding nothing (whose advice, enrolling again, would burn an invite).
    #[tokio::test]
    async fn an_unreadable_pib_is_not_reported_as_holding_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        crate::enroll::enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
            .await
            .expect("enrolls");
        let keys = device.path().join("keys");
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Permissions bind only an unprivileged user.
        let enforced = std::fs::read_dir(&keys).is_err();
        let refused = renew_now(&node.admin).await;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        if enforced {
            assert_ne!(refused.unwrap_err().status_code, 404);
        }
        node.shutdown.shutdown().await;
    }
}
