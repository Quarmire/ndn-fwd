//! `ndn-fwd schema show|explain|update` — inspect the trust schema of the
//! contexts the node adopted (`<pib>/contexts/`, verified on load exactly as
//! the daemon loads them), and bring a namespace's schema up to date on its
//! root device. Early-exit subcommand like `init`/`adopt`.
//!
//! - `show [--namespace <ns>]` prints the context and each schema blob as
//!   readable rules: an LVS binary decoded back to LVS source (rule names
//!   included for schemas compiled in-tree), native-text rules verbatim.
//! - `explain <data-name> <key-name> [--namespace <ns>]` answers whether the
//!   context governing `<data-name>` lets `<key-name>` sign it, and which rule
//!   decides. Exit status 0 = allow, 1 = deny.
//! - `update [--namespace <ns>] [--accept-narrowing]` (root device only)
//!   signs version `N+1` of the namespace's trust context carrying the
//!   current generated schema ([`ndn_cert::namespace_schema`]) and the
//!   enrollment hint of the policy the namespace's CA enforces
//!   ([`ndn_cert::bump_context_schema`]), and hands it to the daemon as
//!   `ndn-fwd revoke` does. A namespace made by an earlier release gets the
//!   rules added since (the `#deny` and `#pending` rules of enrollment by
//!   approval) this way, without being initialized again. The hint: the
//!   held version's own when it advertises a policy (the CA enforces exactly
//!   that); a context made before the hint carried the policy gets the one
//!   its CA enforces for it — `[ca] approval_roles` /
//!   `approval_requires_invite` of `-c`, else the default — so the CA and
//!   the devices agree. A running CA validates admins' decisions and pending
//!   listings under the version its daemon holds now, so it applies the new
//!   rules as soon as its daemon adopts the update, with no restart; its
//!   policy does not change, since the hint states the policy it enforces.
//!
//! **An explicit verb**, not something every root-signed version does: a
//! revocation or a recovery kit (`ndn-fwd revoke`, `ndn-fwd recovery-kit`)
//! carries the schema over verbatim, because revoking a key must not change
//! what the other devices may sign as a side effect. A schema update is the
//! one action that does, and the operator sees which rules it adds and
//! removes before the root signs it. It never narrows silently: when a rule
//! of the held schema is missing from the new one — a custom schema, or the
//! key-name schema of the earliest releases — it is refused, naming the
//! rules devices would lose, unless `--accept-narrowing` is given.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_cert::{RootStore, SchemaUpdatePlan, load_persisted_contexts};
use ndn_config::{CaTomlConfig, ForwarderConfig};
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, Keyring, LvsModel, SchemaFormat, SignedTrustContext};

use crate::onboard::{flag, pib_dir, positionals};
use crate::recovery_kit::{NotTaken, hand_over, root_device};

const USAGE: &str = "usage: ndn-fwd schema show [-c <config>] [--pib <dir>] [--namespace <ns>]\n       \
     ndn-fwd schema explain <data-name> <key-name> [-c <config>] [--pib <dir>] \
     [--namespace <ns>]\n       \
     ndn-fwd schema update [--namespace <ns>] [--accept-narrowing] [-c <config>] [--pib <dir>]";

pub(crate) async fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("show") => show(&args[1..]),
        Some("explain") => explain(&args[1..]),
        Some("update") => update(&args[1..]).await,
        _ => bail!("{USAGE}"),
    }
}

/// Every adopted context in the PIB's store, in a keyring. Contexts that fail
/// to verify are reported and skipped, as the daemon does.
fn load(pib: &Path) -> Result<Keyring> {
    let keyring = Keyring::new();
    let loaded = load_persisted_contexts(pib, &keyring)
        .with_context(|| format!("read adopted contexts in {}", pib.display()))?;
    for (path, result) in &loaded {
        if let Err(e) = result {
            eprintln!("warning: skipping {}: {e}", path.display());
        }
    }
    if keyring.is_empty() {
        bail!(
            "no adopted trust context in {}/contexts (run `ndn-fwd init --namespace <ns>` or \
             `ndn-fwd adopt <envelope>`)",
            pib.display()
        );
    }
    Ok(keyring)
}

fn parse_name(raw: &str, what: &str) -> Result<Name> {
    raw.parse()
        .map_err(|e| anyhow::anyhow!("invalid {what} {raw:?}: {e}"))
}

/// The context named by `--namespace`, else the only adopted one.
fn select(keyring: &Keyring, args: &[String]) -> Result<Arc<SignedTrustContext>> {
    let contexts = keyring.contexts();
    if let Some(ns) = flag(args, &["--namespace"]) {
        let ns = parse_name(ns, "--namespace")?;
        return contexts
            .into_iter()
            .find(|c| c.namespace() == &ns)
            .with_context(|| format!("no adopted trust context for {ns}"));
    }
    match contexts.as_slice() {
        [one] => Ok(Arc::clone(one)),
        many => bail!(
            "{} adopted contexts ({}); pick one with --namespace",
            many.len(),
            many.iter()
                .map(|c| c.namespace().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn show(args: &[String]) -> Result<()> {
    let pib = pib_dir(args)?;
    let ctx = select(&load(&pib)?, args)?;
    println!("# trust context {} v{}", ctx.namespace(), ctx.version());
    let anchors: Vec<String> = ctx.anchors().iter().map(|r| r.key().to_string()).collect();
    println!("anchors        = {}", anchors.join(", "));
    let cas: Vec<String> = ctx.ca_endpoints().iter().map(Name::to_string).collect();
    println!("ca_endpoints   = {}", cas.join(", "));
    println!("link_policy    = {}", ctx.link_policy().describe());
    if ctx.relays().is_empty() {
        println!("relays         = none advertised");
    }
    for relay in ctx.relays() {
        println!("relay          = {relay}");
    }
    println!(
        "evaluation     = {}",
        if ctx.schema_is_authoritative() {
            "schema only, on every certificate hop (authoritative)"
        } else if ctx.enforces_hierarchy() {
            "schema AND hierarchy floor (signer identity must prefix the name), first signature"
        } else {
            "schema only, first signature"
        }
    );
    for (i, blob) in ctx.published_schemas().iter().enumerate() {
        println!();
        match blob.format {
            SchemaFormat::Lvs => {
                let model = LvsModel::decode(&blob.body)
                    .map_err(|e| anyhow::anyhow!("schema blob {i}: {e}"))?;
                println!(
                    "# schema blob {i}: LVS binary ({} bytes), decoded to LVS source",
                    blob.body.len()
                );
                print!("{}", model.to_text());
            }
            SchemaFormat::NativeText => {
                println!("# schema blob {i}: native rules (data => key), OR'd with the others");
                let text = std::str::from_utf8(&blob.body)
                    .with_context(|| format!("schema blob {i} is not UTF-8"))?;
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    println!("{}", line.trim());
                }
            }
            SchemaFormat::Unknown(code) => println!(
                "# schema blob {i}: format {code} ({} bytes), not understood by this node: it \
                 authorizes nothing here and is carried into the next version unchanged",
                blob.body.len()
            ),
        }
    }
    Ok(())
}

fn explain(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let [data, key] = positional.as_slice() else {
        bail!(
            "usage: ndn-fwd schema explain <data-name> <key-name> [-c <config>] [--pib <dir>] \
             [--namespace <ns>]"
        );
    };
    let data = parse_name(data, "data name")?;
    let key = parse_name(key, "key name")?;
    let pib = pib_dir(args)?;
    let keyring = load(&pib)?;
    let ctx = if flag(args, &["--namespace"]).is_some() {
        select(&keyring, args)?
    } else {
        let ctx = keyring.context_for(&data);
        if Arc::ptr_eq(&ctx, keyring.ambient()) {
            bail!("no adopted trust context governs {data}");
        }
        ctx
    };

    let why = ctx.explain(&data, &key);
    println!("data           = {data}");
    println!("key            = {key}");
    println!("context        = {} v{}", ctx.namespace(), ctx.version());
    println!(
        "floor          = {}",
        match why.hierarchy_floor {
            None => "not enforced",
            Some(true) => "passes",
            Some(false) => "FAILS (the key's identity is not a prefix of the data name)",
        }
    );
    println!(
        "rule           = {}",
        why.rule.as_deref().unwrap_or("none matches")
    );
    let allowed = why.allowed();
    println!(
        "verdict        = {}",
        if allowed { "allow" } else { "deny" }
    );
    if !allowed {
        std::process::exit(1);
    }
    Ok(())
}

/// What `ndn-fwd schema update` signs, decided before the root is unlocked.
struct UpdatePlan {
    store: RootStore,
    held: SignedTrustContext,
    held_data: Data,
    /// The schema, enrollment policy and hint, and link policy of the next
    /// version, and what they change ([`ndn_cert::plan_schema_update`]).
    update: SchemaUpdatePlan,
}

/// The `[ca]` / `[[ca]]` entry of `-c` for the CA of `namespace`
/// ([`crate::ca::config_for`]), else the defaults (no stated policy).
fn ca_config(args: &[String], namespace: &Name) -> Result<CaTomlConfig> {
    let Some(path) = flag(args, &["-c", "--config"]) else {
        return Ok(CaTomlConfig::default());
    };
    let toml = std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    let cfg: ForwarderConfig = toml
        .parse()
        .with_context(|| format!("parse config {path}"))?;
    Ok(crate::ca::config_for(&cfg.ca, namespace)
        .cloned()
        .unwrap_or_default())
}

/// Every check that needs no key: this PIB is the root device of the
/// namespace (`--namespace` names it; needed when the PIB holds several
/// roots), and the update does not narrow what devices may do unless
/// `--accept-narrowing`. The enrollment hint is the held version's own when
/// it advertises a policy (refused, as the CA's start refuses, when the
/// namespace's `[ca]` entry of `-c` states another), else the policy the
/// CA enforces for it; the link policy is that entry's when it differs from
/// the held one ([`ndn_cert::plan_schema_update`]).
fn plan_update(pib_dir: &Path, args: &[String]) -> Result<UpdatePlan> {
    let pib =
        FilePib::open(pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    let (store, held, held_data) = root_device(&pib, args, "a namespace's schema is updated")?;
    let stated =
        crate::ca::policy_input(&ca_config(args, held.namespace()).context("nothing was signed")?)
            .context("nothing was signed")?;
    let accept_narrowing = args.iter().any(|a| a == "--accept-narrowing");
    let update = ndn_cert::plan_schema_update(&held, &stated, accept_narrowing)?;
    Ok(UpdatePlan {
        store,
        held,
        held_data,
        update,
    })
}

/// `<key> = <count>` and one `  <mark> <rule>` line per rule, or `= none`.
fn print_rules(key: &str, rules: &[String], mark: char) {
    if rules.is_empty() {
        println!("{key:<15}= none");
        return;
    }
    println!("{key:<15}= {}", rules.len());
    for rule in rules {
        println!("  {mark} {rule}");
    }
}

/// `<key> = none advertised`, or one `  <relay>` line per relay.
fn print_relays(key: &str, relays: &[ndn_security::AdvertisedRelay]) {
    if relays.is_empty() {
        println!("{key:<15}= none advertised");
        return;
    }
    println!("{key:<15}= {}", relays.len());
    for relay in relays {
        println!("    {relay}");
    }
}

/// `ndn-fwd schema update`.
async fn update(args: &[String]) -> Result<()> {
    let pib_dir = pib_dir(args)?;
    let UpdatePlan {
        store,
        held,
        held_data,
        update:
            SchemaUpdatePlan {
                schema,
                policy,
                hint,
                link,
                relays,
                change,
            },
    } = plan_update(&pib_dir, args)?;
    let namespace = held.namespace().clone();
    if change.is_empty() {
        println!("# ndn-fwd schema update");
        println!("namespace      = {namespace}");
        println!(
            "trust_context  = v{} (carries the current schema, enrollment hint, link policy and \
             relays already; nothing signed)",
            held.version()
        );
        println!("enrollment     = {}", policy.describe());
        println!("link_policy    = {}", change.link.describe());
        print_relays("relays", &change.relays);
        return Ok(());
    }
    crate::revoke::check_daemon(args, &pib_dir).await?;

    let unlock = crate::root_key::operator_secret(
        args,
        store.unlock_kind(),
        &format!("Updating the schema of {namespace} signs a new trust context version"),
        false,
    )?;
    let root = store
        .signer(unlock.as_ref())
        .await
        .context("the root did not unlock; nothing was signed")?;
    drop(unlock);
    let accept_narrowing = args.iter().any(|a| a == "--accept-narrowing");
    let signed = ndn_cert::bump_context_schema(
        root.as_ref(),
        &held_data,
        &schema,
        &hint,
        link.as_ref(),
        relays.as_deref(),
        accept_narrowing,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}. Nothing was signed"))?
    .context(
        "the held trust context carries this schema, enrollment hint, link policy and relays \
         already; nothing was signed",
    )?;
    drop(root);
    let version = signed.bump.context.version();
    let handed = hand_over(args, &pib_dir, &signed.bump)
        .await
        .map_err(|not| match not {
            NotTaken::Refused(e) => e.context(format!(
                "nothing changed: the trust context of {namespace} stays v{} with its schema",
                held.version()
            )),
            NotTaken::Unknown(e) => e.context(format!(
                "whether the daemon adopted v{version} (the schema update) is not known: once the \
                 daemon is idle, run `ndn-fwd schema update --pib {}` again with the same flags — \
                 it reports nothing to change if the daemon took v{version}, and signs the \
                 version again if not",
                pib_dir.display()
            )),
        })?;

    let change = &signed.change;
    println!("# ndn-fwd schema update");
    println!("namespace      = {namespace}");
    println!(
        "trust_context  = v{} -> v{version} (signed by the root {})",
        held.version(),
        store.key_name()
    );
    print_rules("rules_added", &change.added, '+');
    if change.removed.is_empty() {
        println!(
            "narrowed       = none (every rule of v{} is kept)",
            held.version()
        );
    } else {
        print_rules("rules_removed", &change.removed, '-');
        println!(
            "narrowed       = yes (--accept-narrowing): a device relying on a removed rule is \
             refused once its node holds v{version}"
        );
    }
    if change.becomes_authoritative {
        println!(
            "evaluation     = schema only, on every certificate hop (authoritative; v{} also \
             required the hierarchy floor)",
            held.version()
        );
    }
    println!("enrollment     = {}", policy.describe());
    if change.changes_link() {
        println!(
            "link_policy    = {} -> {}",
            change.link_before.describe(),
            change.link.describe()
        );
        if !change.link_narrowed.is_empty() {
            print_rules("link_narrowed", &change.link_narrowed, '-');
            println!(
                "                 (--accept-narrowing: a device relying on it loses its links once \
                 its node holds v{version})"
            );
        }
    } else {
        println!("link_policy    = {} (unchanged)", change.link.describe());
    }
    if change.changes_relays() {
        print_relays("relays_before", &change.relays_before);
        print_relays("relays", &change.relays);
        if !change.relays_dropped.is_empty() {
            print_rules("relays_dropped", &change.relays_dropped, '-');
            println!(
                "                 (--accept-narrowing: a device using it loses that relay once it \
                 holds v{version})"
            );
        }
    } else if !change.relays.is_empty() {
        println!(
            "relays         = {} advertised (unchanged)",
            change.relays.len()
        );
    }
    println!("handed_over    = {handed}");
    println!();
    if change.changes_hint() {
        println!("# The trust context now states the enrollment policy the CA of {namespace}");
        println!("# enforces ([ca] approval_roles / approval_requires_invite of -c, else the");
        println!("# default), so devices ask for what the CA requires.");
    }
    println!("# The CA of {namespace} validates admins' decisions and pending listings");
    println!("# under v{version} as soon as its daemon holds it (no restart). Every other");
    println!("# node judges by v{version} once it holds it: at its next refresh ([security]");
    println!("# context_refresh_secs, default 300 s), or at once with `ndn-fwd context refresh`.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use ndn_cert::{
        ApprovalPolicy, ApprovalPoll, ApprovalRecord, ApproverError, Decision, RefusalKind,
        namespace_schema,
    };
    use ndn_mgmt::EnrollOutcome;
    use ndn_packet::encode::DataBuilder;
    use ndn_security::{
        CertCache, Certificate, Ed25519Signer, EnrollmentHint, SchemaBlob, Signer,
        ValidationResult, Validator,
    };

    use super::*;
    use crate::context_adopt::{TrustAdmin, TrustAdminParts};
    use crate::enroll::tests::{Node, node, request};

    fn ns() -> Name {
        "/home/bob".parse().unwrap()
    }

    /// The generated schema an earlier `ndn-fwd init` wrote — today's
    /// without the `#deny` and `#pending` rules, as that generator produced
    /// it — and the hint of that time (no approval roles named).
    fn old_generated_schema() -> (Vec<SchemaBlob>, EnrollmentHint) {
        let schema = namespace_schema(&ns()).unwrap();
        let lvs: String = schema
            .lvs_source
            .lines()
            .filter(|l| !l.starts_with("#deny:") && !l.starts_with("#pending:"))
            .map(|l| format!("{l}\n"))
            .collect();
        let blobs = vec![
            SchemaBlob::lvs(ndn_security::compile_lvs_to_binary(&lvs).unwrap()),
            SchemaBlob::native_text(schema.native_rules),
        ];
        let hint = EnrollmentHint {
            challenges: vec!["token".into(), "device-approval".into()],
            require_all: true,
            approval_roles: Vec::new(),
        };
        (blobs, hint)
    }

    /// The root device's daemon: its trust admin over the keyring its
    /// running CA validates decisions and listings under, holding the
    /// contexts stored in `root_dev`.
    fn root_daemon(node: &Node, root_dev: &Path) -> TrustAdmin {
        let engine = node.admin.ns.engine().clone();
        let keyring = engine
            .validator()
            .map(|v| Arc::clone(v.keyring()))
            .or_else(|| engine.security().map(|mgr| Arc::clone(mgr.keyring())))
            .expect("the CA's keyring");
        load_persisted_contexts(root_dev, &keyring).unwrap();
        TrustAdmin::new(TrustAdminParts {
            engine,
            keyring,
            pib_root: root_dev.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            cas: vec![Arc::clone(&node.ca)],
            context_sync: None,
        })
    }

    /// The admin device `ndn-fwd init` made on the root device: its key and
    /// certificate chain, used here as a remote admin would.
    fn admin_device(root_dev: &Path) -> (Arc<dyn Signer>, Vec<Bytes>) {
        let pib = FilePib::open(root_dev).unwrap();
        let desk: Name = "/home/bob/admin/desk".parse().unwrap();
        let key = pib
            .list_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.has_prefix(&desk))
            .expect("init's admin device");
        let cert = pib.get_issued_cert(&key).unwrap().expect("its certificate");
        (pib.get_signer(&key).unwrap(), vec![cert])
    }

    /// Whether Data the device `key` (in the PIB `device`) produces under
    /// its identity validates under `keyring`, its chain walked to the root.
    async fn produces(node: &Node, keyring: &Arc<Keyring>, device: &Path, key: &Name) -> bool {
        let pib = FilePib::open(device).unwrap();
        let signer = pib.get_signer(key).unwrap();
        let cert = Data::decode(pib.get_issued_cert(key).unwrap().unwrap()).unwrap();
        let cache = Arc::new(CertCache::new());
        cache.insert(Certificate::decode(&cert).unwrap());
        cache.insert(node.ca.ca_certificate().unwrap());
        let identity = Name::from_components(key.components()[..key.len() - 2].iter().cloned());
        let wire = DataBuilder::new(identity.append("notes").append("1"), b"hello")
            .sign_fallible(signer.sig_type(), Some(cert.name.as_ref()), move |region| {
                let (signer, region) = (Arc::clone(&signer), region.to_vec());
                async move { signer.sign(&region).await }
            })
            .await
            .unwrap();
        let validator = Validator::with_keyring(Arc::clone(keyring), cache, None, 4);
        let data = Data::decode(wire).unwrap();
        matches!(
            validator.validate_chain_cached(&data).await.0,
            ValidationResult::Valid(_)
        )
    }

    /// A request pending at the CA, opened as a relay's daemon opens one.
    async fn pending(node: &Node, keyring: &Arc<Keyring>) -> ApprovalRecord {
        let relay: Name = "/home/bob/node/relay".parse().unwrap();
        let key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[9; 32],
            ndn_cert::new_device_key_name(&relay).unwrap(),
        ));
        let poll = ndn_identity::poll_approval_via_engine(
            node.admin.ns.engine(),
            keyring,
            &ns(),
            &ns(),
            key,
            None,
            None,
        )
        .await;
        assert!(matches!(poll, Ok(ApprovalPoll::Pending(_))), "{poll:?}");
        node.approvals.pending().pop().unwrap()
    }

    #[track_caller]
    fn assert_unauthorized<T: std::fmt::Debug>(result: &Result<T, ApproverError>) {
        assert!(
            matches!(result, Err(ApproverError::Refused(r)) if r.kind == RefusalKind::Unauthorized),
            "{result:?}"
        );
    }

    /// A namespace held with the schema an earlier `ndn-fwd init` wrote: its
    /// running CA refuses a remote admin's listing and denial. `ndn-fwd
    /// schema update` plans the two rules added and nothing narrowed, and
    /// once the signed version is handed to the daemon, the same CA — no
    /// restart — lists to and takes the denial from that admin, while an
    /// enrolled device's Data still validates. Asked again, there is
    /// nothing to sign.
    #[tokio::test]
    async fn a_schema_update_handed_over_lets_the_running_ca_take_remote_denials() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let EnrollOutcome::Enrolled(phone) = crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-a", "phone", true),
        )
        .await
        .unwrap() else {
            panic!("an invite enrolls at once")
        };
        let phone_key: Name = phone.key.parse().unwrap();
        let daemon = root_daemon(&node, root_dev.path());
        let root = RootStore::open(&FilePib::open(root_dev.path()).unwrap())
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap();

        // The namespace as an earlier `ndn-fwd init` left it.
        let (_, v1) = ndn_cert::read_stored_context(root_dev.path(), &ns())
            .unwrap()
            .unwrap();
        let (old_schema, old_hint) = old_generated_schema();
        let old = ndn_cert::bump_context_schema(
            root.as_ref(),
            &v1,
            &old_schema,
            &old_hint,
            None,
            None,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        crate::context_refresh::apply_update(&daemon, old.bump.data.raw().clone())
            .await
            .unwrap();

        let (admin, chain) = admin_device(root_dev.path());
        let (engine, keyring, ns) = (daemon.ns.engine(), daemon.ns.keyring(), ns());
        let record = pending(&node, keyring).await;
        let deny = Decision::Deny {
            reason: "not my relay".into(),
        };
        let list =
            || ndn_identity::fetch_pending_via_engine(engine, keyring, &ns, &ns, &admin, &chain);
        assert_unauthorized(&list().await);
        assert_unauthorized(
            &ndn_identity::push_decision_via_engine(
                engine, keyring, &ns, &record, &deny, &admin, &chain,
            )
            .await,
        );
        assert!(node.approvals.get(&record.request_id).unwrap().is_pending());
        assert!(produces(&node, keyring, device.path(), &phone_key).await);

        let plan = plan_update(root_dev.path(), &[]).unwrap();
        assert_eq!(
            plan.update.change.added.len(),
            2,
            "{:?}",
            plan.update.change.added
        );
        assert!(plan.update.change.removed.is_empty());
        assert_eq!(
            plan.update.policy,
            ApprovalPolicy::default(),
            "what the CA enforces"
        );
        let update = ndn_cert::bump_context_schema(
            root.as_ref(),
            &plan.held_data,
            &plan.update.schema,
            &plan.update.hint,
            plan.update.link.as_ref(),
            plan.update.relays.as_deref(),
            false,
        )
        .await
        .unwrap()
        .unwrap();
        let info = crate::context_refresh::apply_update(&daemon, update.bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.held_version, info.version), (2, 3));

        let listed = list().await.unwrap();
        assert!(listed.iter().any(|r| r.request_id == record.request_id));
        let denied = ndn_identity::push_decision_via_engine(
            engine, keyring, &ns, &record, &deny, &admin, &chain,
        )
        .await
        .unwrap();
        assert!(!denied.is_pending(), "{denied:?}");
        assert!(produces(&node, keyring, device.path(), &phone_key).await);
        assert!(
            plan_update(root_dev.path(), &[])
                .unwrap()
                .update
                .change
                .is_empty()
        );
        node.shutdown.shutdown().await;
    }
}
