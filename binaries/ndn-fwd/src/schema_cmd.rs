//! `ndn-fwd schema show|explain` — inspect the trust schema of the contexts
//! the node adopted (`<pib>/contexts/`, verified on load exactly as the
//! daemon loads them). Early-exit subcommand like `init`/`adopt`.
//!
//! - `show [--namespace <ns>]` prints the context and each schema blob as
//!   readable rules: an LVS binary decoded back to LVS source (rule names
//!   included for schemas compiled in-tree), native-text rules verbatim.
//! - `explain <data-name> <key-name> [--namespace <ns>]` answers whether the
//!   context governing `<data-name>` lets `<key-name>` sign it, and which rule
//!   decides. Exit status 0 = allow, 1 = deny.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_cert::load_persisted_contexts;
use ndn_packet::Name;
use ndn_security::{Keyring, LvsModel, SchemaFormat, SignedTrustContext};

use crate::onboard::{flag, pib_dir, positionals};

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("show") => show(&args[1..]),
        Some("explain") => explain(&args[1..]),
        _ => bail!(
            "usage: ndn-fwd schema show [-c <config>] [--pib <dir>] [--namespace <ns>]\n       \
             ndn-fwd schema explain <data-name> <key-name> [-c <config>] [--pib <dir>] \
             [--namespace <ns>]"
        ),
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
            "no adopted trust context in {}/contexts (run `ndn-fwd init --profile hub` or \
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
