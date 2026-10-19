//! `ndn-fwd-tokens` — invites at the CAs of the running `ndn-fwd`, through
//! its management verbs `ca/invite-create`, `ca/invite-list` and
//! `ca/invite-withdraw` (local trust administrators only), and QR codes of
//! invite links (ASCII or SVG).
//!
//! The daemon makes every invite: a random one-time token scoped to
//! `<namespace>/<role>` (a member or a guest — admin and relay (`node` role)
//! certificates are never issued on an invite: they need an admin's
//! approval), recorded durably by its CA before it is shown, and returned
//! once with its `ndn-trust://invite` link (CA prefix, identity namespace,
//! token, the namespace's expected fingerprint and, optionally, a suggested
//! device name). The CA redeems it at once; nothing goes into the config.
//!
//! A daemon that runs several CAs needs `--namespace` to know whose invite
//! to make or withdraw. Refusals come back as codes; this tool words them.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ndn_cert::report::{TrustRefusal, code};
use ndn_cert::{CaInviteListing, CreatedInvite, InviteEntry, InviteRequest};
use ndn_packet::Name;
use ndn_trust_envelope::TrustEnvelope;

#[derive(Parser)]
#[command(name = "ndn-fwd-tokens", version, about)]
struct Cli {
    /// The daemon's config (`ndn-fwd -c <config>`): where its management
    /// socket is. Default: the default socket.
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make one or more invites at the daemon's CA and print each one's id,
    /// token and link (the only time the token is shown).
    New {
        /// The namespace whose CA makes the invite (needed when the daemon
        /// runs several CAs).
        #[arg(long)]
        namespace: Option<String>,
        /// Role the invite admits: `member` (default) or `guest`. Admins and
        /// relays (`node`) enroll on an admin's approval instead.
        #[arg(long, default_value = "member")]
        role: String,
        /// How long the invite can be redeemed: seconds, or `90m`, `12h`,
        /// `7d`. Default: until redeemed or withdrawn.
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<u64>,
        /// The device name to suggest to the invitee (a hint: the invitee may
        /// choose another).
        #[arg(long)]
        device: Option<String>,
        /// Number of invites to make (default 1).
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Public domain serving the host's `EnrollClient` page. When set,
        /// print the `https://<domain>/t/invite#…` mirror of each link.
        #[arg(long)]
        domain: Option<String>,
        /// Render a QR code for each invite in addition to the text lines.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal-friendly) or
        /// `svg` (writes `<id>.svg` in the current directory).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// List the invites of the daemon's CAs (no tokens): outstanding ones and
    /// those that ended recently.
    List {
        /// Only the invites of this namespace's CA.
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Withdraw an outstanding invite by its id: its token is refused from
    /// now on.
    Withdraw {
        /// The invite's id (as `new` and `list` print it).
        id: String,
        /// The namespace whose CA made it (needed when the daemon runs
        /// several CAs).
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Render an invite link as a QR code (e.g. for a paper handoff).
    Qr {
        /// The `ndn-trust://invite/…` link (or its https mirror).
        link: String,
        /// Render the `https://<domain>/t/invite#…` mirror instead.
        #[arg(long)]
        domain: Option<String>,
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        format: QrFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum QrFormat {
    Ascii,
    Svg,
}

/// A `--ttl` value: seconds, or a number with an `m`, `h` or `d` suffix.
fn parse_ttl(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, unit) = match s.char_indices().last() {
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3_600),
        Some((i, 'd')) => (&s[..i], 86_400),
        Some((i, 's')) => (&s[..i], 1),
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("{s:?} is not a duration (e.g. 3600, 90m, 12h, 7d)"))?;
    match n.checked_mul(unit) {
        Some(0) | None => Err(format!("{s:?} must be a positive duration")),
        Some(secs) => Ok(secs),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::New {
            namespace,
            role,
            ttl,
            device,
            count,
            domain,
            qr,
            qr_format,
        } => {
            let ca = namespace_arg(namespace.as_deref())?;
            let (client, socket) = daemon(cli.config.as_deref()).await?;
            let request = InviteRequest {
                role,
                ttl_secs: ttl,
                device,
            };
            for _ in 0..count {
                let made = client
                    .ca_invite_create(ca.as_ref(), &request)
                    .await
                    .map_err(|e| refused("new", &socket, e))?;
                print_created(&made, domain.as_deref())?;
                if qr {
                    render_qr(
                        &shown_link(&made.link, domain.as_deref())?,
                        qr_format,
                        &made.id,
                    )?;
                }
                println!();
            }
        }
        Cmd::List { namespace } => {
            let ca = namespace_arg(namespace.as_deref())?;
            let (client, socket) = daemon(cli.config.as_deref()).await?;
            let listings = client
                .ca_invite_list(ca.as_ref())
                .await
                .map_err(|e| refused("list", &socket, e))?;
            print_listings(&listings);
        }
        Cmd::Withdraw { id, namespace } => {
            let ca = namespace_arg(namespace.as_deref())?;
            let (client, socket) = daemon(cli.config.as_deref()).await?;
            let gone = client
                .ca_invite_withdraw(ca.as_ref(), &id)
                .await
                .map_err(|e| refused("withdraw", &socket, e))?;
            println!("# invite withdrawn: its token is refused from now on");
            print_entry(&gone);
        }
        Cmd::Qr {
            link,
            domain,
            format,
        } => {
            let envelope = invite_envelope(&link)?;
            let shown = match domain {
                Some(d) => envelope.to_https_url(&d),
                None => envelope.to_uri(),
            };
            render_qr(&shown, format, "invite")?;
        }
    }
    Ok(())
}

/// `--namespace` as a name.
fn namespace_arg(raw: Option<&str>) -> Result<Option<Name>> {
    raw.map(|s| {
        s.parse::<Name>()
            .map_err(|e| anyhow::anyhow!("--namespace {s:?} is not an NDN name: {e}"))
    })
    .transpose()
}

/// The running daemon's management client and its socket.
async fn daemon(config: Option<&str>) -> Result<(ndn_ipc::MgmtClient, String)> {
    let socket = match config {
        Some(path) => {
            let toml =
                std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
            toml.parse::<ndn_config::ForwarderConfig>()
                .with_context(|| format!("parse config {path}"))?
                .management
                .face_socket
        }
        None => ndn_config::ManagementConfig::default().face_socket,
    };
    let client = ndn_ipc::MgmtClient::connect(&socket).await.map_err(|e| {
        anyhow::anyhow!(
            "the daemon is not reachable at {socket} ({e}): its CAs make the invites, so start \
             ndn-fwd (and pass `-c <config>` if it uses another socket), then retry"
        )
    })?;
    Ok((client, socket))
}

/// What to tell when the daemon refused (or could not be asked): the
/// refusal worded for this tool from its code, else the error.
fn refused(what: &str, socket: &str, err: ndn_ipc::ForwarderError) -> anyhow::Error {
    match ndn_ipc::trust_refusal_in(&err) {
        Some(refusal) => anyhow::anyhow!("{what} refused: {}", words(&refusal)),
        None => anyhow::anyhow!("{what}: the daemon at {socket} did not answer: {err}"),
    }
}

/// A refusal in this tool's words: its flags and commands; any other code
/// keeps the daemon's neutral sentence.
fn words(refusal: &TrustRefusal) -> String {
    let p = |k: &str| refusal.param(k).unwrap_or_default().to_owned();
    match refusal.code.as_str() {
        c if c == code::INVITE_NO_CA.code => "this daemon runs no CA, so it makes no invites; \
             run ndn-fwd-tokens against the root device of the namespace (its config has [ca])"
            .to_owned(),
        c if c == code::INVITE_SEVERAL_CAS.code => format!(
            "this daemon runs the CAs of {}: add --namespace <one of them>",
            p("namespaces")
        ),
        c if c == code::INVITE_CA_UNKNOWN.code => format!(
            "this daemon runs no CA of {}; its CAs: {} (--namespace)",
            p("requested"),
            p("namespaces")
        ),
        c if c == code::INVITE_ROLE_UNKNOWN.code => {
            format!("--role {}: not a role; use member or guest", p("role"))
        }
        c if c == code::INVITE_ROLE_NEEDS_APPROVAL.code => {
            let role = p("role");
            format!(
                "--role {role}: an invite never admits a {role} device; {} certifies it only on \
                 an admin's approval: on the new device run `ndn-fwd enroll <anchor link> --role \
                 {role}` (anchor_uri from `ndn-fwd init`), then compare its verification code and \
                 run `ndn-fwd approvals approve <code>` on an admin device",
                p("namespace")
            )
        }
        c if c == code::INVITE_EXPIRY_INVALID.code => {
            "--ttl must be a positive duration (e.g. 3600, 90m, 12h, 7d)".to_owned()
        }
        c if c == code::INVITE_DEVICE_INVALID.code => format!(
            "--device {:?} is not a device name ({})",
            p("device"),
            p("error")
        ),
        c if c == code::INVITE_UNKNOWN.code => format!(
            "the CA holds no invite {} (`ndn-fwd-tokens list` shows them)",
            p("id")
        ),
        c if c == code::INVITE_ALREADY_REDEEMED.code => {
            let by = refusal
                .param("redeemed_for")
                .map(|n| format!(" by {n}"))
                .unwrap_or_default();
            format!(
                "invite {} was redeemed already{by}, so there is nothing to withdraw; to remove \
                 the device, revoke it (`ndn-fwd revoke <device identity>`)",
                p("id")
            )
        }
        c if c == code::INVITE_ALREADY_WITHDRAWN.code => {
            format!("invite {} was withdrawn already", p("id"))
        }
        _ => refusal.reason.clone(),
    }
}

/// The link as shown: the `https://<domain>/t/invite#…` mirror when a
/// domain is given (the payload rides in the fragment, so the token stays
/// out of access logs), else the `ndn-trust://invite` link.
fn shown_link(link: &str, domain: Option<&str>) -> Result<String> {
    Ok(match domain {
        Some(d) => invite_envelope(link)?.to_https_url(d),
        None => link.to_owned(),
    })
}

/// An invite link (`ndn-trust://invite/…` or its https mirror), read back.
fn invite_envelope(link: &str) -> Result<TrustEnvelope> {
    let envelope =
        TrustEnvelope::from_uri(link).map_err(|e| anyhow::anyhow!("not an invite link: {e}"))?;
    if !matches!(envelope, TrustEnvelope::Invite { .. }) {
        bail!("not an invite link (an ndn-trust://invite link is needed)");
    }
    Ok(envelope)
}

fn print_created(made: &CreatedInvite, domain: Option<&str>) -> Result<()> {
    let info = &made.info;
    println!("id      = {}", made.id);
    println!(
        "token   = \"{}\"  # {} only: scoped to {}",
        made.token,
        info.role.as_deref().unwrap_or("member"),
        info.scope.as_deref().unwrap_or(&made.namespace)
    );
    println!("invite  = {}", shown_link(&made.link, domain)?);
    println!("ca      = {}", made.ca);
    if let Some(at) = info.expires_secs {
        println!("expires = {}", ndn_cert::approval::iso_secs(at));
    }
    if let Some(device) = &info.device {
        println!("device  = {device}  # suggested to the invitee");
    }
    Ok(())
}

fn print_listings(listings: &[CaInviteListing]) {
    for listing in listings {
        println!(
            "# invites of {} (CA {}): {}",
            listing.namespace,
            listing.ca,
            listing.invites.len()
        );
        for entry in &listing.invites {
            print_entry(entry);
            println!();
        }
    }
}

fn print_entry(entry: &InviteEntry) {
    let info = &entry.info;
    let iso = ndn_cert::approval::iso_secs;
    println!("id      = {}", entry.id);
    println!("state   = {}", info.state.as_str());
    if let Some(role) = &info.role {
        println!("role    = {role}");
    }
    if let Some(scope) = &info.scope {
        println!("scope   = {scope}");
    }
    println!("created = {}", iso(info.created_secs));
    if !info.created_by.is_empty() {
        println!("by      = {}", info.created_by);
    }
    if let Some(at) = info.expires_secs {
        println!("expires = {}", iso(at));
    }
    if let Some(device) = &info.device {
        println!("device  = {device}");
    }
    if let Some(at) = info.ended_secs {
        println!("ended   = {}", iso(at));
    }
    if let Some(name) = &info.redeemed_for {
        println!("for     = {name}");
    }
}

fn render_qr(url: &str, format: QrFormat, file_stem: &str) -> Result<()> {
    let code = ndn_trust_envelope::qr::encode(url).context("QR encoding")?;
    match format {
        QrFormat::Ascii => {
            let s = code
                .render::<char>()
                .module_dimensions(2, 1)
                .quiet_zone(true)
                .dark_color('█')
                .light_color(' ')
                .build();
            println!("{s}");
        }
        QrFormat::Svg => {
            let image = code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(256, 256)
                .build();
            let path = format!("{file_stem}.svg");
            // The QR carries the invite link, token included: owner-only.
            ndn_security::secure_fs::write_private(std::path::Path::new(&path), image)
                .with_context(|| format!("write {path}"))?;
            println!("(wrote QR to {path})");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parses() {
        assert_eq!(parse_ttl("7d"), Ok(7 * 86_400));
        assert_eq!(parse_ttl("90m"), Ok(90 * 60));
        assert_eq!(parse_ttl("90"), Ok(90));
        assert!(parse_ttl("0").is_err() && parse_ttl("x").is_err());
    }

    /// An invite link reads back from either form; another kind of link is
    /// refused.
    #[test]
    fn qr_takes_invite_links_only() {
        let invite = TrustEnvelope::Invite {
            ca_prefix: "/home/bob".into(),
            identity_namespace: "/home/bob/member".into(),
            token: "member-ab".into(),
            ttl_secs: None,
            anchor_fingerprint: Some([3; 32]),
            device: Some("tv".into()),
        };
        let uri = invite.to_uri();
        assert_eq!(invite_envelope(&uri).unwrap(), invite);
        let https = shown_link(&uri, Some("ndn.example.com")).unwrap();
        assert_eq!(invite_envelope(&https).unwrap(), invite);
        assert!(invite_envelope("ndn-trust://nonsense").is_err());
    }
}
