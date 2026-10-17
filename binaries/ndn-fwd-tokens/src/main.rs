//! `ndn-fwd-tokens` — mint invite tokens for the onboarding-link flow and
//! render them as `ndn-trust://invite` envelopes (or their
//! `https://<domain>/t/invite#…` universal-link mirror) and QR codes (ASCII or
//! SVG). Tokens go into `[ca].tokens` in `ndn-fwd.toml`; the running CA
//! picks them up on restart.
//!
//! Every minted token carries its role (`member-<hex>`, `guest-<hex>`): the CA
//! scopes it to `<namespace>/<role>`, so it can only certify a device of that
//! role, and the invite names that prefix as the invitee's identity
//! namespace. Admin and relay (`node` role) certificates are never issued on a token —
//! they need an admin's device approval. With `--ttl` a token also carries its
//! expiry (`…-until<unix-secs>`): the CA refuses it after that, and so does
//! the invitee's `ndn-fwd enroll` before contacting the CA.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ndn_cert::roles::{Role, role_prefix, role_token, token_expiry, token_role, token_with_expiry};
use ndn_packet::Name;
use ndn_trust_envelope::{ANCHOR_FINGERPRINT_LEN, TrustEnvelope};
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "ndn-fwd-tokens", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// What every invite envelope carries besides the token itself.
#[derive(Args)]
struct InviteArgs {
    /// NDNCERT CA prefix the invitee enrolls against (e.g. `/home/bob`).
    #[arg(long)]
    ca: String,
    /// The namespace (`ndn-fwd init --namespace`, e.g. `/home/bob`). The
    /// invite names `<namespace>/<role>` as the invitee's identity
    /// namespace.
    #[arg(long)]
    namespace: String,
    /// Lowercase-hex SHA-256 of the namespace's root anchor public key
    /// (`anchor_fp` from `ndn-fwd init`). With it, `ndn-fwd enroll <invite>`
    /// adopts the namespace's trust context by itself and checks it is signed
    /// by that root; without it the invitee must adopt the context first.
    #[arg(long)]
    anchor_fp: Option<String>,
    /// Public domain serving the host's `EnrollClient` page. When set, emit the
    /// `https://<domain>/t/invite#…` mirror; otherwise `ndn-trust://invite/…`.
    #[arg(long)]
    domain: Option<String>,
}

/// The role an invite admits.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum InviteRole {
    Member,
    Guest,
    /// Refused: admin certificates need an admin's device approval.
    Admin,
    /// Refused: relay (`node` role) certificates need an admin's device approval.
    Node,
}

/// The role a token may carry; admins and relays are refused.
fn invite_role(role: InviteRole) -> Result<Role> {
    match role {
        InviteRole::Member => Ok(Role::Member),
        InviteRole::Guest => Ok(Role::Guest),
        InviteRole::Admin => bail!(
            "--role admin: an invite token never admits an admin device — the CA issues \
             admin certificates only on an admin's device approval: have the new device \
             enroll as <namespace>/admin/<device> with the device-approval challenge and \
             approve it on an admin device (`ca approve` on the CA host)"
        ),
        InviteRole::Node => bail!(
            "--role node: an invite token never admits a relay — the CA issues node-role \
             certificates only on an admin's device approval: have the relay enroll as \
             <namespace>/node/<name> with the device-approval challenge and approve it on \
             an admin device (`ca approve` on the CA host)"
        ),
    }
}

/// The invitee's identity namespace: `<namespace>/<role>`.
fn invite_namespace(namespace: &str, role: Role) -> Result<String> {
    let ns: Name = namespace
        .parse()
        .map_err(|e| anyhow::anyhow!("--namespace {namespace:?} is not an NDN name: {e}"))?;
    Ok(role_prefix(&ns, role).to_string())
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate one or more random tokens + their matching invite envelopes.
    /// The token strings go into `[ca].tokens` in `ndn-fwd.toml`;
    /// the invites go to your users.
    New {
        #[command(flatten)]
        invite: InviteArgs,
        /// Role the invite admits: `member` (default) or `guest`. `admin` and
        /// `node` are refused — they need an admin's device approval.
        #[arg(long, value_enum, default_value_t = InviteRole::Member)]
        role: InviteRole,
        /// Number of tokens to mint (default 1).
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// How long the invite can be redeemed: seconds, or `90m`, `12h`,
        /// `7d`. The expiry is written into the token itself, so it holds
        /// however long the token sits in the config. Default: no expiry.
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<u64>,
        /// Token byte length (default 16 — 128 bits, fits a small QR).
        #[arg(long, default_value_t = 16)]
        bytes: usize,
        /// Render a QR code for each invite in addition to the text line.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal-friendly)
        /// or `svg` (writes `<token>.svg` in the current directory).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// Render an existing token's invite as a QR code (e.g. for a paper
    /// handoff). A token without a role prefix is a member token.
    Qr {
        #[command(flatten)]
        invite: InviteArgs,
        #[arg(long)]
        token: String,
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        format: QrFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum QrFormat {
    Ascii,
    Svg,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::New {
            invite,
            role,
            count,
            ttl,
            bytes,
            qr,
            qr_format,
        } => {
            let role = invite_role(role)?;
            let identity_namespace = invite_namespace(&invite.namespace, role)?;
            for _ in 0..count {
                let mut token = role_token(role, &mint_token(bytes)?);
                if let Some(ttl) = ttl {
                    token = token_with_expiry(&token, now_secs().saturating_add(ttl));
                }
                let url = invite_url(&invite, &identity_namespace, &token)?;
                println!("token  = \"{token}\"  # {role} only: scoped to {identity_namespace}");
                println!("invite = {url}");
                if qr {
                    render_qr(&url, qr_format, &token)?;
                }
                println!();
            }
        }
        Cmd::Qr {
            invite,
            token,
            format,
        } => {
            // The namespace CA scopes a token without a role prefix to members.
            let role = token_role(&token).unwrap_or(Role::Member);
            let identity_namespace = invite_namespace(&invite.namespace, role)?;
            let url = invite_url(&invite, &identity_namespace, &token)?;
            render_qr(&url, format, &token)?;
        }
    }
    Ok(())
}

/// The invite envelope for `token`. The https mirror keeps the payload in the
/// URL fragment, not the query: fragments don't traverse the HTTP request line,
/// so the token stays out of intermediary access logs.
fn invite_url(args: &InviteArgs, identity_namespace: &str, token: &str) -> Result<String> {
    let anchor_fingerprint = args.anchor_fp.as_deref().map(parse_fp).transpose()?;
    let envelope = TrustEnvelope::Invite {
        ca_prefix: args.ca.clone(),
        identity_namespace: identity_namespace.to_owned(),
        token: token.to_owned(),
        // What is left of the token's own expiry, for readers of the envelope.
        ttl_secs: token_expiry(token).map(|at| at.saturating_sub(now_secs())),
        anchor_fingerprint,
    };
    Ok(match &args.domain {
        Some(domain) => envelope.to_https_url(domain),
        None => envelope.to_uri(),
    })
}

fn parse_fp(hex: &str) -> Result<[u8; ANCHOR_FINGERPRINT_LEN]> {
    let hex = hex.trim();
    if !hex.is_ascii() || hex.len() != ANCHOR_FINGERPRINT_LEN * 2 {
        bail!(
            "--anchor-fp must be {} hex characters (SHA-256), got {hex:?}",
            ANCHOR_FINGERPRINT_LEN * 2
        );
    }
    let mut out = [0u8; ANCHOR_FINGERPRINT_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("--anchor-fp is not hex: {hex}"))?;
    }
    Ok(out)
}

fn mint_token(bytes: usize) -> Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom (this CLI is Unix-only today)")?
        .read_exact(&mut buf)
        .context("read /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn render_qr(url: &str, format: QrFormat, token: &str) -> Result<()> {
    let code = QrCode::new(url.as_bytes()).context("QR encoding")?;
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
            let path = format!("{token}.svg");
            // The QR carries the invite URL, token included: owner-only.
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
    fn admin_and_node_invites_are_refused() {
        assert_eq!(invite_role(InviteRole::Member).unwrap(), Role::Member);
        assert_eq!(invite_role(InviteRole::Guest).unwrap(), Role::Guest);
        for refused in [InviteRole::Admin, InviteRole::Node] {
            assert!(invite_role(refused).is_err());
        }
    }

    #[test]
    fn role_tokens_name_their_scope() {
        let token = role_token(Role::Guest, "00ff");
        assert_eq!(token_role(&token), Some(Role::Guest));
        assert_eq!(
            invite_namespace("/home/bob", Role::Guest).unwrap(),
            "/home/bob/guest"
        );
        assert!(invite_namespace("home bob", Role::Member).is_err());
    }

    /// `qr` for a token without a role prefix renders a member invite the
    /// invitee can enroll with.
    #[test]
    fn unprefixed_token_qr_is_a_usable_member_invite() {
        let args = InviteArgs {
            ca: "/home/bob".into(),
            namespace: "/home/bob".into(),
            anchor_fp: None,
            domain: None,
        };
        let role = token_role("plain").unwrap_or(Role::Member);
        let url = invite_url(&args, &invite_namespace("/home/bob", role).unwrap(), "plain").unwrap();
        let link = ndn_cert::InviteLink::from_uri(&url).expect("usable invite");
        assert_eq!(link.role, Role::Member);
    }

    /// A `--ttl` token carries its expiry into the invite.
    #[test]
    fn ttl_travels_in_the_token() {
        assert_eq!(parse_ttl("7d"), Ok(7 * 86_400));
        assert_eq!(parse_ttl("90"), Ok(90));
        assert!(parse_ttl("0").is_err() && parse_ttl("x").is_err());
        let token = token_with_expiry(&role_token(Role::Member, "ab"), now_secs() + 600);
        let args = InviteArgs {
            ca: "/home/bob".into(),
            namespace: "/home/bob".into(),
            anchor_fp: None,
            domain: None,
        };
        let url = invite_url(&args, "/home/bob/member", &token).unwrap();
        let link = ndn_cert::InviteLink::from_uri(&url).unwrap();
        assert_eq!(link.expires_at_secs, token_expiry(&token));
    }
}
