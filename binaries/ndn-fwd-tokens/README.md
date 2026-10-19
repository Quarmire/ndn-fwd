# ndn-fwd-tokens

Operator CLI for invites. It asks the running `ndn-fwd` to make, list or
withdraw the invites of its CAs, and renders invite links as QR codes
(terminal ASCII or SVG) for paste-into-chat or scan-with-phone delivery.

The daemon's CA makes each invite: a random one-time token scoped to
`<namespace>/<role>`, recorded durably (only a hash of the token is stored)
before it is shown. The invite is returned once, with its
`ndn-trust://invite` link, or the `https://<domain>/t/invite#…`
universal-link mirror with `--domain`. The link carries the CA prefix, the
identity namespace, the token, the namespace's expected fingerprint and,
optionally, a suggested device name. That is everything the invitee needs:
`ndn-fwd enroll <link>` adopts the namespace's trust context, checks it
against the fingerprint and enrolls. The CA can redeem the invite at once.
Nothing goes into the config, and no restart is needed. Invites survive a
restart of the daemon.

An invite admits a `member` (default) or a `guest` (`--role guest`), never
anything else. Admin devices and relays (`node` role) need an admin's
approval: on the new device run `ndn-fwd enroll <anchor link> --role admin`
(or `node`), then on the CA host or an admin device run
`ndn-fwd approvals approve <code>` with the code it shows.

The management verbs (`ca/invite-create`, `ca/invite-list`,
`ca/invite-withdraw`) are trust changes. They are accepted only from a
local trust administrator on the daemon's management socket, never over
the network. The daemon records who made each invite.

## Get started

```bash
ndn-fwd-tokens -c /etc/ndn-fwd.toml new --domain ndn.example.com
```

Output:

```
id      = 3c9e0f…
token   = "member-8f3a4c19…"  # member only: scoped to /home/bob/member
invite  = https://ndn.example.com/t/invite#cARx…   (give to the invitee)
ca      = /home/bob
```

## Configure

CLI flags only. `-c <config>` (global) names the daemon's config, which says
where its management socket is. Without it, the default socket is used.

| Subcommand | Purpose |
|---|---|
| `new [--namespace <ns>] [--role member\|guest] [--ttl <dur>] [--device <name>] [--count N] [--domain <d>] [--qr [--qr-format ascii\|svg]]` | Make one or more invites. |
| `list [--namespace <ns>]` | List the invites of the daemon's CAs (every CA's without `--namespace`): outstanding ones, and those redeemed, withdrawn or expired in the last 30 days. Tokens are never shown again. |
| `withdraw <id> [--namespace <ns>]` | Withdraw an outstanding invite: its token is refused from now on. A redeemed invite cannot be withdrawn; revoke the device instead (`ndn-fwd revoke`). |
| `qr <link> [--domain <d>] [--format ascii\|svg]` | Render an invite link as a QR code. |

### `new` flags

| Flag | Default | Purpose |
|---|---|---|
| `--namespace` | the daemon's only CA | The namespace whose CA makes the invite. Needed when the daemon is the root of several namespaces (`[[ca]]`). |
| `--role` | `member` | `member` or `guest`. |
| `--ttl` | none | How long the invite can be redeemed: seconds, or `90m`, `12h`, `7d`. The expiry also travels inside the token, so `ndn-fwd enroll` refuses an expired invite before contacting the CA. |
| `--device` | none | A device name to suggest to the invitee (`ndn-fwd enroll` uses it unless `--device` is given there). A hint, not a constraint. |
| `--count` | `1` | How many invites to make. |
| `--domain` | none | DNS domain serving the `EnrollClient` page: print the `https://<d>/t/invite#…` mirror. The payload rides in the URL fragment, so the token never reaches a web server's access log. |
| `--qr` | off | Also render a QR code for each invite. |
| `--qr-format` | `ascii` | `ascii` (terminal) or `svg` (writes `<id>.svg`, owner-readable only). |

## Build

### Cargo

```bash
cargo build --release -p ndn-fwd-tokens
./target/release/ndn-fwd-tokens --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#ndn-fwd-tokens -- new
nix profile install github:Quarmire/ndn-rs#ndn-fwd-tokens
```

## Run

### Make one member invite

```bash
ndn-fwd-tokens -c ndn-fwd.toml new --ttl 7d
```

### Guest invites for a party

```bash
ndn-fwd-tokens -c ndn-fwd.toml new --role guest --ttl 12h --count 20 > invites.txt
```

### A root device of two namespaces

```bash
ndn-fwd-tokens -c ndn-fwd.toml new --namespace /work/acme --device laptop
```

### See and withdraw invites

```bash
ndn-fwd-tokens -c ndn-fwd.toml list
ndn-fwd-tokens -c ndn-fwd.toml withdraw 3c9e0f…
```

### Invite + QR

```bash
ndn-fwd-tokens -c ndn-fwd.toml new --qr --qr-format ascii
ndn-fwd-tokens qr 'ndn-trust://invite/…' --format svg
```

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Built on the NDNCERT 0.3 TokenChallenge extension. The QR rendering
uses the [`qrcode`](https://crates.io/crates/qrcode) crate.
