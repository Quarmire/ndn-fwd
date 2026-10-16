# ndn-fwd-tokens

Operator CLI for invite-token onboarding via the NDNCERT
TokenChallenge. Mints fresh tokens, prints the matching invite as an
`ndn-trust://invite` envelope (or its `https://<domain>/t/invite#…`
universal-link mirror), and optionally renders it as a QR code
(terminal ASCII or SVG) for paste-into-chat / scan-with-phone delivery.

The invite carries the CA prefix, the identity namespace, the token,
and optionally the CA's root anchor fingerprint — everything the
invitee needs to enroll. The payload rides in the URL fragment, so the
token never reaches a web server's access log.

The CLI does **not** talk to a running `ndn-fwd` — tokens go into
`[demo_ca].tokens` in the TOML config, and the forwarder picks them
up on restart. Live token management against a running CA is a
future `ndn-fwd-mgmt` subcommand.

## Get started

```bash
cargo run --release -p ndn-fwd-tokens -- new \
    --ca /demo --namespace /demo/users --domain ndn.example.com
```

Output:

```
token  = "8f3a4c19..."                                  (paste into [demo_ca].tokens)
invite = https://ndn.example.com/t/invite#cARx...       (give to requester)
```

## Configure

CLI flags only.

| Subcommand | Purpose |
|---|---|
| `new --ca <p> --namespace <p> [--anchor-fp <hex>] [--domain <d>] [--count N] [--bytes N] [--qr [--qr-format ascii\|svg]]` | Mint one or more tokens + invites. |
| `qr --ca <p> --namespace <p> [--anchor-fp <hex>] [--domain <d>] --token <t> [--format ascii\|svg]` | Render the QR for an existing token's invite. |

### Invite flags (both subcommands)

| Flag | Default | Purpose |
|---|---|---|
| `--ca` | required | NDNCERT CA prefix the invitee enrolls against (`[demo_ca].prefix`). |
| `--namespace` | required | Identity namespace the invitee is certified under. |
| `--anchor-fp` | none | 64-hex SHA-256 of the CA's root anchor public key; lets the invitee pin the CA. |
| `--domain` | none | DNS domain serving the `JoinClient` page. Set → `https://<d>/t/invite#…`; unset → `ndn-trust://invite/…`. |

### `new` flags

| Flag | Default | Purpose |
|---|---|---|
| `--count` | `1` | How many tokens to mint. |
| `--bytes` | `16` | Token byte length (128 bits → small QR). |
| `--qr` | off | Also render a QR code for each invite. |
| `--qr-format` | `ascii` | `ascii` (terminal) or `svg` (write `<token>.svg`). |

## Build

### Cargo

```bash
cargo build --release -p ndn-fwd-tokens
./target/release/ndn-fwd-tokens --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#ndn-fwd-tokens -- new --ca /demo --namespace /demo/users
nix profile install github:Quarmire/ndn-rs#ndn-fwd-tokens
```

## Run

### Mint one token

```bash
ndn-fwd-tokens new --ca /demo --namespace /demo/users --domain ndn.example.com
# Paste the token line into ndn-fwd.toml under [demo_ca].tokens, restart ndn-fwd.
```

### Mint a batch for a workshop

```bash
ndn-fwd-tokens new --ca /demo --namespace /demo/users --count 20 > tokens.txt
```

Each entry is `token = "<…>"` + `invite = <…>`; bulk-paste the token
half into `[demo_ca].tokens`.

### Token + QR

```bash
ndn-fwd-tokens new --ca /demo --namespace /demo/users --qr --qr-format ascii
# Terminal-renderable QR code; great for sharing in a slide deck.

ndn-fwd-tokens new --ca /demo --namespace /demo/users --qr --qr-format svg
# Writes <token>.svg next to where you run it.
```

### Render a QR for an already-minted token

```bash
ndn-fwd-tokens qr --ca /demo --namespace /demo/users --token 8f3a4c19...
```

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Built on the NDNCERT 0.3 TokenChallenge extension. The QR rendering
uses the [`qrcode`](https://crates.io/crates/qrcode) crate.
