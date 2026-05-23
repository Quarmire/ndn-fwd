# ndn-fwd-tokens

Operator CLI for invite-token onboarding via the NDNCERT
TokenChallenge. Mints fresh tokens, prints the matching join URL,
and optionally renders the URL as a QR code (terminal ASCII or PNG)
for paste-into-chat / scan-with-phone delivery.

The CLI does **not** talk to a running `ndn-fwd` — tokens go into
`[demo_ca].tokens` in the TOML config, and the forwarder picks them
up on restart. Live token management against a running CA is a
future `ndn-fwd-mgmt` subcommand.

## Get started

```bash
cargo run --release -p ndn-fwd-tokens -- new --domain ndn.example.com
```

Output:

```
token=8f3a4c19...                                       (paste into [demo_ca].tokens)
url=https://ndn.example.com/join?token=8f3a4c19...      (give to requester)
```

## Configure

CLI flags only.

| Subcommand | Purpose |
|---|---|
| `new --domain <d> [--count N] [--bytes N] [--qr [--qr-format ascii\|png]]` | Mint one or more tokens + URLs. |
| `qr --domain <d> --token <t> [--qr-format ascii\|png]` | Render the QR for an existing token. |

### `new` flags

| Flag | Default | Purpose |
|---|---|---|
| `--domain` | required | DNS domain the join URL points to (must match the forwarder's web entry). |
| `--count` | `1` | How many tokens to mint. |
| `--bytes` | `16` | Token byte length (128 bits → small QR). |
| `--qr` | off | Also render a QR code for each URL. |
| `--qr-format` | `ascii` | `ascii` (terminal) or `png` (write `<token>.png`). |

## Build

### Cargo

```bash
cargo build --release -p ndn-fwd-tokens
./target/release/ndn-fwd-tokens --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#ndn-fwd-tokens -- new --domain ndn.example.com
nix profile install github:Quarmire/ndn-rs#ndn-fwd-tokens
```

## Run

### Mint one token

```bash
ndn-fwd-tokens new --domain ndn.example.com
# Paste the token line into ndn-fwd.toml under [demo_ca].tokens, restart ndn-fwd.
```

### Mint a batch for a workshop

```bash
ndn-fwd-tokens new --domain ndn.example.com --count 20 > tokens.txt
```

Each line is `token=<…>` + `url=<…>`; bulk-paste the token half into
`[demo_ca].tokens`.

### Token + QR

```bash
ndn-fwd-tokens new --domain ndn.example.com --qr --qr-format ascii
# Terminal-renderable QR code; great for sharing in a slide deck.

ndn-fwd-tokens new --domain ndn.example.com --qr --qr-format png
# Writes <token>.png next to where you run it.
```

### Render a QR for an already-minted token

```bash
ndn-fwd-tokens qr --domain ndn.example.com --token 8f3a4c19...
```

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Built on the NDNCERT 0.3 TokenChallenge extension. The QR rendering
uses the [`qrcode`](https://crates.io/crates/qrcode) crate.
