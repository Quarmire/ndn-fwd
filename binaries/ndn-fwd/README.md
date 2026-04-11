# ndn-router

Standalone NDN forwarder binary.

## Usage

```bash
# Default config (engine starts with no faces or routes):
cargo run --bin ndn-router

# With a TOML config file:
cargo run --bin ndn-router -- -c ndn-router.toml

# Custom management socket path:
cargo run --bin ndn-router -- -c ndn-router.toml -m /run/ndn/mgmt.sock
```

## Features

- Loads face and route configuration from a TOML file (`-c`)
- Supports UDP, TCP, multicast, and Unix socket faces
- Static FIB routes from config, plus runtime route management
- Unix-socket management server for live route/face/stats queries
- NDN-native management via `/localhost/ndn-ctl` Interest/Data exchange
- Optional trust-anchor and key directory for signed-Data verification
- Structured tracing via `RUST_LOG` (e.g. `RUST_LOG=ndn_engine=trace`)

## Management

The management server speaks newline-delimited JSON over a Unix socket
(default `/tmp/ndn-router.sock`):

```bash
SOCK=/tmp/ndn-router.sock

echo '{"cmd":"add_route","prefix":"/ndn","face":0,"cost":10}' | nc -U $SOCK
echo '{"cmd":"list_faces"}' | nc -U $SOCK
echo '{"cmd":"get_stats"}' | nc -U $SOCK
echo '{"cmd":"shutdown"}' | nc -U $SOCK
```

## Configuration

See the [main README](../../README.md#configuration) for the full TOML schema.
