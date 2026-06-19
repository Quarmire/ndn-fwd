# ndn-fwd

The Named Data Networking **forwarder binary** and CLIs, built on
[ndn-rs](https://github.com/Quarmire/ndn-rs) + [ndn-ext](https://github.com/Quarmire/ndn-ext).

- `binaries/ndn-fwd` — the forwarder daemon (face provisioning, mgmt, Docker image)
- `binaries/tooling`, `crates/tooling/ndn-tools-core` — CLIs (put/peek/ping/iperf, …)
- `crates/tooling/dioxus-demo` — in-browser ndn-rs demo
- `testbed/` — interop / compliance / bench harness

The operator dashboard lives in its own repo:
**[ndn-dashboard](https://github.com/Quarmire/ndn-dashboard)**.

Part of the [ndn-rs](https://github.com/Quarmire/ndn-rs) ecosystem.
