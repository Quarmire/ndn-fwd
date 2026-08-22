# ndn-fwd

The Named Data Networking **forwarder daemon**
([`binaries/ndn-fwd`](binaries/ndn-fwd/)) and its operator CLI suite
([`binaries/tooling`](binaries/tooling/), core logic in
[`crates/tooling/ndn-tools-core`](crates/tooling/ndn-tools-core/)), with a
Docker-based interop/compliance harness in [`testbed/`](testbed/). Built on
the sibling [ndn-rs](https://github.com/Quarmire/ndn-rs) and
[ndn-ext](https://github.com/Quarmire/ndn-ext) repos via unpinned `../` path
deps — check them out (plus
[ndn-radio-drivers](https://github.com/Quarmire/ndn-radio-drivers)) next to
this repo to build. Like the rest of the ecosystem this code is primarily
AI-authored and not proven spec-compliant; do not treat it as a reference
NDN implementation. The operator dashboard lives in
[ndn-dashboard](https://github.com/Quarmire/ndn-dashboard).

Where every repo in the workspace stands (branches, sync state, CI,
direction) is recorded in the checkout-level [`STATE.md`](../STATE.md)
ledger, one directory above this repo in the dev workspace.
