# End-to-end harness (`ndn-e2e`)

Runs real `ndn-fwd` daemons and the operator CLIs (`ndn-fwd`,
`ndn-fwd-tokens`, `ndn-put`, `ndn-peek`, `ndn-ctl`, `ndn-sec`) through the
personal-namespace life cycle, the way an operator would, and checks what can
be observed: exit status, fetched bytes equal to published bytes, a fetch that
returns nothing, a certificate name that changed, a trust-context version that
advanced or did not, a file present or absent. It never matches message
wording.

## Running

```sh
cargo run -p ndn-e2e                        # every scenario, ~4 minutes
cargo run -p ndn-e2e -- --only negatives    # one scenario (repeatable, or a,b)
cargo run -p ndn-e2e -- --keep              # keep configs, PIBs, logs, report.json
cargo run -p ndn-e2e -- --list
```

It first runs `cargo build -p ndn-fwd -p ndn-tools -p ndn-fwd-tokens --bins`
(a stale binary would witness old behaviour), then, in the sibling
`ndn-mobile` workspace, `cargo build -p ndn-boltffi --example phone_host`
(the app's side of `phone-links`), and takes the binaries from the cargo
target directory (`cargo metadata` → `target_directory`, `debug/` and
`debug/examples/`). `--no-build` skips the builds; `--bin-dir <dir>` uses
other binaries (with `examples/phone_host` under it).

The crate is a workspace member but not a default member, so `cargo build` and
`cargo test` in ndn-fwd never build or run it.

Exit status: 0 when every step passed, 1 when a step failed, 2 when the
harness could not run.

## Prerequisites

- Linux with unprivileged user namespaces (`unshare --map-root-user --net
  --pid --mount-proc --fork true` must work).
- `unshare`, `nsenter`, `setpriv` (util-linux), `ip` (iproute2) and `nft`
  (nftables) on `PATH`; on NixOS without them: `nix-shell -p util-linux
  iproute2 nftables`. Without `nft` (or `nsenter`) the `direct-paths` and
  `membership` scenarios are reported SKIP with the reason.
- For the "another local user" steps: subordinate uids for your user
  (`/etc/subuid`) and `newuidmap`, so `unshare --map-auto` can map uid 1.
  Without them those two steps are reported SKIP with the reason.

No root, no change to the host's network, no fixed ports on the host.

## How it runs

The outer process starts `unshare --map-auto --map-root-user --net --pid
--mount-proc --fork --kill-child` running itself again as PID 1 of a new
user, network, mount and PID namespace (`--mount-proc` gives it its own
`/proc`, so `/proc/<pid>/ns/net` names a namespace of a process it
started). Inside, `lo` carries 10.200.0.1-10/24. Those are not
loopback addresses (faces to 127.0.0.1 are local and skip validation), so
every link between daemons is a non-local UDP face and every Data is
validated. Daemons and producers are stopped after each scenario; when the
inner process exits for any reason (including a panic or a kill), the kernel
kills every process left in the PID namespace. Ctrl-C kills `unshare`, which
SIGKILLs the namespace. The run directory (`$TMPDIR/ndn-e2e-*`) is removed
unless `--keep` is set.

NAT boxes (`src/nat.rs`, used by `direct-paths` and `membership`) are nested network
namespaces inside that one, which acts as the internet and routes between
them (`ip_forward = 1`). Each is held by an `unshare --net sleep infinity`
process and entered with `nsenter --net=/proc/<pid>/ns/net`. Box k has a
veth `w<k>` (10.0.k.1/24, harness side) ↔ `wan` (10.0.k.2/24, its public
address, default route via 10.0.k.1) and a LAN veth `lan` (192.168.k.1/24)
↔ `eth0` in a device namespace (192.168.k.2/24, default route via
192.168.k.1). nftables in the box masquerades out of `wan` (`masquerade`:
port-restricted cone; `masquerade random,fully-random`: symmetric) and drops
whatever arrives on `wan` unsolicited (`ct state new drop` on input and
forward; without it an unsolicited packet leaves a conntrack entry that makes
masquerade pick another port). A node behind a box runs its daemon with
`nsenter --net=…` in the device namespace, its faces bound to its LAN
address; the tools stay outside and reach it through its unix socket. The
public nodes (root, relay) stay on `lo`. Cutting two boxes apart is an
nftables table in the harness's namespace dropping UDP between their public
addresses. The rulesets and every command run, with its output, are in
`<run dir>/direct-paths/nat/` (`--keep`).

Inside the user namespace the daemons run as uid 0 (your uid, mapped). The
"another local user" steps run the CLI as uid 1 through `setpriv --reuid=1
--regid=1 --clear-groups`; the daemon's peer-credential check sees a uid
that is neither its own, root, nor in `trust_admin_groups`.

Each step prints PASS/FAIL with its duration, followed by its `evidence:`
lines where it records what it observed (addresses, counters, path states;
also in `report.json`). A failing step prints its
commands with their output and the tail of every daemon and producer log,
and ends its scenario. Secrets go through the environment
(`NDN_ROOT_PASSPHRASE`, `NDN_KIT_PASSPHRASE`, `NDN_KIT_WORDS`) and are never
printed.

## Scenarios

| Scenario | Proves |
|---|---|
| `lifecycle` | `init` with a sealed-file root and CA; a relay adopts from a fingerprint-only link; two members enroll with invites through the relay; a member's Data validates at the relay and at another member with cold caches; after every daemon restarts, trust state is unchanged and the Data validates again; `renew` (member lifetime 1 day) keeps the key and changes the certificate name, and new Data validates where the old certificate is cached; `revoke` with a wrong passphrase changes no file; with the right one the version advances, the relay and the other member adopt it by periodic pull, and both refuse the revoked member's Data while a member that was not revoked still validates. |
| `lifecycle-push` | The same with `context_sync = true` and `context_refresh_secs = 0` (no periodic refresh), so only the sync group can deliver the revocation. |
| `recovery-destroyed` | A words kit and a file kit; both check out on the relay. The member goes offline, the root device's daemon is stopped and its PIB deleted. `recover` without `--from-held` stops and writes nothing (nothing answers); with `--old-root destroyed --from-held` the relay becomes the root device (v3 → v5, new fingerprint) and restarts with the printed `[security]`/`[ca]` lines. The offline member comes back and catches up from v3 to v5 on its own, its Data under the old CA still validates at the restarted relay, it renews at the new CA (its PIB then holds a certificate whose KeyLocator is the new CA key), and new Data validates. A fresh device is refused with the old root's link, adopts with the new one, enrolls with a new invite, and its Data validates. |
| `recovery-compromised` | Two file kits. The old root keeps running. `recover --old-root compromised` with kit 1 (no `--from-held`: the old root answers). The member's Data under its old certificate is refused at the relay; it enrolls again with `--force` (new key) and its Data validates. Kit 2 (not kept) no longer checks out; kit 1 does. A witness linked only to the old root adopts the recovered version inline; the old root then signs three more versions, and the witness, relay and member still hold the recovered version, the witness's contexts byte for byte. |
| `negatives` | Mistyped and swapped words (variants whose BIP39 checksum fails) are refused by `recovery-kit check` and `recover`, and `recover` writes no root store and leaves the held contexts unchanged; the same for a wrong kit passphrase and for a revoked kit with the right passphrase. An invite carrying another namespace's fingerprint, a used invite and an expired invite are refused and leave no certificate. Data signed under the member's name by an unenrolled key is refused at once (`ndn-peek` exits 3 with `refused: unverifiable`, then `refused for now: retry later: …`: the root's certificate fetch is answered NoRoute, so the certificate is known absent; not final, since a certificate absent now may be fetched later); Data with one byte flipped in transit by a UDP shim is refused at once (`ndn-peek` exits 3 with `refused: bad-signature`, then `final: …`; the shim must have flipped something). Another local user is refused `ndn-ctl route add` and `ndn-fwd adopt`. Each refusal has a control under the same setup that succeeds: the right words or passphrase, an unused invite, enrolled Data, the shim not tampering, the operator's own command. |
| `approval` | Enrollment on an admin's approval: `ndn-fwd enroll <anchor link> --role admin\|node` (by default the namespace certifies admin and node devices on an admin's approval alone). A device asks and is `pending` with a six-digit code, and its `enroll --status` shows the same code; the root device's operator approves by code (`ndn-fwd approvals approve`) and the device's certificate is issued with no further action (its daemon keeps a held status Interest at the CA, answered the moment the decision is recorded; the wait ends on what `enroll --status` shows). A second device asks for admin and a member asks for a node certificate (`--force`); the CA's daemon and the second device's restart, the CA's approval records unchanged byte for byte and the request pending on both sides (the member's held status Interest is lost with the CA's restart; it sends the next one when that one expires, within 30 s). The first device, now a remote admin, lists the request with the code the requester shows and approves it by code: the certificate is issued with no further action, the CA's record names the admin's key, and the new admin's Data validates at the root. The member's own `approvals approve` is refused with a reason and changes nothing (CA records byte for byte, request still pending); the remote admin denies with a reason, and the requester's status shows `denied` with the reason the admin typed, its new key is gone from its PIB, and its member certificate stays. Last, a namespace made before the `#deny`/`#pending` schema rules: a fixture signs, with the root store, a version whose schema lacks those two rules and whose enrollment hint names no approval roles (what `init` made before), and hands it to the root's daemon with `security/context-update` (the one place the harness calls a library, `ndn-cert`: no CLI signs a chosen schema). Every node adopts it; the remote admin's list and deny are refused with a reason and change nothing. `ndn-fwd schema update` on the root device signs the next version, every node adopts it, the remote admin lists the request (same code) and denies it, the requester learns the denial, and the admin's new Data validates at the root and at the remote admin. Expiry is not run here, since the request lifetime is in days (`[ca] approval_request_ttl_days`); `ndn-cert`'s `tests/approval.rs` covers it (`the_requester_learns_a_denial_or_an_expiry`, `an_expired_request_is_neither_listed_nor_decided_and_is_pruned`, `a_held_status_is_answered_when_the_decision_is_recorded`). |
| `quic-links` | Devices linked over QUIC, identified by their keys. A relay (a `node` device by approval, listening for links) and two devices that reach it over QUIC only, from before they are enrolled: phone (dial-only, `listen = false`, so the relay sees it at its own address) gets an enrollment link that carries nothing but its enrollment (a fetch of the relay's Data is Nacked), enrolls by invite over it, and then fetches that Data over the full link its daemon made by itself; tab does the same on the root device's approval. A 400 KB segmented object validates from phone at tab through the relay, and Data the other way; an unenrolled device holding the namespace gets only an enrollment link, which carries none of the namespace's Data; a dial expecting another key than the relay's links nothing; links come back after the relay, then a device, restart; a revocation the relay adopts closes the revoked device's link and keeps it closed. |
| `direct-paths` | Direct paths through real NAT (nested network namespaces with nftables masquerade, see How it runs). phone and tab, each behind a port-restricted cone box, link to the relay over QUIC only and enroll by invite; the relay sees each at its box's public address (`ndn-ctl face list`), not its LAN address. phone names tab as a `[[peer]]` reached through the relay; within seconds both show a `path direct` in `ndn-ctl link list` at the other box's public address. tab fetches an 800 KB object from phone and the relay's packet counters on their links grow by less than half the segment count (relayed, each segment costs it four packets). Dropping UDP between the two boxes removes the direct path from both within the 8 s idle timeout; phone's `direct` state is `trying` or `not-possible`, and a fetch goes through the relay (its counters grow by at least the segment count). Allowing it again brings the direct path back by itself (retry with backoff), and a fetch works. car and tv, behind symmetric boxes, get no direct path; car's `direct` state is `not-possible` with the reason, and tv's Data reaches car through the relay. stranger (public, never enrolled, a key of its own outside the namespace, no trust context, accepted by the relay by its key) punches tab: tab's `punches-refused` grows, its `probes-sent` does not, box B forwards no UDP to stranger (an nftables counter stays 0), and stranger's `direct` state is `refused` with the reason. |
| `phone-links` | An app hosting links through ndn-boltffi: `phone_host` (ndn-mobile's `ndn-boltffi` example) drives the `NdnEngine` FFI an Android or iOS app calls, line by line over stdin, against real daemons (root + CA, a `node` relay listening for QUIC links with `[relay_service] hold` and a `wake_command`, desk a member linked to it). The app makes a key of its own, starts links on 10.200.0.4 and adds its relay (`add_relay`): the relay admits it on an enrollment link; the app enrolls by invite over it and the link becomes a full one by itself. The app gets the desk's Data through the relay (`get` by its exact name, `<name>/seg=0` of a one-segment `ndn-put`) and the desk fetches the object the app publishes (`publish_object`, RDR: ndn-peek asks for its metadata, then the version it names); both then show a direct path to the other by membership (no `[[peer]]` names either). Mode `off` closes the relay link (the relay's `ndn-ctl face list` has no link from the app) and it stays closed until the app's `connect`; `on-demand` closes idle after the app goes to the background and links again for an outgoing Interest only the relay answers; `network_changed` with a socket on 10.200.0.6 moves the links (the relay's link list and its `ndn-ctl face list` show the app there, not at its old address), the desk's direct path to the app is back at the new address within 4 s whichever side had dialled it (the app punches again at once: a QUIC server cannot migrate, so without that a path the app accepted was lost for the desk's 8 s idle timeout), and the desk still reaches it. The relay runs its wake command with the app's token and device for the sleeping app, never while it is awake, holds the Interest, and the app answers it once foregrounded. |
| `relays` | Which relays a device uses, and whom a relay serves (`[relays]`, `[[relay]]`, `[relay_service]`, `[[ca.relay]]`). /ra's root device advertises r1 (preference 0) and r2 (preference 1) from `[[ca.relay]]` at `init -c`; m1 and m2 enroll and, with no `[[relay]]`, `[[peer]]` or UDP link, link to r1 (`relay linked source=namespace:/ra preference=0`, r2 `standby`) and m2's fetch of m1's object goes through r1 (its packet counters cover every segment). r1 stops (closing its links as shutting down): both move to r2 at once, without first redialling r1, and the next fetch goes through r2; r1 restarts: both link to it again and release r2, which then lists them neither linked nor asleep although they asked it to hold their Interests. b1 of /rb names r1 by its expected fingerprint and is refused (`relay down`, the reason naming b1 and /rb; r1 never links it). club, the root device of /rc, serves `open` with `links_per_namespace = 1`: it links b1 and refuses b2 (the reason naming /rb), linking one /rb device only. club then serves /ra `listed` by its root fingerprint; m1 and m2 add it as a `[[relay]]` by its expected fingerprint (user relay first, r1 `standby`) and m2's fetch of m1's object goes through club. |
| `on-demand` | Link modes and reachability while asleep, from `ndn-fwd.toml` and `ndn-ctl link connect\|disconnect`. The relay holds Interests (`hold_per_device = 2`) and runs a `wake_command` script appending `$NDN_WAKE_TOKEN $NDN_WAKE_DEVICE` to a file; members make no direct paths. phone's `[[relay]]` is `on-demand` (`idle_secs = 10`, `hold`, `wake_token`): an outgoing fetch links it, it closes after its idle time (`down` says why; the relay shows the phone `asleep`), and the next fetch links it again. tab's is `off`: once its link list says so, it stays closed and a fetch over it fails, until `ndn-ctl link connect`; `disconnect` closes it. The desk's fetch of the linked phone's Data leaves the wake file empty; once the phone sleeps, two Interests for it are held, the wake command writes one line with its token (hex) and device, and a third is Nacked (Congestion) at once; `ndn-ctl link connect` on the phone (the push waking the app) delivers the two held Interests, answered within their lifetime. |
| `membership` | Direct paths by membership under the trust context's default role matrix, through real NAT (three cone boxes). m1 and m2 (members) and visitor (a guest, by a guest invite) each name only the relay (`[[peer]]`) and enroll by invite over it. With no `[[peer]]` for each other, m1 and m2 show `path direct` to each other at the other box's public address, and m2's fetch of m1's 400 KB object adds no packet to the relay's counters on their links. The guest's link list shows only the relay (no member, no address but the relay's) and neither member lists it; its fetch of m1's Data goes through the relay. Once the guest names m1 as reached through the relay, its `direct` state toward m1 is `off`, saying the role matrix allows no direct path between guest and member devices. |
| `tui` | The admin TUI's state layer (`ndn_tui::driver::Driver`: its model, its streams and the commands behind its keys) against real daemons, no terminal. The main device's TUI lists /tu as owned with the no-recovery-kit warning; it makes an invite (member, 1 day, device hint) shown once with its link and QR code and listed as open; phone's TUI joins with it, and the main device's TUI lists phone as a member and the invite as used from its trust stream alone. laptop's TUI asks to join as an admin and waits with a code; the main device's TUI shows the request with the same code; once approved there, laptop's wait ends by itself. The main device's TUI fetches phone's Data and checks it (trusted, vouched for by /tu), lists laptop's QUIC link as carrying /tu, and removes phone with the main-key passphrase typed into its own prompt: a new version, phone listed as removed on the main device and the new version held by phone's TUI. Its event log tells each change. The screens are written to `<run dir>/tui/*.txt` (`--keep`). |

## Touchpoints

After the run the harness prints, for each scenario and step, the human inputs
the step needed and the concepts it brought up (for example `root
passphrase`, `24 recovery words`, `invite link`, `--old-root
destroyed|compromised choice (destroyed)`, `device name (phone)`,
`requested role (admin)`, `verification code (compared with the requesting
device's)`, `reason for the denial`, `relay config: [[route]] /lc -> root`).
These are worked out from each step's commands (tool, subcommand, flags,
positional arguments, secret environment) and from the config settings that
changed since a daemon's last start, not written by hand (`step.rs`,
`classify`). The same data, with each step's status and duration, is in
`report.json` in the run directory; use `--keep` to keep it.

## Layout

| File | What |
|---|---|
| `src/main.rs` | Arguments, build, namespace entry, summary, touchpoints, `report.json`. |
| `src/run.rs` | Running a command with a deadline; long-lived processes stopped on drop. |
| `src/world.rs` | Nodes, their generated `ndn-fwd.toml`, daemons, held versions, certificates and their issuers. |
| `src/step.rs` | Steps, failure reports and touchpoint classification. |
| `src/shim.rs` | The tampering UDP shim. |
| `src/nat.rs` | NAT boxes: nested network namespaces, nftables cone or symmetric NAT, cutting two boxes apart. |
| `src/scenarios/` | One file per scenario, plus shared steps. |
