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
cargo run -p ndn-e2e                        # every scenario, ~2 minutes
cargo run -p ndn-e2e -- --only negatives    # one scenario (repeatable, or a,b)
cargo run -p ndn-e2e -- --keep              # keep configs, PIBs, logs, report.json
cargo run -p ndn-e2e -- --list
```

It first runs `cargo build -p ndn-fwd -p ndn-tools -p ndn-fwd-tokens --bins`
(a stale binary would witness old behaviour) and takes the binaries from the
workspace's cargo target directory (`cargo metadata` → `target_directory`,
`debug/`). `--no-build` skips the build; `--bin-dir <dir>` uses other
binaries.

The crate is a workspace member but not a default member, so `cargo build` and
`cargo test` in ndn-fwd never build or run it.

Exit status: 0 when every step passed, 1 when a step failed, 2 when the
harness could not run.

## Prerequisites

- Linux with unprivileged user namespaces (`unshare --map-root-user --net
  --pid --fork true` must work).
- `unshare`, `setpriv` (util-linux) and `ip` (iproute2) on `PATH`; on NixOS
  without them: `nix-shell -p util-linux iproute2`.
- For the "another local user" steps: subordinate uids for your user
  (`/etc/subuid`) and `newuidmap`, so `unshare --map-auto` can map uid 1.
  Without them those two steps are reported SKIP with the reason.

No root, no change to the host's network, no fixed ports on the host.

## How it runs

The outer process starts `unshare --map-auto --map-root-user --net --pid
--fork --kill-child` running itself again as PID 1 of a new user, network
and PID namespace. Inside, `lo` carries 10.200.0.1-6/24. Those are not
loopback addresses (faces to 127.0.0.1 are local and skip validation), so
every link between daemons is a non-local UDP face and every Data is
validated. Daemons and producers are stopped after each scenario; when the
inner process exits for any reason (including a panic or a kill), the kernel
kills every process left in the PID namespace. Ctrl-C kills `unshare`, which
SIGKILLs the namespace. The run directory (`$TMPDIR/ndn-e2e-*`) is removed
unless `--keep` is set.

Inside the user namespace the daemons run as uid 0 (your uid, mapped). The
"another local user" steps run the CLI as uid 1 through `setpriv --reuid=1
--regid=1 --clear-groups`; the daemon's peer-credential check sees a uid
that is neither its own, root, nor in `trust_admin_groups`.

Each step prints PASS/FAIL with its duration. A failing step prints its
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
| `negatives` | Mistyped and swapped words (variants whose BIP39 checksum fails) are refused by `recovery-kit check` and `recover`, and `recover` writes no root store and leaves the held contexts unchanged; the same for a wrong kit passphrase and for a revoked kit with the right passphrase. An invite carrying another namespace's fingerprint, a used invite and an expired invite are refused and leave no certificate. Data signed under the member's name by an unenrolled key is refused at once (`ndn-peek` exits 3 with `refused: unverifiable`: the root's certificate fetch is answered NoRoute, so the certificate is known absent); Data with one byte flipped in transit by a UDP shim is refused at once (`ndn-peek` exits 3 with `refused: bad-signature`; the shim must have flipped something). Another local user is refused `ndn-ctl route add` and `ndn-fwd adopt`. Each refusal has a control under the same setup that succeeds: the right words or passphrase, an unused invite, enrolled Data, the shim not tampering, the operator's own command. |

## Touchpoints

After the run the harness prints, for each scenario and step, the human inputs
the step needed and the concepts it brought up (for example `root
passphrase`, `24 recovery words`, `invite link`, `--old-root
destroyed|compromised choice (destroyed)`, `device name (phone)`,
`relay config: [[route]] /lc -> root`). These are worked out from each step's
commands (tool, subcommand, flags, positional arguments, secret environment)
and from the config settings that changed since a daemon's last start, not
written by hand (`step.rs`, `classify`). The same data, with each step's
status and duration, is in `report.json` in the run directory; use `--keep`
to keep it.

## Layout

| File | What |
|---|---|
| `src/main.rs` | Arguments, build, namespace entry, summary, touchpoints, `report.json`. |
| `src/run.rs` | Running a command with a deadline; long-lived processes stopped on drop. |
| `src/world.rs` | Nodes, their generated `ndn-fwd.toml`, daemons, held versions, certificates and their issuers. |
| `src/step.rs` | Steps, failure reports and touchpoint classification. |
| `src/shim.rs` | The tampering UDP shim. |
| `src/scenarios/` | One file per scenario, plus shared steps. |
