# Contributing to netwatch

Bug reports, fixes, detection rules and docs are all welcome. For a bug, open an issue with the template; it asks for what we need to reproduce it. For a larger change (a new finding, a new page, a new config option), open an issue first so we can agree on the shape before you write it.

Security problems don't go in issues: see [SECURITY.md](SECURITY.md).

## Layout

- `netwatch/`: the daemon and CLI (Rust, tokio, axum, rusqlite).
- `netwatch-common/`: types shared by the daemon and the eBPF programs.
- `netwatch-ebpf/`: the XDP, TC and tracepoint programs (Rust, [aya](https://github.com/aya-rs/aya)).
- `ui/`: the web UI (React, Vite), embedded into the binary at compile time.
- `site/`: the [documentation site](https://gotempsh.github.io/netwatch/).
- `skills/netwatch/SKILL.md`: the agent skill, embedded into the binary for `netwatch skill --install`.
- `scripts/`: the installers, GeoIP updater, systemd units and the end-to-end test.

## Build

On Linux you need a Rust toolchain (stable, and nightly with `rust-src`), [`bpf-linker`](https://github.com/aya-rs/bpf-linker) and Node 20 or newer:

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

npm --prefix ui ci && npm --prefix ui run build   # the UI is embedded at compile time
cargo build --release
```

On macOS the eBPF toolchain isn't needed; the same `npm` and `cargo` commands build it.

## Checks

CI runs these on every pull request. Run them before you push:

```shell
npm --prefix ui ci && npm --prefix ui run build   # type-checks and builds the UI
cargo fmt --check -p netwatch
cargo clippy -p netwatch --all-targets -- -D warnings
cargo test -p netwatch
```

On Linux, `cargo test` and `cargo run` go through `sudo -E` (see `.cargo/config.toml`), because loading eBPF programs needs root. On macOS, `cargo test -p netwatch` needs no root: it includes the sensor's packet-level tests and reads this machine's sockets and interfaces. CI runs clippy and the tests on both.

The end-to-end test needs Linux and root. It sets up a veth pair and a network namespace, then runs a port scan, SSH brute force, approve, drop, unban, flows, DNS and owners against a real daemon:

```shell
sudo scripts/e2e-netns.sh
sudo IMAGE=ghcr.io/gotempsh/netwatch:latest scripts/e2e-netns.sh   # against the container image
```

It brings up a throwaway sshd on port 2222 as its own systemd unit, so a netwatch service already running on the host doesn't see the test's SSH failures.

A change in behaviour comes with a test, including any wording a user or script depends on. `NETWATCH_PCAP=capture.pcap netwatch run` replays a capture through the whole pipeline without root, which helps when testing a detection rule; point `db_path` and the sockets at a scratch directory.

## Work on the UI

The UI runs against built-in demo data, with no daemon and no root:

```shell
npm --prefix ui ci
npm --prefix ui run dev:mock     # against the demo data in ui/src/api/mock.ts
npm --prefix ui run dev          # against a local daemon on 127.0.0.1:9180
```

The screenshots in the README and the docs are taken from the demo data, so a new page or column usually needs a demo row too. Check a UI change at laptop and phone widths, in light and dark.

## Docs

A change that a user can see updates its docs in the same pull request:

- `site/content/*.md`, the documentation site;
- `README.md`, where it covers the feature;
- the CLI's `--help`;
- `skills/netwatch/SKILL.md`, when commands or behaviour an agent relies on change. Its tests check that every command it quotes still parses.

To preview the site:

```shell
npm --prefix site ci
npm --prefix site run dev        # http://127.0.0.1:4321, rebuilds on change
```

## Test data and privacy

Fixtures, mock data, docs and commit messages use the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and `example.com`. Don't paste real addresses, hostnames, usernames or logs from your servers; rewrite them, keeping the shape.

## Commits and pull requests

Commit subjects follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `chore:`, with an optional scope (`fix(update): …`). Write the subject as the effect a user sees, not the code that changed:

```text
fix: a stopped Tailscale can no longer hold up startup
feat: export metrics and security events over OpenTelemetry
```

Pull requests are squash-merged, and release notes are generated from their titles, so the title follows the same format. Keep a pull request to one change, and say in its description how you tested it.

## Licence

The code is under three licences, and a contribution is licensed the same way as the code it changes:

| Code | Licence |
|---|---|
| `netwatch-ebpf/` (the eBPF programs loaded into the kernel) | GPL-2.0, MIT or Apache-2.0, at your option |
| Everything else: `netwatch/`, `netwatch-common/`, `ui/`, `site/`, `scripts/` | MIT or Apache-2.0, at your option |

The texts are in [`LICENSE-GPL2`](LICENSE-GPL2), [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). The kernel only lets GPL-compatible eBPF programs use some helpers, which is why the eBPF code also carries GPL-2.0.
