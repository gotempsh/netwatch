---
title: Development
description: Build netwatch from source, run the tests and the end-to-end test, and work on the UI against demo data.
---

## Layout

- `netwatch/`: the daemon and CLI (Rust, tokio, axum, rusqlite).
- `netwatch-common/`: types shared by the daemon and the eBPF programs.
- `netwatch-ebpf/`: the XDP, TC and tracepoint programs (Rust, [aya](https://github.com/aya-rs/aya)).
- `ui/`: the web UI (React, Vite), embedded into the binary at compile time.
- `site/`: these docs.
- `scripts/`: the installer, GeoIP updater, systemd units and the end-to-end test.

## Build

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

npm --prefix ui ci && npm --prefix ui run build
cargo build --release
```

On macOS the eBPF toolchain isn't needed.

## Tests

```shell
cargo test -p netwatch
sudo scripts/e2e-netns.sh        # veth + network namespace: scan, SSH brute force, approve, drop, unban, flows, DNS, owners
```

The end-to-end test brings up a throwaway sshd on port 2222 as its own systemd unit, so a netwatch service already running on the host doesn't see the test's SSH failures. `sudo IMAGE=ghcr.io/gotempsh/netwatch:latest scripts/e2e-netns.sh` runs it against the container image.

On macOS, `cargo test -p netwatch` needs no root: it includes the sensor's packet-level tests and reads this machine's sockets and interfaces.

## UI

```shell
npm --prefix ui run dev:mock     # against built-in demo data, no daemon needed
npm --prefix ui run dev          # against a local daemon on :9180
```

The demo data in `ui/src/api/mock.ts` is what the screenshots in these docs show, and what the [live demo](/demo/) runs on. Its addresses come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32), so no real host appears in a screenshot; keep new demo data in them too.

## Docs

```shell
npm --prefix site ci
npm --prefix site run dev        # http://127.0.0.1:4321, rebuilds on change
npm --prefix ui run build:demo   # the live demo, into site/dist/demo/
```

The demo is the UI built with `--mode demo`: mock data, no API calls, and a banner on every page saying so. The UI uses hash routes (`demo/#/threats/sources`), so deep links and refreshes work on GitHub Pages with no fallback page. Build it after the site: the site build empties `site/dist/`, and so does each rebuild of `run dev`.

Pages are Markdown in `site/content/`. Each one is also published as `<page>.md`, and `llms.txt` and `llms-full.txt` list them for agents.

## Contributing

[CONTRIBUTING.md](https://github.com/gotempsh/netwatch/blob/main/CONTRIBUTING.md) lists the checks CI runs, the commit format and how to file a bug. Report security problems as [SECURITY.md](https://github.com/gotempsh/netwatch/blob/main/SECURITY.md) describes, not in a public issue.

## License

The userspace code is MIT or Apache-2.0, at your option. The eBPF code is GPL-2.0, MIT or Apache-2.0, at your option. See the `LICENSE-*` files.
