---
title: Installation
description: Install netwatch from a release on Linux, run the container image, install it on macOS, or build it from source.
---

## Requirements

- **Linux 5.8 or newer**, x86_64 or aarch64, with glibc 2.35 or newer (Debian 12, Ubuntu 22.04, RHEL 10 or newer). Linux 6.6 or newer attaches the TC programs with TCX; older kernels use a clsact qdisc.
- **Root.** netwatch loads eBPF programs and reads every process's sockets.
- Or **macOS** on Apple Silicon or Intel. See [macOS](/macos).

## Install script

On Linux and macOS:

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
```

The script picks the release archive for your OS and architecture, checks it against the release's `SHA256SUMS`, and installs it with `sudo`: a systemd service on Linux, a launchd daemon on macOS. Running it again upgrades netwatch and keeps your configuration.

To install a specific release:

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh | NETWATCH_VERSION=v0.1.0 sh
```

The script is [`scripts/get.sh`](https://github.com/gotempsh/netwatch/blob/main/scripts/get.sh) in the repository. To read it before running it:

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh -o install.sh
less install.sh
sh install.sh
```

## Updating

From 0.1.3, netwatch updates itself from the latest release:

```shell
netwatch update --check          # is there a newer release? (no root)
sudo netwatch update             # install it and restart the daemon
sudo netwatch update --auto on   # install new releases daily
```

`netwatch update` downloads the release archive for your machine and checks it against the release's `SHA256SUMS`. It also runs the new binary once before changing anything. Then it installs the archive with that release's own installer, which updates the systemd units or launchd jobs too. If the new daemon doesn't answer on the API with its version within a minute, the previous binary goes back in place and the error says why. The previous binary stays at `/usr/local/bin/netwatch.previous`; `sudo netwatch uninstall` on macOS removes it with the rest. While an update runs, `--auto` and `uninstall` refuse with `another netwatch update is running`. A daemon stopped with `sudo netwatch stop` isn't updated, since installing would start it again; the daily job tries again once it is started.

`--auto on` runs `netwatch update` once a day: from the `netwatch-update.timer` systemd timer on Linux (`journalctl -u netwatch-update` shows what it did), and from the `dev.netwatch.update` launchd job on macOS (logging to `/var/log/netwatch.log`). `--auto off` stops it. Automatic updates are off by default. Release candidates (`v0.2.0-rc.1`) are never installed this way.

It only updates an install the script above made. For the container, pull the new image instead. For a build from source, rebuild. Running the install script again also upgrades, including from 0.1.2 or older.

## Linux, by hand

Download the archive for your architecture (`x86_64` or `aarch64`), unpack it and run its installer:

```shell
curl -fsSLO https://github.com/gotempsh/netwatch/releases/latest/download/netwatch-linux-x86_64.tar.gz
tar xzf netwatch-linux-x86_64.tar.gz
sudo netwatch-linux-x86_64/scripts/install.sh
```

The installer (the install script runs the same one):

- copies the binary to `/usr/local/bin`;
- writes `/etc/netwatch/netwatch.toml` (only if it doesn't exist), with `interface = "auto"`: the interface that carries the default route;
- downloads the free [DB-IP Lite](https://db-ip.com/db/lite.php) city and ASN databases (CC BY 4.0) and enables a monthly timer that refreshes them;
- starts `netwatch.service` in **observe** mode.

Check that it's running:

```shell
systemctl status netwatch
netwatch status
```

`netwatch status` lists what needs attention first. If it says *Connection tracking is off*, the kernel refused the flow programs; [Connection tracking](/connections#when-the-kernel-refuses-the-programs) says what to do.

XDP attaches in native driver mode when the NIC supports it, and falls back to generic mode (shown as `skb`) otherwise. On some drivers (igb, ixgbe, …) attaching resets the link for about 3 seconds.

### Verify the download

Each release has `SHA256SUMS`, which the install script checks, and a build provenance attestation, which shows that an archive was built by this repository's release workflow:

```shell
gh attestation verify netwatch-linux-x86_64.tar.gz -R gotempsh/netwatch
```

[Security and privacy](/security#verify-a-download) shows the full check, including the tag and commit an archive was built from.

### GeoIP databases

To use MaxMind GeoLite2 instead of DB-IP, point `geoip_city` and `geoip_asn` in the [configuration](/configuration) at those `.mmdb` files. Changed files are reloaded automatically.

## Uninstalling

On Linux, stop the service and its timers, then remove what the installer wrote:

```shell
sudo systemctl disable --now netwatch.service netwatch-update.timer netwatch-update-geoip.timer
sudo rm -f /etc/systemd/system/netwatch*.service /etc/systemd/system/netwatch*.timer
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/netwatch /usr/local/bin/netwatch.previous /usr/local/bin/netwatch-update-geoip
```

Stopping the service detaches the XDP and TC programs, so traffic is no longer counted or dropped. To also delete the configuration, the database (history, bans, proposals) and the GeoIP databases:

```shell
sudo rm -rf /etc/netwatch /var/lib/netwatch
```

If you installed the agent skill with `netwatch skill --install`, remove `~/.claude/skills/netwatch` too (or `netwatch` in the directory you passed with `--dir`). On macOS, `sudo netwatch uninstall` stops and removes the daemon and the binaries, and `--purge` also deletes the configuration, the database and the log; see [macOS](/macos).

## Docker

```shell
docker run -d --name netwatch --restart unless-stopped --stop-timeout 30 \
  --network host --pid host --privileged \
  -v netwatch-data:/var/lib/netwatch -v /run/netwatch:/run/netwatch \
  ghcr.io/gotempsh/netwatch:latest
```

The image is multi-arch (`linux/amd64`, `linux/arm64`). [Docker](/docker) explains each flag and how to configure it.

## macOS

The [install script](#install-script) works on macOS too. [macOS](/macos) covers installing by hand and what differs from Linux.

## From source

You need a Rust toolchain (stable, plus nightly with `rust-src`), [`bpf-linker`](https://github.com/aya-rs/bpf-linker), and Node 22.12 or newer (or 20.19 or newer on Node 20) to build the UI:

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker            # or use a prebuilt release

npm --prefix ui ci && npm --prefix ui run build   # the UI is embedded at compile time
cargo build --release
sudo scripts/install.sh
```

On macOS no eBPF toolchain is needed: build the UI, `cargo build --release`, then `sudo target/release/netwatch install`.

## Next

Continue with the [Quick start](/quick-start) to open the UI and approve your first ban.
