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

XDP attaches in native driver mode when the NIC supports it, and falls back to generic mode otherwise. On some drivers (igb, ixgbe, …) attaching resets the link for about 3 seconds.

### Verify the download

Each release has `SHA256SUMS`, which the install script checks, and a build provenance attestation, which shows that an archive was built by this repository's release workflow:

```shell
gh attestation verify netwatch-linux-x86_64.tar.gz -R gotempsh/netwatch
```

### GeoIP databases

To use MaxMind GeoLite2 instead of DB-IP, point `geoip_city` and `geoip_asn` in the [configuration](/configuration) at those `.mmdb` files. Changed files are reloaded automatically.

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

You need a Rust toolchain (stable, plus nightly with `rust-src`), [`bpf-linker`](https://github.com/aya-rs/bpf-linker), and Node 20 or newer to build the UI:

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
