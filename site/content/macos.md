---
title: macOS
description: The same daemon, UI, CLI, detection and ban policy on macOS, capturing with /dev/bpf and banning with pf.
---

The same binary, UI, CLI, detection and ban policy run on macOS (developed on macOS 27, Apple Silicon). Only the layer under them differs.

## Install

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
```

Or by hand, with `x86_64` instead of `arm64` on an Intel Mac:

```shell
curl -fsSLO https://github.com/gotempsh/netwatch/releases/latest/download/netwatch-macos-arm64.tar.gz
tar xzf netwatch-macos-arm64.tar.gz
sudo netwatch-macos-arm64/netwatch install
```

The binary isn't notarized yet. `curl` doesn't mark it as downloaded, so Gatekeeper lets it run. A copy downloaded with a browser needs `xattr -d com.apple.quarantine netwatch` first.

`netwatch install`, which the install script runs:

- copies the binary to `/usr/local/bin/netwatch`;
- writes `/etc/netwatch/netwatch.toml` if it doesn't exist;
- downloads the DB-IP Lite databases into `/var/db/netwatch` and schedules `netwatch update-geoip` monthly;
- starts the launchd daemon `dev.netwatch` in observe mode, logging to `/var/log/netwatch.log`.

Then open [http://127.0.0.1:9180](http://127.0.0.1:9180).

`sudo netwatch uninstall` stops and removes it; add `--purge` to delete the config, database and log too.

Secrets go in `/etc/netwatch/env` (`NETWATCH_SLACK_WEBHOOK=...`), which the daemon reads at startup because launchd has no environment file. After editing the config or that file, restart the daemon with `sudo launchctl kickstart -k system/dev.netwatch`. If the CLI says nothing answers at `127.0.0.1:9180`, `sudo launchctl print system/dev.netwatch` shows whether launchd is running it, and `/var/log/netwatch.log` shows why it stopped.

## What differs from Linux

| | Linux | macOS |
|---|---|---|
| Per-source accounting, flows, payload samples | XDP and TC programs | `/dev/bpf` capture threads, one per interface, feeding the same logic in userspace |
| TCP states, connect latency, failed connects | TCP tracepoints | read from the TCP flags on the wire |
| Which process opened a connection | tracepoint pid/comm, `/proc` scan | the capture header (macOS names the sending process of outgoing packets), libproc scan |
| Retransmits | `tcp_retransmit_skb` | the capture header's retransmit flag (our own retransmits only) |
| Bans | XDP drop | pf table in the anchor `com.apple/netwatch` |
| SSH logins | journald | the unified log (`log stream`) |
| Service | systemd | launchd |

- **Defaults.** `interface = "auto"` is the default-route interface, usually `en0`. Flows are also recorded on `utun*` (Tailscale, WireGuard and other VPNs) and `bridge*` (UTM, Lima and other VMs). Docker Desktop runs its containers in a VM, so they show up as one bridged VM, not per container.
- **Bans.** The stock `/etc/pf.conf` evaluates `anchor "com.apple/*"`, so bans work without editing it. netwatch enables pf with a reference token, and removes its rules and releases pf when it stops, so bans only hold while it runs, as with XDP. With a custom `pf.conf` that lacks that anchor, add `anchor "com.apple/netwatch"` to it and reload pf with `sudo pfctl -f /etc/pf.conf`. Until you do, the sensor reports `capture+pf-unreferenced`, and the UI shows bans as counted, not dropped. netwatch reads the ruleset again every minute, so it notices the fix without a restart.
- **Capture cost.** Capture happens in userspace, so CPU use grows with traffic. That's fine for a workstation or a small server; it isn't line rate like XDP. Packets are cut at about 1.2 KB, and the log warns if the kernel drops captures.
- **Linux-only settings.** `xdp_mode`, `drop_syn_ip_options` and the CVE-2026-98432 alerts (a Linux TCP bug) don't apply. `ssh_units` is replaced by the unified log.
- **SSH.** SSH alerts need Remote Login (System Settings › General › Sharing). Without it, the "sshd accepts passwords" check is skipped.
- **Tailscale and WireGuard peers.** They are read from tailscaled's socket (`/var/run/tailscaled.socket`, the Homebrew or open-source tailscaled) or the Tailscale app's bundled CLI, and from wireguard-go's sockets in `/var/run/wireguard` (`wg-quick` from Homebrew). The WireGuard app from the App Store runs its tunnels in a network extension that netwatch can't ask, so add its endpoints with `sudo netwatch allow`.
- **Paths.** Data lives in `/var/db/netwatch` and sockets in `/var/run/netwatch`.

## Replaying a capture

`NETWATCH_PCAP=capture.pcap netwatch run` replays a capture file through the whole pipeline instead of capturing, without root. It is useful for testing rules: point `db_path` and the sockets at a scratch directory. It reads classic pcap files; convert a Wireshark pcapng first with `tcpdump -r in.pcapng -w out.pcap`. A capture cut short at the end is read up to its last whole packet.
