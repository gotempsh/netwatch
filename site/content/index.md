---
title: Introduction
nav: Introduction
description: netwatch is a single-binary traffic monitor for Linux servers and macOS. It shows every connection with the process behind it, flags attackers, and proposes bans you approve.
---

netwatch counts every packet in the kernel with eBPF/XDP and keeps a record of every connection, together with the process or container behind it. It flags port scans, brute force, floods and listed attackers, and proposes bans that you approve, or enforces them at XDP speed. You browse everything in a read-only web UI that listens only on `127.0.0.1`, or from the command line.

![Overview: live rates, active bans, pending proposals and insights](/screenshots/overview.png "The Overview page. Screenshots in these docs use the UI's built-in demo data.")

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
```

That installs a systemd service (a launchd daemon on macOS) in **observe** mode: it watches and proposes, and blocks nothing until you approve. [Installation](/installation) covers Docker, macOS and building from source.

## What it does

- **Counts traffic in the kernel.** Packets, bytes, SYNs, UDP and ICMP per source, plus every local port each source touches. The XDP program fails open: it only drops sources you banned.
- **Records every connection.** On the host, Tailscale, WireGuard and Docker interfaces: who connected to whom, bytes and rates, TCP state and latency, the owning process with its systemd service or container, TLS SNI, HTTP host, SSH banners and the DNS name the address came from.
- **Detects attacks.** Port scans, probes of services that should never be public, brute force, floods, threat-feed matches and about 60 known exploit requests. Each source gets a 0–100 score.
- **Follows SSH logins.** Password guessing, invalid users, a login after failures and logins from a country or network not seen in 90 days.
- **Proposes or enforces bans.** Observe mode turns every ban into a proposal you approve. Enforce mode bans automatically with escalating TTLs. Infrastructure you depend on (gateway, VPN peers, Cloudflare) is never banned.
- **Explains itself.** Insights turn the data into concrete advice, each with the command that fixes it.
- **Optionally uses a model.** Any OpenAI-compatible endpoint, local or hosted, reviews the sources the rules can't settle and compiles ban policies written in plain English. It is built for cheap models and small token budgets.

## How it works

```text
                     ┌───────────────── kernel ─────────────────┐
 eno1 ──────packets──▶ XDP: per-source + per-port counters,      │──▶ PASS (always, unless banned)
                     │      allow/block LPM tries                │
 eno1, tailscale0, ──▶ TC ingress/egress: flow table, first      │──▶ next (never drops)
 docker0, br-*       │      payload per direction, DNS           │
 TCP stack ──────────▶ tracepoints: state changes (pid, comm),   │
                     │      retransmits, resets                  │
                     └────────┬─────────────────────▲────────────┘
                   maps / ring buffers               │ block / allow
                     ┌────────▼─────────────────────┴────────────┐
 journald (ssh) ─────▶ netwatch daemon: flows + owners (/proc,    │◀── sudo netwatch ban/approve/…
 threat feeds  ──────▶ Docker), findings, scoring, policy,        │    (root-only Unix socket)
 mmdb geo      ──────▶ proposals, SQLite history, optional LLM    │
                     └────────┬──────────────────────────────────┘
                              ▼
                http://127.0.0.1:9180  (GET-only API + embedded web UI)
```

The daemon is one Rust binary with the eBPF programs and the web UI embedded. State lives in a single SQLite file. On macOS the same daemon captures from `/dev/bpf` and bans with pf instead.

## Where to next

<!-- cards -->
- [**Installation** Linux release, Docker image, macOS, or from source.](/installation)
- [**Quick start** Open the UI, read the first insights, approve a ban.](/quick-start)
- [**The web UI** A tour of every page, with screenshots.](/web-ui)
- [**CLI reference** Every command and its options.](/cli)
