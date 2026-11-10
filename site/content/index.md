---
title: Introduction
nav: Introduction
description: netwatch is a single-binary traffic monitor for Linux servers and macOS. It shows every connection with the process behind it, flags attackers, and proposes bans you approve.
---

**[Try the live demo](/demo/)**: the same web UI on demo data, in your browser. Nothing to install and no server behind it.

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
npx skills add gotempsh/netwatch     # the agent skill
```

Or let your coding agent set it up:

<!-- copy-prompt -->

netwatch counts every packet in the kernel with eBPF/XDP and records every connection with the process or container behind it. It flags port scans, brute force, floods and listed attackers, and proposes bans that you approve, or enforces them at XDP speed. It starts in **observe** mode: it watches and proposes, and blocks nothing until you approve.

```mermaid
flowchart LR
  accTitle: Where netwatch sits
  accDescr: Packets from the internet reach the server, where netwatch's kernel programs count them and track each flow. The daemon scores the sources, proposes bans for you to approve, and serves the web UI and CLI on the server itself.
  net("Internet") -- "packets" --> kernel("Kernel<br/>XDP and TC programs")
  kernel -- "flows, owners,<br/>SSH logins" --> daemon("netwatch daemon")
  daemon -- "bans you approve" --> kernel
  daemon --> ui("Web UI and CLI<br/>on 127.0.0.1")
  daemon --> slack("Slack alerts")
```

It runs as root and sees all your traffic, so [Security and privacy](/security) lists what it does with that: every request it makes to the internet, what it stores, and how to verify a release. [Compared to other tools](/comparison) sets it next to fail2ban, CrowdSec, ntopng, Suricata, OpenSnitch and Little Snitch.

## Get started

<!-- cards -->
- [**Installation** Linux release, Docker image, macOS, or from source.](/installation)
- [**Quick start** Open the UI, read the first insights, approve a ban.](/quick-start)
- [**The web UI** A tour of every page, with screenshots.](/web-ui)
- [**Live demo** Click through the web UI on demo data, no install.](/demo/)
- [**CLI reference** Every command and its options.](/cli)
- [**Security and privacy** What runs as root, what leaves the machine, what is stored.](/security)
- [**Compared to other tools** fail2ban, CrowdSec, ntopng, Suricata, OpenSnitch, Little Snitch.](/comparison)

## See it

<!-- steps -->

### Open the overview

Live packets, SYNs and drops, flagged sources, bans, pending proposals and SSH failures, with the insights that need you and the command that acts on each.

![Overview: live rates, active bans, pending proposals and insights](/screenshots/overview.png)

### Find who is probing you

Every address that sent traffic, scored 0–100 for what it did: port scans, SSH brute force, exploit requests, threat-feed listings. Open one to see why it scored what it did and every port it touched.

![Sources: addresses with their score, findings, country and network](/screenshots/sources.png)

### See what talks to what

Every connection in and out, with the process or container that owns it, the DNS name or TLS SNI of the other side, bytes each way, TCP state and latency.

![Connections: flows with their owning process, remote name, bytes and state](/screenshots/connections.png)

### Follow the logins

Failed passwords, invalid users and successful logins from sshd and Tailscale SSH, with the addresses that failed most. A login after failures, or from a network not seen in 90 days, is flagged.

![SSH: login events and the addresses that failed most](/screenshots/ssh.png)

### Approve the bans

In observe mode every ban is a proposal with its reason, confidence and the command that applies it. Approve it with `sudo netwatch approve <id>`, or switch to enforce mode once the proposals look right.

![Bans and proposals: active bans with dropped packets, and proposals waiting for approval](/screenshots/bans.png)

<!-- /steps -->

[The web UI](/web-ui) goes through every page, with the command that gives the same view in a terminal.

## What you get

- **Counts traffic in the kernel.** Packets, bytes, SYNs, UDP and ICMP per source, plus every local port each source touches. The XDP program fails open: it only drops sources you banned.
- **Records every connection.** On the host, Tailscale, WireGuard and Docker interfaces: who connected to whom, bytes and rates, TCP state and latency, the owning process with its systemd service or container, TLS SNI, HTTP host, SSH banners and the DNS name the address came from.
- **Detects attacks.** Port scans, probes of services that should never be public, brute force, floods, threat-feed matches and about 60 known exploit requests. Each source gets a 0–100 score.
- **Follows SSH logins.** Password guessing, invalid users, a login after failures and logins from a country or network not seen in 90 days.
- **Proposes or enforces bans.** Observe mode turns every ban into a proposal you approve. Enforce mode bans automatically with escalating TTLs. Infrastructure you depend on (gateway, VPN peers, Cloudflare) is never banned.
- **Explains itself.** Insights turn the data into concrete advice, each with the command that fixes it.
- **Optionally uses a model.** Any OpenAI-compatible endpoint, local or hosted, reviews the sources the rules can't settle and compiles ban policies written in plain English. It is built for cheap models and small token budgets.
- **Works with your coding agent.** `netwatch skill --install` teaches Claude Code, Codex, Cursor and other agents to investigate with netwatch and to ask before banning anything. See [AI agents](/agents).
- **Stays on the host.** The web UI and API are read-only and listen only on `127.0.0.1`; every change goes through `sudo netwatch` and a root-only socket.

## How it fits together

```mermaid
flowchart TB
  wan(["eno1: incoming packets"]) --> xdp
  ifaces(["eno1, tailscale0, docker0, br-*"]) --> tc
  stack(["TCP stack"]) --> tp

  subgraph kernel ["Kernel (eBPF)"]
    xdp["<b>XDP</b><br/>per-source and per-port counters<br/>allow and block LPM tries<br/>drops only banned sources"]
    tc["<b>TC ingress and egress</b><br/>flow table, first payload<br/>per direction, DNS<br/>never drops"]
    tp["<b>Tracepoints</b><br/>TCP state changes with pid and comm<br/>retransmits, resets"]
  end

  kernel -- "maps and ring buffers" --> daemon
  daemon -- "block and allow" --> xdp

  journald(["journald: SSH logins"]) --> daemon
  feeds(["threat feeds"]) --> daemon
  geo(["mmdb geo databases"]) --> daemon
  cli(["sudo netwatch ban, approve, …<br/>root-only Unix socket"]) --> daemon

  daemon["<b>netwatch daemon</b><br/>flows and their owners (/proc, Docker)<br/>findings, scoring, policy, proposals<br/>SQLite history, optional LLM"]
  daemon --> api(["http://127.0.0.1:9180<br/>GET-only API and embedded web UI"])
```

The daemon is one Rust binary with the eBPF programs and the web UI embedded. State lives in a single SQLite file. On macOS the same daemon captures from `/dev/bpf` and bans with pf instead.

## For agents

Every page is also plain Markdown at its address with `.md` in place of the trailing slash (`/installation/` is `/installation.md`; this page's is [`/index.md`](/index.md)), or use **Copy page** at the top. [`/llms.txt`](/llms.txt) lists every page and [`/llms-full.txt`](/llms-full.txt) holds them all in one file.

The [agent skill](/cli#agent-skill) teaches a coding agent which command answers which question, how to read scores, and to ask before banning anything.
