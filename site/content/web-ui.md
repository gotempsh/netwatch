---
title: The web UI
nav: The web UI
description: A tour of every page in the web UI, what it shows and the command that gives the same view in a terminal.
---

The UI is built into the binary and served with the API on `127.0.0.1:9180`. It is read-only: it can't ban, approve or change settings, so exposing it through a tunnel can't change anything on the host. Every page refreshes on its own, follows your system's light or dark theme, and works on a phone.

> The screenshots on this page use the UI's built-in demo data, not a real host. To click through the same demo without installing anything, run `npm --prefix ui ci && npm --prefix ui run dev:mock` in a checkout.

## Overview

The state of the host at a glance: the attached interface and mode, live inbound packets, SYNs and drops, flagged sources, active bans, pending proposals and SSH failures, with 30-minute charts. Below them are the insights, each with the command that acts on it, and a summary of the host's connections.

![Overview](/screenshots/overview.png)

Terminal: `netwatch status`.

## Sources

Every address that sent traffic, scored 0–100. Each row shows what it did (port scan, SSH brute force, threat feed, …), its country and network, its traffic, and whether it's banned, allowlisted or on a threat feed. Search by address, country or ASN, and sort by score, SYNs, bytes or ports touched.

![Sources](/screenshots/sources.png)

Terminal: `netwatch sources --flagged` (alias `netwatch top`).

## Source detail

One address in full: why it scored what it did, which feeds list it and the matching range, its ban and the command that lifts it, its traffic counters, the ports it touched (and which hit a listening service), its SSH events, alerts and proposals, and seven days of hourly history.

![Source detail](/screenshots/source-detail.png)

Terminal: `netwatch ip 218.92.0.112`.

## Connections

Every flow on the monitored interfaces, live or from history. For each one: direction, the process or container that owns it, the DNS name or TLS SNI of the other side, bytes and rates each way, TCP state, connect latency and retransmits. The summary above it shows active flows, failed connects, and the top remotes, processes, services and countries.

![Connections](/screenshots/connections.png)

The **Destinations** tab lists every address the host and its containers connected out to, one row per address, with the processes that reached it.

Terminal: `netwatch flows`, or `netwatch flows --history --window 24h`.

## DNS

Every DNS query seen on the wire, with the client, the server, the answer, the response code and the latency. Next to it, the most-queried names with their NXDOMAIN counts, which is where misconfigured clients and malware beacons stand out.

![DNS](/screenshots/dns.png)

Terminal: `netwatch dns`, `netwatch dns --top`, `netwatch dns --rcode NXDOMAIN`.

## Network

**Interfaces** shows every interface with its addresses, throughput, and what netwatch attached to it: XDP for accounting and bans, TC programs for flows. It also lists the kernel programs and tracepoints that loaded and the flow settings in effect.

![Interfaces](/screenshots/interfaces.png)

**Listeners** shows every listening socket, which process or container owns it, and whether it's exposed on a public or wildcard address or bound to loopback only.

![Listeners](/screenshots/listeners.png)

Terminal: `netwatch ifaces`, `netwatch listeners`.

## Alerts

Findings over time: port scans, brute force, floods, threat-feed matches, probes of sensitive ports and exploit attempts, each with its score, source, location, a summary and how many times it fired.

![Alerts](/screenshots/alerts.png)

Terminal: `netwatch alerts`.

## SSH

SSH events from sshd and Tailscale SSH: failed passwords, invalid users, pre-auth disconnects and successful logins, with the addresses that failed most on the left.

![SSH](/screenshots/ssh.png)

Terminal: `netwatch ssh`.

## Bans & proposals

Active bans with their reason, who applied them, when they expire and how many packets they dropped. Pending proposals show who proposed them (the rules or the model), the confidence, the reason and the command that applies them. The number next to the tab is the count of proposals waiting.

![Bans and proposals](/screenshots/bans.png)

Terminal: `netwatch bans`, `netwatch proposals`, then `sudo netwatch approve <id>`.

## Geography

Sources grouped by country and by network (ASN), the ports they hit and the sources with the highest score over the last day or week.

![Geography](/screenshots/geo.png)

Terminal: `netwatch geo 1.1.1.1` looks up one address offline.

## Policy & AI

The ban policy in effect: your rules written in plain English, the structured rules they compiled to, and the built-in defaults. If a model is configured, the page also shows its recent runs, the tokens they used and what they proposed.

![Policy and AI](/screenshots/policy.png)

Terminal: `netwatch policy show`. See [Bans and policy](/bans-and-policy) and [AI analysis](/ai-analysis).
