---
title: The web UI
nav: The web UI
description: A tour of every page in the web UI, what it shows and the command that gives the same view in a terminal.
---

The UI is built into the binary and served with the API on `127.0.0.1:9180`. It is read-only: it can't ban, approve or change settings, so exposing it through a tunnel can't change anything on the host. Every page refreshes on its own, follows your system's light or dark theme, and works on a phone.

It has five sections: **Status**, **Threats**, **Traffic**, **Exposure** and **Bans**. Sections with more than one page show them as tabs under the main navigation. The mode chip at the top right says whether netwatch bans on its own (`enforce · auto-ban on`) or only proposes (`observe · auto-ban off`), and adds `dry run` when bans are counted but not dropped (`drop_banned = false`, or macOS without pf).

> The screenshots on this page use the UI's built-in demo data, not a real host. **[Open the live demo](/demo/)** to click through the same data in your browser, without installing anything.

## Status

The page that opens first answers one question: does anything need you? The verdict at the top says **All quiet. Nothing needs you.**, or **Needs you** with the count of things to act on now and to check, and the command for the first one. Below it, each item says what netwatch saw, what it means for the host, a link to the evidence and the command that fixes or investigates it. They come from the daemon's insights, the pending proposals, and programs on this host whose connections to the same address and port failed three or more times in the last 24 hours.

![Status](/screenshots/status.png)

Under the list, three columns:

- **Who is knocking**: flagged sources, bans and SSH logins, with the five highest-scoring sources active in the last 24 hours as a small timeline.
- **Who this host talks to**: internet destinations in the last 24 hours, failing ones first.
- **What the internet can reach**: listening ports bound beyond loopback, and how many sources touched each one in the last 24 hours.

Then inbound packets per second over the last 30 minutes, with SYN bursts marked, and a line about the sensor: where XDP is attached, how many interfaces record flows, the threat feeds, and any tracepoint that failed to attach with what is missing because of it.

If the daemon stops answering, the verdict says so and gives the command that checks the service.

Terminal: `netwatch status`.

## Threats

### Timeline

The flagged sources active in the last 7 days (or 24 hours), one lane each, highest score first, up to 20. A lane shows packets per hour, and marks when a finding was raised, a ban was proposed, the ban started, and any SSH login it got. Above it, the networks with more than one flagged source or a ban. The sentence at the top says how many flagged sources were active in the window, how many are banned, how many have a ban waiting for you, and whether any logged in.

![Threats timeline](/screenshots/threats.png)

### Sources

Every address that sent traffic, scored 0–100. Each row shows what it did (port scan, SSH brute force, threat feed, …), its country and network, its traffic, and whether it's banned, allowlisted or on a threat feed. Search by address, country or ASN (`AS174` matches that network exactly), and sort by score, SYNs, bytes or ports touched. Links from Status can also filter the list to the sources that touched one port.

![Sources](/screenshots/sources.png)

Terminal: `netwatch sources --flagged` (alias `netwatch top`).

### One source

Opening an address tells its story. The verdict says what happened and where it stands (for example "Banned 2d ago for SSH brute force, still trying"), with the next command: approve its pending proposal, ban it, or lift its ban. Three facts follow: whether it ever logged in, what its ban dropped (or matched, in a dry run), and the threat feeds that list it. Then seven days of packets and SYNs per hour with the events on them, and **What it did**: the ports it touched and which had a service listening, its connections and client software, the usernames it tried, and other flagged sources in the same network.

The evidence is folded underneath: its connections, the ports touched, SSH attempts, alerts and proposals, and the raw counters.

![Source detail](/screenshots/source-detail.png)

Terminal: `netwatch ip 192.0.2.12`.

### Alerts

Findings over time: port scans, brute force, floods, threat-feed matches, probes of sensitive ports and exploit attempts, each with its score, source, location, a summary and how many times it fired.

![Alerts](/screenshots/alerts.png)

Terminal: `netwatch alerts`.

### SSH logins

SSH events from sshd and Tailscale SSH: failed passwords, invalid users, pre-auth disconnects and successful logins, with the addresses that failed most on the left.

![SSH logins](/screenshots/ssh.png)

Terminal: `netwatch ssh`.

### Countries & networks

Sources grouped by country and by network (ASN), the ports they hit and the sources with the highest score over the last day or week.

![Countries and networks](/screenshots/geo.png)

Terminal: `netwatch geo 1.1.1.1` looks up one address offline.

## Traffic

### Map

Who talks to whom, with the host in the middle. On the left, who connects in and to which service; on the right, which program on the host connects out and to whom. Line width is bytes. Failing connections are dashed red and say why (refused, timed out, unanswered), and lines from flagged sources are orange. Each column shows up to nine boxes and folds the rest into "N more". Click a box to list its connections under the map; **Table** shows the same lines as a table. The window is 5 minutes, 1 hour or 24 hours.

![Traffic map](/screenshots/map.png)

### Connections

Every flow on the monitored interfaces, live or from history. For each one: direction, the process or container that owns it, the DNS name or TLS SNI of the other side, bytes and rates each way, TCP state, connect latency and retransmits. The summary above it shows active flows, failed connects, and the top remotes, processes, services and countries.

![Connections](/screenshots/connections.png)

Terminal: `netwatch flows`, or `netwatch flows --history --window 24h`.

### Destinations

Every address the host and its containers connected out to, one row per address, with the processes that reached it.

![Destinations](/screenshots/destinations.png)

### DNS

Every DNS query seen on the wire, with the client, the server, the answer, the response code and the latency. Next to it, the most-queried names with their NXDOMAIN counts, which is where misconfigured clients and malware beacons stand out.

![DNS](/screenshots/dns.png)

Terminal: `netwatch dns`, `netwatch dns --top`, `netwatch dns --rcode NXDOMAIN`.

## Exposure

**Listening ports** shows every listening socket, which process or container owns it, and whether it's exposed (bound to any address but loopback, LAN included) or bound to loopback only.

![Listening ports](/screenshots/listeners.png)

**Interfaces & sensor** shows every interface with its addresses, throughput, and what netwatch attached to it: XDP for accounting and bans, TC programs for flows. It also lists the kernel programs and tracepoints that loaded and the flow settings in effect.

![Interfaces and sensor](/screenshots/interfaces.png)

Terminal: `netwatch listeners`, `netwatch ifaces`.

## Bans

### Bans & proposals

Active bans with their reason, who applied them, when they expire and how many packets they dropped. When bans don't drop (a dry run), the column is **Matched, not dropped** and counts the packets that hit the ban and went through. Pending proposals show who proposed them (the rules or the model), the confidence, the reason and the command that applies them. The number next to **Bans** in the navigation is the count of proposals waiting.

![Bans and proposals](/screenshots/bans.png)

Terminal: `netwatch bans`, `netwatch proposals`, then `sudo netwatch approve <id>`.

### Policy & AI

The ban policy in effect: your rules written in plain English, the structured rules they compiled to, and the built-in defaults. If a model is configured, the page also shows its recent runs, the tokens they used and what they proposed.

![Policy and AI](/screenshots/policy.png)

Terminal: `netwatch policy show`. See [Bans and policy](/bans-and-policy) and [AI analysis](/ai-analysis).

## Old addresses

Links to the pages from before the five sections still work and land on the new page: `#/overview` opens Status, `#/sources` Threats › Sources, `#/geo` Countries & networks, `#/connections` Traffic › Connections, `#/listeners` Exposure, `#/policy` Bans › Policy & AI, and so on.
