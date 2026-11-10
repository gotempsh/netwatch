---
title: Quick start
description: Open the web UI, read what netwatch found, approve your first ban and switch to enforce mode when the proposals look right.
---

This assumes netwatch is [installed](/installation) and running. It starts in **observe** mode: it records and proposes, but blocks nothing you haven't approved.

## 1. Open the web UI

The UI and its API listen only on `127.0.0.1:9180` and are read-only. From your own machine, open an SSH tunnel to the server:

```shell
ssh -L 9180:127.0.0.1:9180 user@server
```

Then browse [http://127.0.0.1:9180](http://127.0.0.1:9180). On a Mac running netwatch locally, open that address directly.

No server yet? The [live demo](/demo/) is the same UI on demo data, so you can follow the steps below in your browser.

![The Overview page: host status, live rates, flagged sources, bans and proposals](/screenshots/overview.png "Overview: the host, live packet and SYN rates, flagged sources, active bans and pending proposals.")

The strip at the top shows the host, the interface XDP is attached to and how (driver or generic), the mode, whether bans drop packets, the threat feeds loaded and, if configured, the model and its token budget.

## 2. Read the insights

Further down the Overview, **Insights** is what netwatch thinks deserves attention, most severe first. Each one says what it saw and gives the command that fixes or investigates it, for example:

- "sshd accepts passwords", with the `sshd_config` change;
- "SSH brute force from CHINANET /16 is ongoing", with the pending proposal;
- "port 5432 is reachable and being probed";
- "this host talked to a listed IP".

The same list is in the terminal:

```shell
netwatch status
```

## 3. Look at who is knocking

**Sources** lists every address that sent traffic, scored 0–100. Open one to see why it scored what it did.

![Sources, sorted by score](/screenshots/sources.png "Sources: score, findings, network and ban state for every address that sent traffic.")

```shell
netwatch sources --flagged       # the same list in the terminal
netwatch ip 218.92.0.112         # everything about one address
```

## 4. Approve a ban

In observe mode every ban is a **proposal**. **Bans & proposals** lists them with who proposed them (the rules or the model), why, and the command that applies each one.

![Bans and proposals](/screenshots/bans.png "Bans & proposals: active bans with their drop counts, and proposals waiting for approval.")

The UI is read-only on purpose, so changes go through the CLI, which talks to a root-only socket:

```shell
netwatch proposals               # what netwatch wants to ban, and why
sudo netwatch approve 7          # apply proposal 7
sudo netwatch reject 8
sudo netwatch ban 203.0.113.0/24 --ttl 7d --reason "scanner subnet"
sudo netwatch allow 198.51.100.4 # never ban this address
```

A ban drops the source's packets in XDP before the kernel's network stack sees them. On macOS it goes into a pf table.

## 5. Switch to enforce

Once the proposals look right, let netwatch ban on its own. Set the mode in `/etc/netwatch/netwatch.toml`:

```toml
mode = "enforce"
```

```shell
sudo systemctl restart netwatch
```

In enforce mode sources that cross `ban.auto_ban_score` are banned automatically, with TTLs that grow ×4 for each repeat offence, up to 30 days. Allowlisted addresses and `never_ban` rules still win. [Bans and policy](/bans-and-policy) explains the rules and how to write your own.

## Next

- [The web UI](/web-ui): every page, with screenshots.
- [Slack notifications](/slack): get told about new proposals and suspicious logins.
- [AI analysis](/ai-analysis): let a model review the sources the rules can't settle.
- [AI agents](/agents): ask Claude Code, Codex or Cursor what is happening on the server.
