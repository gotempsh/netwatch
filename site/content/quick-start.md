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

![The Status page: a verdict, what needs you with the command for each item, and who is knocking](/screenshots/status.png "Status: what needs you, most urgent first, then who is knocking, who this host talks to and what the internet can reach.")

## 2. Read what needs you

**Status** opens with a verdict: all quiet, or what needs you now and what to check. Each item says what netwatch saw and gives the command that fixes or investigates it, for example:

- "sshd accepts passwords", with the `sshd_config` change;
- "SSH brute force from CHINANET /16 is ongoing", with the pending proposal;
- "port 5432 is reachable and being probed";
- "pg-backup can't reach db.backup.example.com:5432", when a program's connections keep failing.

A line at the bottom of the page says where the sensor is attached, how many interfaces record flows and which threat feeds are loaded. The chip at the top right shows the mode, and says `dry run` when bans are counted but not dropped.

The daemon's insights, without the client-side checks such as failing connections, are in the terminal too:

```shell
netwatch status
```

## 3. Look at who is knocking

**Threats** opens on a timeline of the flagged sources, one lane each, with when each finding, proposal and ban happened. **Threats › Sources** lists every address that sent traffic, scored 0–100. Open one to see what it did and where it stands.

![Sources, sorted by score](/screenshots/sources.png "Sources: score, findings, network and ban state for every address that sent traffic.")

```shell
netwatch sources --flagged       # the same list in the terminal
netwatch ip 192.0.2.12           # everything about one address
```

## 4. Approve a ban

In observe mode every ban is a **proposal**. **Bans** lists them with who proposed them (the rules or the model), why, and the command that applies each one.

![Bans and proposals](/screenshots/bans.png "Bans & proposals: active bans with their drop counts, and proposals waiting for approval.")

The UI is read-only on purpose, so changes go through the CLI, which talks to a root-only socket:

```shell
netwatch proposals               # what netwatch wants to ban, and why
sudo netwatch approve 7          # apply proposal 7
sudo netwatch reject 8
sudo netwatch ban 203.0.113.0/24 --ttl 7d --reason "scanner subnet"
sudo netwatch allow 198.51.100.4 # never ban this address
```

To lift a ban, by hand or approved, use its target as `netwatch bans` lists it. The source's page in the UI shows the same command:

```shell
netwatch bans                    # active bans and when they expire
sudo netwatch unban 203.0.113.0/24
```

A ban drops the source's packets in XDP before the kernel's network stack sees them. On macOS it goes into a pf table.

## 5. Switch to enforce

Once the proposals look right, let netwatch ban on its own. Set the mode in `/etc/netwatch/netwatch.toml`:

```toml
mode = "enforce"
```

```shell
sudo systemctl restart netwatch                    # Linux
sudo launchctl kickstart -k system/dev.netwatch    # macOS
```

In enforce mode sources that cross `ban.auto_ban_score` are banned automatically, with TTLs that grow ×4 for each repeat offence, up to 30 days. Allowlisted addresses and `never_ban` rules still win. [Bans and policy](/bans-and-policy) explains the rules and how to write your own.

## Next

- [The web UI](/web-ui): every page, with screenshots.
- [Slack notifications](/slack): get told about new proposals and suspicious logins.
- [AI analysis](/ai-analysis): let a model review the sources the rules can't settle.
- [AI agents](/agents): ask Claude Code, Codex or Cursor what is happening on the server.
