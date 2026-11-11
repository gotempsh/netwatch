---
title: CLI reference
nav: CLI
description: Every netwatch command and its options. Read-only commands need no root; commands that change state go through a root-only socket.
---

```text
netwatch [-c, --config <path>] <command>
```

`--config` defaults to `/etc/netwatch/netwatch.toml`, or `NETWATCH_CONFIG` when set. Every command has `--help`.

Read-only commands query the daemon's API on `127.0.0.1:9180` and need no root. Commands that change state (marked **root**) go through the root-only control socket.

## Overview

| Command | What it shows |
|---|---|
| `netwatch status` | rates, counts and current insights |
| `netwatch insights` | only the insights |
| `netwatch alerts [-n 30]` | recent findings |
| `netwatch ssh [-n 30]` | SSH log events from sshd and Tailscale SSH |

## Sources

| Command | What it shows |
|---|---|
| `netwatch sources` | tracked sources, by score; alias `top` |
| `netwatch ip <ip>` | everything known about one address, including its connections |
| `netwatch geo <ip>` | offline lookup in the GeoIP databases; needs no daemon, and says how to download the databases if they're missing |

`netwatch sources` options:

- `--sort score|syn|in_bytes|in_pps|ports|last_seen` (default `score`)
- `--flagged`: only sources with findings
- `--port <port>`: only sources that touched this local port
- `-q <text>`: filter by IP, country or ASN substring
- `-n, --limit <n>` (default 30)

## Connections

| Command | What it shows |
|---|---|
| `netwatch flows` | live connections; alias `conns` |
| `netwatch listeners` | listening sockets and who owns them |
| `netwatch ifaces` | interfaces, throughput and what netwatch attached where |
| `netwatch dns` | DNS queries seen on the wire |
| `netwatch events` | failed outbound connects, new and closed listeners |

`netwatch flows` options:

- `--history`: finished flows from the store instead of live ones
- `--window 5m|15m|1h|6h|24h|7d|30d`: history window (default `1h`)
- `--ip <ip>`, `--port <port>`, `--iface <name>`
- `--process <name>`: process or container name
- `--dir in|out|unknown`: `in` means they connected to us, `out` that we connected to them
- `-q <text>`: free text over IP, DNS name, SNI, process, ASN org and country
- `--sort bytes|rate|last|first|retrans` (default `bytes`)
- `-n, --limit <n>` (default 40)

`netwatch listeners --all` includes loopback-only sockets and UDP sockets seen acting as DNS clients.

`netwatch dns` options: `-q <name>`, `--rcode NXDOMAIN|SERVFAIL|TIMEOUT|…`, `--window` (default `1h`), `--top` for the most-queried names, `-n` (default 40).

`netwatch events` options: `--kind connect_failed|listen|unlisten`, `--window` (default `24h`), `-n` (default 40).

## Bans

| Command | |
|---|---|
| `netwatch bans` | active bans |
| `netwatch proposals [--all]` | what netwatch wants to ban, and why; `--all` includes decided ones |
| `netwatch approve <id>...` | **root**: apply one or more proposals |
| `netwatch reject <id>...` | **root**: dismiss one or more proposals |
| `netwatch ban <ip-or-cidr>` | **root**: ban now |
| `netwatch unban <ip-or-cidr>` | **root**: lift a ban |
| `netwatch allow <ip-or-cidr> [--note <text>]` | **root**: never ban, keep out of proposals and bypass XDP drops |
| `netwatch disallow <ip-or-cidr>` | **root**: remove from the allowlist |

`netwatch ban` options:

- `--ttl <duration>`: `1h`, `24h`, `7d` or `permanent`; default `ban.default_ttl`
- `--reason <text>`
- `--force`: allow very large ranges and non-public addresses

TTLs print the way `--ttl` takes them (`7d`, `1d 30m`); countdowns and uptimes keep the two largest units (`in 6d 23h`). Reasons longer than the column end in `…`; `netwatch ip <ip>` shows them in full.

## Policy and AI

| Command | |
|---|---|
| `netwatch policy show` | the policy in effect, and the JSON rule format |
| `netwatch policy set <text> [--dry-run]` | **root**: plain-English policy (compiled by the model) or rules as JSON; `--dry-run` shows the rules without installing them |
| `netwatch policy clear` | **root**: remove your policy; the built-in rules remain |
| `netwatch analyze` | **root**: run a model analysis pass now |

See [Bans and policy](/bans-and-policy) and [AI analysis](/ai-analysis).

## Service

| Command | |
|---|---|
| `netwatch start` | **root**: start the installed daemon if it isn't running, then wait until it answers; shows its last log lines if it doesn't, and refuses a config that doesn't parse |
| `netwatch stop` | **root**: stop the daemon until `netwatch start` or the next boot; its bans are lifted while it is stopped. Works with a broken config, to end a restart loop. Updates, including the daily one, wait until it is started again |
| `netwatch restart` | **root**: restart the daemon, for example after editing the config; refuses a config that doesn't parse |
| `netwatch run` | **root**: run the daemon in the foreground (what the service runs) |
| `netwatch install` | **root**, macOS: install this binary as a launchd daemon and start it |
| `netwatch uninstall [--purge]` | **root**, macOS: stop and remove the daemon; `--purge` also deletes the config, database and log |
| `netwatch update-geoip` | **root**: download the DB-IP Lite databases |
| `netwatch update --check` | say whether a newer release exists, and whether automatic updates are on |
| `netwatch update` | **root**: install the latest release and restart the daemon; puts the previous version back if the new one doesn't start |
| `netwatch update --auto on\|off` | **root**: install new releases daily, or stop |
| `netwatch default-config` | print the default configuration |

`start`, `stop` and `restart` drive the systemd service on Linux and the launchd daemon `dev.netwatch` on macOS. On macOS they read the config the daemon was installed with (`netwatch install --config`), so `--config` isn't needed again. In the container, use `docker start`, `stop` and `restart` instead. On Linux, `scripts/install.sh` installs the systemd service; see [Installation](/installation). [Updating](/installation#updating) covers `netwatch update`, and [Uninstalling](/installation#uninstalling) removing it.

## Agent skill

netwatch ships a skill that teaches AI coding agents (Claude Code, Codex, Cursor and others that read `SKILL.md` skills) to investigate with netwatch: which command answers which question, the JSON API, how to read scores and private addresses, and to ask before banning anything.

```shell
netwatch skill --install                          # Claude Code and Cursor: ~/.claude/skills/netwatch
netwatch skill --install --dir ~/.agents/skills   # Codex and other agents
netwatch skill --install --dir .claude/skills     # one project only
netwatch skill                                    # print it, to put it anywhere else
```

The skill is built into the binary, so it always matches the installed version; run `--install` again after upgrading. Run it as yourself: under `sudo` it refuses unless you pass `--dir`, because the files would belong to root. [AI agents](/agents) has the directory for each agent and how to use it.
