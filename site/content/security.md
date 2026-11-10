---
title: Security and privacy
nav: Security and privacy
description: What runs as root and why, what the UI and API expose, every network request netwatch makes, what it stores, how to verify a release, and how to remove it.
---

netwatch is a root daemon that sees all of a host's traffic, so this page says exactly what it does with that access. Everything here comes from the source. File references are to the [repository](https://github.com/gotempsh/netwatch). To report a vulnerability, see [`SECURITY.md`](https://github.com/gotempsh/netwatch/blob/main/SECURITY.md).

## What runs as root, and why

The daemon (`netwatch run`) runs as root for its whole life. It doesn't drop privileges.

On Linux it needs root to:

- load the eBPF programs and attach them: XDP on the main interface, TC ingress and egress on the flow interfaces, and the TCP tracepoints;
- read every process's sockets under `/proc`, to name the process, systemd unit or container behind each connection;
- read SSH logins from the journal (`journalctl`) and run `sshd -T` to see whether password logins are allowed;
- create the control socket under `/run/netwatch`.

The systemd unit (`scripts/systemd/netwatch.service`) keeps the rest locked down: `ProtectSystem=strict` with only `/var/lib/netwatch` writable, `ProtectHome=read-only`, `PrivateTmp`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID` and `LockPersonality`.

On macOS it needs root to:

- open `/dev/bpf` and capture on each interface;
- load the ban table into the pf anchor `com.apple/netwatch` with `pfctl`, which the stock `/etc/pf.conf` already evaluates (netwatch doesn't edit `/etc/pf.conf`);
- read other users' sockets through libproc, and sshd logins from the unified log;
- create the control socket under `/var/run/netwatch`.

The [container](/docker) runs `--privileged` with the host's network and PID namespaces for the same reasons.

Read-only CLI commands (`netwatch status`, `sources`, `flows`, …) don't need root: they read the API. Only commands that change something need `sudo`.

## Nothing is blocked until you say so

The default `mode` is `observe`. In observe mode netwatch drops packets only from sources a person banned: with `sudo netwatch ban`, or by approving a proposal with `sudo netwatch approve`. Everything the rules or the model would ban becomes a proposal instead, and proposals left pending expire after a day. The XDP program passes everything except banned sources.

Automatic bans happen only after you set `mode = "enforce"`:

- a source whose score reaches `ban.auto_ban_score` (80 by default) is banned by the rules;
- a model suggestion is applied without approval only if you also set `llm.auto_apply = true`, and only at or above `llm.min_confidence` (0.9).

Even then the allowlist wins: private ranges, your default gateway, WireGuard and Tailscale peers, Cloudflare's ranges and `netwatch allow` entries are never banned. `drop_banned = false` turns bans into a dry run that only counts what would have been dropped.

One setting drops traffic from anyone: `drop_syn_ip_options`, which drops IPv4 SYNs carrying IP options ([CVE-2026-98432](/exploits)). It is off by default.

## The web UI and API

The UI and its API listen on `127.0.0.1:9180`. The daemon refuses to start if `api_listen` isn't a loopback address, so to reach it from your laptop you use an SSH tunnel (`ssh -L 9180:127.0.0.1:9180 server`).

The API only has `GET` routes, so nothing can be changed over HTTP. It never returns the model's API key or the Slack webhook. It has no login, though: any user or process on the machine (or at your end of an SSH tunnel) can read everything it shows, including connections, DNS queries, process names and SSH usernames. Don't run it on a host shared with people who shouldn't see that.

The UI is embedded in the binary and loads nothing from the internet.

Changes go through the control socket, `/run/netwatch/control.sock` (`/var/run/netwatch/control.sock` on macOS). It is a Unix socket with mode `0600` owned by root, so only root can ban, unban, allow, approve, reject, set a policy or start a model run. Every command it receives is logged. Slack is outbound only: nothing posted there can change netwatch.

[temps](/temps) integration listens on a second root-only (`0600`) Unix socket, `/run/netwatch/requests.sock`, which only accepts HTTP request lines to scan for exploits. Set `temps.enabled = false` to turn it off.

## Every outbound request

This is every network request netwatch makes, besides its own sockets and reading the interfaces.

On by default, so a fresh install makes them:

- **Threat feeds.** `GET` from `raw.githubusercontent.com` (three FireHOL lists) and `www.team-cymru.org` (full bogons), at startup and then every 6 hours. A failed feed is retried after 15 seconds, then less often. `feeds = []` turns them off.
- **Cloudflare ranges.** `GET` `www.cloudflare.com/ips-v4` and `/ips-v6`, at startup and then every 10 minutes with the allowlist refresh. If that fails, a built-in list is used. `allow_cloudflare = false` turns it off.
- **GeoIP databases.** `GET` from `download.db-ip.com` (DB-IP Lite city and ASN): at install if the files are missing, then monthly on the 3rd, from the `netwatch-update-geoip.timer` systemd timer or the `dev.netwatch.geoip` launchd job. The container fetches them at first start and when they are over 30 days old. Disable the timer or job to stop it.

Only when you ask for them:

- **Release check.** `GET` `releases/latest` on the GitHub repository, reading only the redirect (no API), when you run `netwatch update` or `netwatch update --check`, or daily after `sudo netwatch update --auto on`.
- **Release download.** `SHA256SUMS` and your platform's archive from the release on GitHub, when an update finds a newer release and when you run the install script.
- **Slack.** `POST` to your incoming webhook (it must be `https://`) when something worth a message happens: batched, at most `max_per_hour` (20) messages. Needs `slack.enabled` and the webhook.
- **OpenTelemetry.** OTLP/HTTP to your `otel.endpoint` (`/v1/metrics` and `/v1/logs`): metrics every `interval_secs` (60), events in batches as they happen. Needs `otel.enabled`.
- **Model.** `POST` to your `llm.base_url` + `/chat/completions`, every `interval_secs` (600) while there are unsettled sources and the digest has changed, at most `max_calls_per_hour` (6) and within `daily_token_budget`. Also `sudo netwatch analyze`, and `sudo netwatch policy set` with plain-English text. Needs `llm.enabled` and a model.

Each of these reveals your server's address to the service it contacts, like any download. Feeds, Cloudflare ranges and GeoIP downloads send no data about your traffic: they are plain `GET` requests.

Sources: feeds in `netwatch/src/config.rs` and `intel.rs`, the 6-hour and 10-minute loops in `daemon.rs`, GeoIP in `scripts/netwatch-update-geoip`, `scripts/docker-entrypoint.sh` and `netwatch/src/macos/launchd.rs`, updates in `update.rs` and `scripts/get.sh`, Slack in `notify.rs`, OpenTelemetry in `otel.rs`, the model in `llm.rs` and `daemon.rs`.

### What Slack receives

One message per batch, starting with the host name. A message can hold: that netwatch started (mode, interface), automatic bans with the target, TTL and reason, proposals with their target, reason and the `netwatch approve` command, suspicious SSH logins (and every login with `notify_logins = true`) as `user@address`, new listeners reachable from outside with the process behind them, and CVE-2026-98432 triggers. See [Slack](/slack).

### What the OpenTelemetry collector receives

Every export carries `service.name`, `service.version`, `host.name` and `os.type`. Metrics are totals per host, interface, direction and top-20 process, never per source address. Events include source addresses, finding kinds and scores, locations, ban targets, SSH usernames and methods, and listener addresses with their process, PID, unit and container. [OpenTelemetry](/opentelemetry) lists every metric and attribute. Endpoint tokens go in `/etc/netwatch/env` as `OTEL_EXPORTER_OTLP_HEADERS`.

### What the model receives

An analysis call sends a fixed system prompt and one user message with:

- your policy text, or `none`;
- the TCP and UDP ports the host listens on, whether sshd accepts passwords, and the mode;
- up to `max_sources_per_call` (15) flagged sources the rules haven't settled, one line each: the address, country and ASN with its organisation, score, finding kinds with their scores, how many local ports it touched in the last hour and the top 8, its SYN and inbound packet totals, SSH failure, invalid-user and success counts, and the feeds it's listed on.

It sends no payloads, no flows, no DNS queries, no usernames and no host name. `sudo netwatch policy set "<text>"` sends your policy text with the list of finding kinds and the built-in rules. The key is sent as a bearer token. `base_url` can be a local server (Ollama, vLLM, llama.cpp) so nothing leaves the machine; with an `http://` URL to another host, the prompt travels unencrypted. See [AI analysis](/ai-analysis).

## What is stored, and where

Everything netwatch keeps is in one SQLite file, `/var/lib/netwatch/netwatch.db` on Linux and `/var/db/netwatch/netwatch.db` on macOS. The GeoIP databases sit next to it.

The file is created with mode `0644`. On macOS `netwatch install` makes its directory `0750`. On Linux the unit's `StateDirectory=` resets `/var/lib/netwatch` to systemd's default `0755` at every start, so local users can read the database there, the same data the API already shows them.

| Kept for | What |
|---|---|
| `flow_retention_days` (7) | Finished connections: addresses, ports, bytes, TCP state, process, unit, container, DNS name, TLS SNI or HTTP host. DNS queries and answers. Connection and listener events |
| `retention_days` (30) | Alerts, hourly traffic per source, SSH login events (with usernames), model runs (tokens and summary), decided proposals |
| Until removed | Bans until they expire, allow rules, your policy text, and offence counts per address (they make repeat bans longer) |

Payloads are never stored. The capture hands netwatch up to 1 KB of DNS packets and of the first payload in each direction of a TCP connection, and it keeps only the parsed fields: DNS names and answers, TLS SNI and ALPN, the HTTP request or status line with Host and User-Agent, and SSH banners. The last few request lines per source stay in memory; one that matches a known exploit also goes into its alert's summary, cut to 100 characters.

Logs go to the journal on Linux and `/var/log/netwatch.log` on macOS. Secrets (`NETWATCH_LLM_API_KEY`, `NETWATCH_SLACK_WEBHOOK`, `OTEL_EXPORTER_OTLP_HEADERS`) belong in `/etc/netwatch/env` with mode `0600`.

## Verify a download

Each release has a `SHA256SUMS` file and a GitHub build provenance attestation for each archive, signed through Sigstore by the release workflow (`.github/workflows/release.yml`).

Check the checksum:

```shell
curl -fsSLO https://github.com/gotempsh/netwatch/releases/download/v0.1.3/netwatch-linux-x86_64.tar.gz
curl -fsSLO https://github.com/gotempsh/netwatch/releases/download/v0.1.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS        # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
```

Check that the archive was built from this repository by the release workflow, with the [GitHub CLI](https://cli.github.com):

```shell
gh attestation verify netwatch-linux-x86_64.tar.gz --repo gotempsh/netwatch \
  --signer-workflow gotempsh/netwatch/.github/workflows/release.yml
```

It exits with status 0 and prints the verified workflow run when the archive matches. A changed file, or one built anywhere else, fails. The attestation also names the tag and commit it was built from:

```shell
gh attestation verify netwatch-linux-x86_64.tar.gz --repo gotempsh/netwatch --format json \
  --jq '.[0].verificationResult.signature.certificate | {sourceRepositoryRef, sourceRepositoryDigest}'
```

The attestation covers the `.tar.gz` archives, not `SHA256SUMS` itself.

The install script and `netwatch update` check the archive against the `SHA256SUMS` of the same release. That catches a corrupt or truncated download, not a tampered release, since both files come from the same place. They don't check the attestation; do that yourself if it matters to you.

## Read the installer first

The one-line installer is [`scripts/get.sh`](https://github.com/gotempsh/netwatch/blob/main/scripts/get.sh), published with these docs. To read it before it runs:

```shell
curl -fsSL https://gotempsh.github.io/netwatch/install.sh -o install.sh
less install.sh
sh install.sh
```

It downloads the archive and `SHA256SUMS` from the GitHub release, checks the hash, and runs the archive's own installer with `sudo`: `scripts/install.sh` on Linux, `netwatch install` on macOS. You can also [install by hand](/installation#linux-by-hand) without it.

## Uninstall

### Linux

There's no uninstall command on Linux yet. This removes everything the installer and `netwatch update --auto on` create:

```shell
sudo systemctl disable --now netwatch.service netwatch-update-geoip.timer netwatch-update.timer
sudo rm -f /etc/systemd/system/netwatch.service \
  /etc/systemd/system/netwatch-update-geoip.service /etc/systemd/system/netwatch-update-geoip.timer \
  /etc/systemd/system/netwatch-update.service /etc/systemd/system/netwatch-update.timer
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/netwatch /usr/local/bin/netwatch.previous /usr/local/bin/netwatch-update-geoip
sudo rm -rf /etc/netwatch /var/lib/netwatch       # config, secrets, database, GeoIP files
```

Stopping the service detaches the XDP and TC programs, which lifts every ban. `/run/netwatch` goes away with the service.

### macOS

```shell
sudo netwatch uninstall --purge
```

That stops and removes the `dev.netwatch`, `dev.netwatch.geoip` and `dev.netwatch.update` launchd jobs, deletes `/usr/local/bin/netwatch` and `netwatch.previous`, and with `--purge` also `/etc/netwatch`, `/var/db/netwatch`, `/var/run/netwatch` and `/var/log/netwatch.log`. Without `--purge` it keeps the config and database. Stopping the daemon removes its pf rules.

### Docker

With the `docker run` command from [Installation](/installation#docker):

```shell
docker rm -f netwatch
docker volume rm netwatch-data
```

With `docker-compose.yml`, `docker compose down -v` in its directory removes the container and its data volume.

### The agent skill

If you ran `netwatch skill --install`, remove `~/.claude/skills/netwatch` (or the directory you passed with `--dir`).
