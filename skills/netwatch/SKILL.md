---
name: netwatch
description: Investigate network activity and attacks on a Linux or macOS host running netwatch - who connects to it, scans, brute force, exploit attempts, SSH logins, what each process connects to, DNS, listening services - and manage bans and ban proposals. Use when asked what is happening on a server's network, why an address was flagged, what a process or container talks to, whether a service is exposed, or to ban, unban, allow or approve.
---

# netwatch

netwatch is a daemon on the host. It counts traffic per source address in the kernel, tracks every connection with its process or container, reads SSH logs, scores sources and proposes bans. The `netwatch` CLI and a local JSON API read from it.

## First check it is running

```sh
netwatch status
```

- One summary line per topic (mode, rates, sources, flows) means it is running.
- `nothing answers at http://127.0.0.1:9180, so the netwatch daemon isn't running there`: the daemon is down or not installed. On Linux check `systemctl status netwatch` and `journalctl -u netwatch -n 50`. On macOS it runs as the launchd daemon `dev.netwatch` (`sudo launchctl print system/dev.netwatch`, log in `/var/log/netwatch.log`).
- `0 flows` and the insight `Connection tracking is off`: the kernel refused the flow programs, so flows, DNS and exploit attempts are missing while source counters, findings and bans still work. `journalctl -u netwatch -b | grep 'flow program'` (in Docker, the container's log: `docker logs <container>` or `docker compose logs netwatch`) shows why; 0.1.3 and older hit this on Debian 12 and Ubuntu 22.04 kernels, and `sudo netwatch update` fixes it.
- `mode observe` (the default) means netwatch never bans on its own: every ban is a proposal a person approves. `mode enforce` bans automatically.

Reading needs no privileges. Every change (ban, unban, allow, approve, reject, policy, analyze) needs root and goes through a control socket; without root it fails with `(is the daemon running, and are you root?)`.

## Answer questions with the CLI

| Question | Command |
|---|---|
| What needs attention now? | `netwatch insights` |
| Who is attacking or probing? | `netwatch sources --flagged` |
| Everything about one address | `netwatch ip 203.0.113.9` |
| Recent findings (scans, brute force, exploits) | `netwatch alerts -n 50` |
| SSH logins and failures | `netwatch ssh` |
| Open connections, busiest first | `netwatch flows` |
| Finished connections | `netwatch flows --history --window 24h` |
| What does a process or container connect to? | `netwatch flows --history --window 24h --process nginx` |
| Who connects to a port? | `netwatch flows --dir in --port 5432` |
| Which services listen, and are they exposed? | `netwatch listeners` |
| Failed outbound connects, new listeners | `netwatch events --kind connect_failed` |
| DNS lookups and failures | `netwatch dns --top`, `netwatch dns --rcode NXDOMAIN` |
| Active bans, pending proposals | `netwatch bans`, `netwatch proposals` |
| Ban policy in force | `netwatch policy show` |

`--window` takes `5m`, `15m`, `1h`, `6h`, `24h`, `7d` or `30d`. `-q` searches IPs, DNS names, TLS SNI, processes, ASN and country.

## Get JSON from the API

For anything you need to parse, read the API instead of the CLI's text. It is GET-only and listens on loopback only:

```sh
curl -s http://127.0.0.1:9180/api/overview
curl -s 'http://127.0.0.1:9180/api/sources?flagged=1&limit=20'
curl -s http://127.0.0.1:9180/api/sources/203.0.113.9
curl -s 'http://127.0.0.1:9180/api/flows?view=history&window=24h&process=nginx'
curl -s http://127.0.0.1:9180/api/proposals
```

Other endpoints: `/api/insights`, `/api/alerts`, `/api/ssh`, `/api/bans`, `/api/summary`, `/api/timeline` (flagged sources with their hourly history and events), `/api/flows/summary`, `/api/flows/graph` (who connects to which service, which program connects where), `/api/destinations`, `/api/listeners`, `/api/dns`, `/api/conn_events`, `/api/interfaces`, `/api/policy`. From another machine, tunnel first: `ssh -L 9180:127.0.0.1:9180 user@server`.

## Read the results correctly

- **Scores** run 0-100 from a source's findings. 40 means review, 70 recommends a ban, 80 is the automatic ban threshold in enforce mode.
- **Allowlisted** sources (private ranges, Tailscale and WireGuard peers, Cloudflare, anything added with `netwatch allow <address>`) are never banned or proposed.
- **A private source address on an attack** (10.x, 172.16-31.x, 192.168.x) is usually a load balancer, NAT gateway or another server in the same network, not the attacker. The real client address is not in the packets; look at that device's logs or at an `X-Forwarded-For` header. Never ban it: every client behind it would be cut off.
- **Exploit attempts** are matched on the first ~1 KB of plaintext requests. They show the attempt, not success; HTTPS requests are invisible unless temps reports them.
- **Directions**: `in` means the remote connected to this host, `out` means this host connected out.
- **Threat feeds** (Spamhaus DROP, DShield, Feodo, bogons) mark listed addresses; outbound traffic to a listed address is worth checking too.

## Change things only when asked

Bans drop traffic in the kernel. Treat every change as the user's decision:

1. Show the evidence first: `netwatch ip <address>` and the finding that triggered it.
2. Say exactly which command you would run and what it blocks, then wait for the user's go-ahead.
3. Prefer the pending proposal over an ad-hoc ban, because it carries the reason and the TTL:

```sh
netwatch proposals
sudo netwatch approve 7        # or: sudo netwatch reject 7
```

Other changes, all with `sudo`:

```sh
sudo netwatch ban 203.0.113.9 --ttl 24h --reason "SSH brute force"
sudo netwatch unban 203.0.113.9
sudo netwatch allow 198.51.100.4 --note "office"    # never ban this address
sudo netwatch disallow 198.51.100.4
```

- `--ttl` takes `1h`, `24h`, `7d` or `permanent`.
- A range wider than /16 (IPv4) or /32 (IPv6), or a non-public address, is refused unless you add `--force`. Don't add it to get past the refusal: ask the user why they want that range banned.
- Undo a ban with `unban`, and an allow with `disallow`.
