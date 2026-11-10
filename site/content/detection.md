---
title: Detection and scoring
nav: Detection and scoring
description: What netwatch counts in the kernel, the findings it raises, how sources are scored, SSH monitoring, threat feeds, insights and what is never banned.
---

## Traffic accounting

An XDP program on the primary interface counts, per source address: packets, bytes, SYNs, inbound UDP and ICMP, and every local port the source touches. A source is "inbound" when it opens connections to us; replies to our own connections don't count.

The program fails open. It passes every packet except those from sources you banned.

## Findings

| Finding | When |
|---|---|
| Port scan | a source touches many distinct local ports within 10 minutes (`thresholds.scan_ports`, default 12) |
| Closed-port probe | a source probes ports nothing listens on (`thresholds.probe_closed_ports`) |
| Sensitive-port probe | a source probes a service that should never be public: Telnet, SMB, RDP, Redis, Docker, Postgres, Elasticsearch, … (`sensitive_ports`) |
| Brute force | repeated SYNs to one listening auth port within 5 minutes (`auth_ports`, `thresholds.brute_force_syn_5m`) |
| SYN, UDP and ICMP floods | per-source packet rates above `thresholds.*_pps`, plus an interface-wide SYN-rate alarm |
| Threat feed | the address is on a loaded feed, including outbound traffic from this host to a listed address |
| Exploit attempt | the first request matches a known exploit; see [Exploit detection](/exploits) |
| Watched country | the source is in one of `watch_countries` |

Each source gets a 0–100 score from its findings. At `ban.review_score` (40) it shows up for review, at `ban.recommend_ban_score` (70) the recommendation becomes a ban, and in enforce mode `ban.auto_ban_score` (80) bans it. When `ban.subnet_min_sources` flagged sources share a /24 (or /64), netwatch proposes banning the range.

## Threat feeds

The defaults are the parts of [FireHOL level1](https://iplists.firehol.org/?ipset=firehol_level1), loaded separately so each match shows which list and which listed range it came from:

- Spamhaus DROP
- DShield
- Feodo
- Team Cymru full bogons

Add your own as `[[feeds]]` with a `name` and a `url` pointing at a plain list of addresses or CIDRs.

## SSH monitoring

netwatch follows `ssh`, `sshd` and Tailscale SSH in journald (the unified log on macOS) and flags:

- password brute force and invalid users;
- a successful login after failures;
- logins from a country or ASN not seen in the last 90 days.

It also warns when sshd accepts passwords.

## Insights

Insights turn the data into concrete advice, each with a command to run, for example:

- "sshd accepts passwords";
- "port 5432 is reachable and being probed";
- "12 scanners from AS14061";
- "this host talked to a listed IP".

They're on the Overview page and in `netwatch status` and `netwatch insights`.

## Never ban what you depend on

These are allowlisted in the kernel automatically:

- private, CGNAT and link-local ranges;
- the default gateway;
- WireGuard endpoints (`allow_wireguard_peers`);
- Tailscale peers and DERP relays (`allow_tailscale_peers`);
- Cloudflare's ranges, so a Cloudflare tunnel keeps working (`allow_cloudflare`).

The peers come from `wg show` and `tailscale status`, read at startup and every 10 minutes. If Tailscale or WireGuard isn't running, there are no peers to add and netwatch starts anyway. A command that doesn't answer within 10 seconds is stopped, with a warning in the log. Its addresses from the last refresh stay allowlisted, and it is tried again at the next one. There's no need to turn `allow_tailscale_peers` off on a machine where Tailscale is sometimes down.

netwatch also refuses bans broader than /16 (IPv4) or /32 (IPv6) unless you pass `--force`. Add your own addresses with `sudo netwatch allow <ip-or-cidr>` or the `allowlist` setting.

## Behind NAT or a tunnel

Behind NAT or a Cloudflare tunnel, most internet traffic never reaches the NIC directly: tunnelled visitors come from Cloudflare's addresses, which are allowlisted. In that setup netwatch mostly sees what the router forwards, plus your own outbound connections.
