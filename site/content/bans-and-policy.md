---
title: Bans and policy
description: Observe and enforce modes, the built-in ban rules, writing your own policy in plain English or JSON, and managing bans from the CLI.
---

## Observe and enforce

- **observe** (the default): every ban is a *proposal* you approve or reject. Only bans you approve or apply by hand take effect.
- **enforce**: sources are banned automatically, with TTLs that escalate for repeat offenders (×4 per offence by default, up to 30 days).

Set `mode` in `/etc/netwatch/netwatch.toml` and restart the service. With `drop_banned = false`, bans are counted in the kernel but packets still pass, which is a dry run of enforcement.

## Managing bans

```shell
netwatch proposals                   # pending proposals; --all includes decided ones
sudo netwatch approve 7              # apply a proposal
sudo netwatch reject 7
netwatch bans
sudo netwatch ban 203.0.113.0/24 --ttl 7d --reason "scanner subnet"
sudo netwatch unban 203.0.113.0/24
sudo netwatch allow 198.51.100.4 --note "office"   # never ban; also bypasses XDP drops
sudo netwatch disallow 198.51.100.4
```

`--ttl` takes `1h`, `24h`, `7d` or `permanent`; the default is `ban.default_ttl`. Ranges broader than /16 (IPv4) or /32 (IPv6), and non-public addresses, need `--force`.

## Built-in rules

Applied in this order; the first match wins:

| Rule | When | Action |
|---|---|---|
| compromise | login succeeded after failures, or from a new location | review |
| bruteforce | SSH password guessing or SYN brute force on auth ports | ban 7d |
| flood | SYN, UDP or ICMP flood | ban 1h |
| exploit | sent a known exploit request | ban 7d |
| listed-prober | on a threat feed and probing us, or probing for secrets | ban 7d |
| scanner | wide port scan (score ≥ 75) | ban 24h |
| high-score | score ≥ 85 | ban 24h |
| review | score ≥ 40 | review |

## Your own policy in plain English

Write the policy as a sentence. The configured [model](/ai-analysis) compiles it into structured rules once, and you can read exactly what was installed:

```shell
sudo netwatch policy set "never ban anything from Spain or AS3352; ban Telnet and SMB probers for 30 days; anything from AS14061 that scans gets a week" --dry-run
sudo netwatch policy set "…"      # install it
netwatch policy show
sudo netwatch policy clear        # the built-in rules remain
```

![Policy and AI page](/screenshots/policy.png "The Policy & AI page shows the English policy, the rules compiled from it and the built-in defaults.")

## Rules as JSON

Without a model, pass the rules as JSON instead (`netwatch policy show` prints the format):

```shell
sudo netwatch policy set '[{"id":"no-es","description":"never ban Spain","action":"never_ban","when":{"countries":["ES"]}}]'
```

Each rule has an `id`, a `description`, an `action`, the conditions in `when`, and for bans a `ttl_secs` (the default TTL applies without one). At most 50 rules; a rule without conditions is rejected because it would match every source.

Conditions in `when` (all must hold):

| Condition | Matches |
|---|---|
| `findings_any` | any of these finding kinds (listed below) |
| `min_score` | score at or above |
| `countries` / `not_countries` | ISO country codes |
| `asns` | AS numbers |
| `cidrs` | address ranges |
| `ports_any` | touched any of these local ports |
| `in_feed` | listed on a threat feed |
| `min_ssh_failed` | at least this many failed SSH logins |

Actions are `ban`, `review`, `ignore` (no proposals, still shown in the UI) and `never_ban`. `never_ban` always beats everything else, including the model's suggestions.

Finding kinds: `port_scan`, `closed_probe`, `sensitive_probe`, `brute_force`, `conn_flood`, `syn_flood`, `flood`, `icmp_flood`, `exploit_attempt`, `recon_probe`, `threat_feed`, `outbound_to_listed`, `watched_country`, `ssh_bruteforce`, `login_after_failures` and `new_login_location`.
