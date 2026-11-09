---
title: Configuration
description: Every setting in /etc/netwatch/netwatch.toml with its default, and where secrets go.
---

netwatch reads `/etc/netwatch/netwatch.toml`, or the file passed with `--config` or `NETWATCH_CONFIG`. Every setting is optional; a missing file means all defaults. Print them with:

```shell
netwatch default-config
```

Restart the service after editing (`sudo systemctl restart netwatch`). Changed GeoIP files are reloaded on their own.

## Secrets

Keys never go in the TOML. Put them in `/etc/netwatch/env` (mode 0600), which the service reads at startup:

```shell
NETWATCH_LLM_API_KEY=sk-...
NETWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

With Docker, pass them with `-e` instead.

## Interface and mode

```toml
interface = "auto"        # where XDP attaches; "auto" = the interface of the default route
xdp_mode = "auto"         # "auto" (driver, falling back to skb), "driver" or "skb"; Linux only
mode = "observe"          # "observe": propose only; "enforce": also ban automatically
drop_banned = true        # false: count banned packets but let them pass (a dry run)
drop_syn_ip_options = false   # drop IPv4 SYNs with IP options from every source (CVE-2026-98432); Linux only
api_listen = "127.0.0.1:9180" # read-only API and UI; must be a loopback address
tick_secs = 5
```

## Paths

Linux defaults; on macOS the data directory is `/var/db/netwatch` and the sockets are in `/var/run/netwatch`.

```toml
control_socket = "/run/netwatch/control.sock"   # root-only, used by the CLI for changes
db_path = "/var/lib/netwatch/netwatch.db"
geoip_city = "/var/lib/netwatch/dbip-city-lite.mmdb"
geoip_asn = "/var/lib/netwatch/dbip-asn-lite.mmdb"
retention_days = 30          # alerts and hourly per-source traffic
```

## Connections

```toml
track_flows = true
flow_interfaces = ["tailscale*", "wg*", "docker0", "br-*"]   # macOS: ["utun*", "bridge*"]
sample_dns = true            # parse DNS to log queries and name remote addresses
sample_tcp_payload = true    # parse TLS SNI, HTTP host and SSH banners; payload bytes are never kept
flow_retention_days = 7      # finished flows, DNS queries and connection events
```

See [Connection tracking](/connections).

## Allowlist

```toml
allowlist = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
             "100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]
allow_wireguard_peers = true   # never ban current WireGuard peer endpoints
allow_tailscale_peers = true   # never ban Tailscale peers and DERP relays
allow_cloudflare = true        # never ban Cloudflare ranges (cloudflared tunnels terminate there)
```

## Detection

```toml
watch_countries = []    # ISO codes: a small score bump, and called out in insights
auth_ports = [21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900]
sensitive_ports = [23, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5555,
                   5900, 5984, 6379, 6443, 7547, 9200, 10250, 11211, 27017]
ssh_units = ["ssh.service", "sshd.service", "tailscaled.service"]   # journald units with SSH logins

[thresholds]
scan_ports = 12             # distinct local ports touched within 10 minutes
probe_closed_ports = 3      # closed ports probed within 10 minutes
brute_force_syn_5m = 30     # SYNs to one listening auth port within 5 minutes
conn_flood_syn_5m = 600     # SYNs to any single listening port within 5 minutes
syn_flood_pps = 200.0       # per-source SYNs per second
flood_pps = 20000.0         # per-source inbound packets per second
icmp_flood_pps = 100.0      # per-source ICMP echo requests per second
global_syn_pps = 2000.0     # interface-wide SYNs per second
```

## Threat feeds

```toml
[[feeds]]
name = "spamhaus_drop"
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"

[[feeds]]
name = "dshield"
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset"

[[feeds]]
name = "feodo"
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset"

[[feeds]]
name = "fullbogons"
url = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
```

Setting `feeds` replaces the defaults. A feed can also have an `about` line, shown next to a match; the default feeds have one built in.

## Bans

```toml
[ban]
default_ttl = "24h"
max_ttl = "30d"
repeat_multiplier = 4       # each previous offence multiplies the TTL
review_score = 40           # shows up as "review"
recommend_ban_score = 70    # the recommendation becomes "ban"
auto_ban_score = 80         # enforce mode bans automatically
subnet_min_sources = 3      # flagged sources in one /24 (or /64) before proposing a range ban
```

## Model

```toml
[llm]
enabled = false
base_url = "https://api.openai.com/v1"   # up to and including /v1
model = ""
api_key_env = "NETWATCH_LLM_API_KEY"
interval_secs = 600           # minimum seconds between analysis calls
max_calls_per_hour = 6
daily_token_budget = 200000   # prompt + completion tokens per UTC day
max_sources_per_call = 15
max_output_tokens = 600
json_mode = true              # dropped automatically if the endpoint rejects it
auto_apply = false            # apply the model's bans without approval (enforce mode only)
min_confidence = 0.9
timeout_secs = 60
```

See [AI analysis](/ai-analysis).

## Slack

```toml
[slack]
enabled = false
webhook_env = "NETWATCH_SLACK_WEBHOOK"
notify_reviews = false
notify_logins = false
max_per_hour = 20
```

See [Slack notifications](/slack).

## temps

```toml
[temps]
enabled = true
socket = "/run/netwatch/requests.sock"
```

See [temps](/temps).
