---
title: Connection tracking
nav: Connections
description: How netwatch records every flow with its owning process or container, DNS names, TLS SNI and HTTP hosts, and what it keeps.
---

TC programs keep a table of every flow on the primary interface, and on Tailscale, WireGuard and Docker interfaces. TCP tracepoints add state changes, retransmits and resets. The programs never drop or modify traffic.

## What each flow records

- direction (who connected to whom), bytes, packets and rates each way;
- TCP state, connect latency, retransmits and resets;
- the owning process, with its systemd service or Docker container. This comes from the TCP tracepoints and a `/proc` scan every 15 s, so it also covers UDP, listeners and connections opened before netwatch started;
- application metadata parsed from the first payload in each direction: TLS SNI and ALPN, HTTP method, host, path, user agent and status, and SSH banners;
- the DNS name the remote address was resolved from.

netwatch also logs DNS queries and answers (with rcode and latency), listening sockets and who owns them, failed outbound connects, and new or closed listeners.

## Totals over a window

The Connections summary (bytes received and sent, and the top talkers) counts what moved within the window, not each connection's lifetime: a connection open for nine hours adds only its last hour to "1h". Windows up to an hour count by the minute; longer ones by whole hours, so "6h" at 10:42 starts at 04:00, and the tiles say so. A new connection's bytes are counted once netwatch knows its process (within about 20 seconds), so they land under that process and not under `unknown`. After upgrading from a version without these totals, the hours before the upgrade count each connection in the hour it ended.

## Querying flows

```shell
netwatch flows                                  # live connections, biggest first
netwatch flows --history --window 24h           # finished ones from the store
netwatch flows --process postgres --dir in      # who connects to postgres
netwatch flows -q github.com --sort last        # free text: IP, name, SNI, process, ASN org, country
netwatch listeners                              # listening sockets and their owners
netwatch dns --rcode NXDOMAIN                   # failing lookups
netwatch events --kind connect_failed           # failed outbound connects
```

`netwatch conns` is an alias for `netwatch flows`.

## Settings

In `/etc/netwatch/netwatch.toml`, with the Linux defaults:

```toml
track_flows = true
flow_interfaces = ["tailscale*", "wg*", "docker0", "br-*"]   # besides `interface`; a trailing * is a prefix match
sample_dns = true             # parse DNS queries and answers on port 53
sample_tcp_payload = true     # parse the first payload of each TCP direction
flow_retention_days = 7
```

Interfaces that match a pattern are attached when they come up and detached when they go away. On macOS the defaults are `utun*` and `bridge*`.

## Privacy

With `sample_tcp_payload`, the kernel copies at most the first 1 KB of each direction of a TCP connection to netwatch. Only the parsed fields listed above are kept; payload bytes are never stored or logged. TLS contents stay encrypted; only the cleartext ClientHello is read.

Set `sample_tcp_payload = false` (and `sample_dns = false`) to keep only counters, states and owners.

## Retention

Live flows are in memory. Finished flows, DNS queries and connection events are stored in SQLite for `flow_retention_days` (default 7), and so are bytes per remote, process, service and country by hour (the busiest 500 of each per hour; the rest is added up as one). Alerts and hourly per-source traffic are kept for `retention_days` (default 30).

The tracepoints see every network namespace. Sockets that belong neither to the host nor to a Docker container (for example in `ip netns`) are ignored.
