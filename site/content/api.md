---
title: HTTP API
description: The read-only JSON API the web UI uses, served on 127.0.0.1:9180.
---

The daemon serves a GET-only JSON API and the web UI on `api_listen` (default `127.0.0.1:9180`, and it must be a loopback address). There are no write endpoints: bans, approvals and policy changes go through the CLI and the root-only control socket. Requests must be addressed to `localhost`, `127.0.0.1` or `[::1]`; any other `Host` gets `403`, unless it is listed in `api_hosts` (see [Security](/security#the-web-ui-and-api)).

```shell
curl -s http://127.0.0.1:9180/api/overview | jq .
curl -s 'http://127.0.0.1:9180/api/sources?flagged=1&limit=10' | jq '.[].ip'
```

## Endpoints

| Endpoint | Returns | Query parameters |
|---|---|---|
| `/api/overview` | host, mode, rates, counts and the attached interfaces | |
| `/api/insights` | current insights with their commands | |
| `/api/sources` | tracked sources with score, findings, geo and ban state | `sort`, `flagged`, `port`, `q`, `limit`, `all` |
| `/api/sources/{ip}` | one source in full: findings, feeds, ports, its 200 latest SSH events and its 50 latest accepted logins (`ssh_logins`), which newer failures can't push out, alerts, proposals, history | |
| `/api/alerts` | findings over time | `since`, `ip`, `limit` |
| `/api/ssh` | SSH events | `since`, `ip`, `limit` |
| `/api/bans` | active bans; `matched` counts the packets that hit each ban, `dropped` the ones it dropped (0 when bans don't drop: `drop_banned = false`, or macOS without pf) | |
| `/api/proposals` | pending proposals with the command that applies each | `status=all` (include decided ones), `ip`, `limit` |
| `/api/timeline` | flagged sources active in the window, highest score first, each with its hourly packets and SYNs, its findings, proposals, ban and accepted SSH logins; `total` counts them all before `limit` | `window` (`24h` or `7d`, the default), `limit` (1–50, default 20) |
| `/api/summary` | traffic by country, network, port and top sources | `window` |
| `/api/events` | recent daemon events | `limit` |
| `/api/policy` | your rules, the compiled rules and the built-in defaults | |
| `/api/llm` | model settings, token use and recent runs | |
| `/api/flows` | connections | `view` (`active`, `history`, `all`), `window`, `ip`, `port`, `process`, `dir`, `iface`, `proto`, `q`, `sort`, `limit` |
| `/api/flows/graph` | the Traffic map: inbound connections grouped by who connected and the service they reached, outbound ones by program and destination, each column folded to nine boxes, with bytes and failures per line | `window` (`5m`, `1h` the default, `24h`) |
| `/api/flows/summary` | flow counts, failed connects, bytes moved in the window (from `bytes_since`), top remotes, processes, services and countries | `window` |
| `/api/destinations` | every address the host connected out to, one row per address | `window`, `scope` (`public`, `all`), `unnamed`, `q`, `sort` (`flows`, `bytes`, `last`, `first`, `failed`), `limit` |
| `/api/interfaces` | interfaces, rates and attached programs | |
| `/api/listeners` | listening sockets, owners and exposure | |
| `/api/dns` | DNS queries and the most-queried names | `window`, `q`, `rcode`, `limit` |
| `/api/conn_events` | failed connects, new and closed listeners | `window`, `kind`, `limit` |

`window` takes durations such as `15m`, `1h`, `24h` or `7d`. `since` is a Unix timestamp.

The response shapes are the ones the UI consumes; `ui/src/api/types.ts` in the repository describes them in TypeScript. They may change between releases.

## Reaching it remotely

The API never listens on a public address. Use an SSH tunnel:

```shell
ssh -L 9180:127.0.0.1:9180 user@server
```
