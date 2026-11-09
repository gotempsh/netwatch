---
title: HTTP API
description: The read-only JSON API the web UI uses, served on 127.0.0.1:9180.
---

The daemon serves a GET-only JSON API and the web UI on `api_listen` (default `127.0.0.1:9180`, and it must be a loopback address). There are no write endpoints: bans, approvals and policy changes go through the CLI and the root-only control socket.

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
| `/api/sources/{ip}` | one source in full: findings, feeds, ports, SSH, alerts, proposals, history | |
| `/api/alerts` | findings over time | `since`, `ip`, `limit` |
| `/api/ssh` | SSH events | `since`, `ip`, `limit` |
| `/api/bans` | active bans | |
| `/api/proposals` | pending proposals with the command that applies each | `status=all` (include decided ones), `ip`, `limit` |
| `/api/summary` | traffic by country, network, port and top sources | `window` |
| `/api/events` | recent daemon events | `limit` |
| `/api/policy` | your rules, the compiled rules and the built-in defaults | |
| `/api/llm` | model settings, token use and recent runs | |
| `/api/flows` | connections | `view` (`active`, `history`, `all`), `window`, `ip`, `port`, `process`, `dir`, `iface`, `proto`, `q`, `sort`, `limit` |
| `/api/flows/summary` | flow counts, failed connects, top remotes, processes, services and countries | `window` |
| `/api/destinations` | every address the host connected out to, one row per address | `window`, `scope` (`public`, `all`), `unnamed`, `q`, `sort`, `limit` |
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
