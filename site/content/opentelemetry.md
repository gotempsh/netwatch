---
title: OpenTelemetry
description: Push netwatch's metrics and security events to an OpenTelemetry collector over OTLP/HTTP, and from there to Prometheus, Grafana, Loki, Datadog or a SIEM.
---

Each netwatch watches one host and keeps its UI on `127.0.0.1`. To see every server in one place, netwatch can push to an OpenTelemetry collector:

- **metrics**: traffic, sources, bans, proposals, flows and throughput, aggregated per host, interface and process;
- **events**: findings, ban proposals, bans, SSH logins and new listeners, as OpenTelemetry log records.

It pushes over OTLP/HTTP with protobuf. Like Slack, it is outbound only: nothing new listens on the host.

## Turn it on

```toml
[otel]
enabled = true
endpoint = "http://127.0.0.1:4318"   # an OTLP/HTTP receiver; /v1/metrics and /v1/logs are appended
interval_secs = 60                   # seconds between metric exports
metrics = true
logs = true                          # events as log records
```

Restart netwatch. The log says `opentelemetry: sending metrics and events to …`.

Backends that need a token take it as a header. Put the headers in `/etc/netwatch/env` (mode 0600), in the standard `OTEL_EXPORTER_OTLP_HEADERS` format, `key=value` pairs separated by commas, with values percent-encoded:

```shell
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic%20dXNlcjp0b2tlbg==
```

`headers_env` names a different variable if you prefer. Extra resource attributes (`deployment.environment`, a cluster name, …) come from the standard `OTEL_RESOURCE_ATTRIBUTES` variable.

## A collector for Prometheus and Loki

Run the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) next to netwatch, or once for many hosts. This configuration serves the metrics to Prometheus and sends the events to Loki:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318

exporters:
  prometheus:
    endpoint: 0.0.0.0:8889          # scrape this from Prometheus
  otlphttp/loki:
    endpoint: http://loki:3100/otlp

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
    logs:
      receivers: [otlp]
      exporters: [otlphttp/loki]
```

```shell
docker run -d --name otelcol --network host \
  -v $PWD/collector.yaml:/etc/otelcol-contrib/config.yaml:ro \
  otel/opentelemetry-collector-contrib
```

Hosted backends (Grafana Cloud, Honeycomb, Datadog, New Relic, …) accept OTLP/HTTP directly: set `endpoint` to their OTLP URL and the token in `OTEL_EXPORTER_OTLP_HEADERS`.

## Metrics

Every series carries the resource attributes `service.name` (`netwatch`), `service.version`, `host.name` and `os.type`.

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `netwatch.packets` | counter | `{packet}` | |
| `netwatch.bytes` | counter | `By` | |
| `netwatch.packets.inbound` | counter | `{packet}` | |
| `netwatch.packets.syn` | counter | `{packet}` | |
| `netwatch.packets.banned` | counter | `{packet}` | |
| `netwatch.packets.dropped` | counter | `{packet}` | |
| `netwatch.events.lost` | counter | `{event}` | |
| `netwatch.connects.failed` | counter | `{connection}` | `network.transport` |
| `netwatch.sources.tracked` | gauge | `{source}` | |
| `netwatch.sources.active` | gauge | `{source}` | |
| `netwatch.sources.flagged` | gauge | `{source}` | |
| `netwatch.bans.active` | gauge | `{ban}` | |
| `netwatch.proposals.pending` | gauge | `{proposal}` | |
| `netwatch.ssh.failures` | gauge | `{attempt}` | |
| `netwatch.listeners.exposed` | gauge | `{socket}` | |
| `netwatch.flows.active` | gauge | `{flow}` | `network.transport`, `netwatch.direction` |
| `netwatch.interface.throughput` | gauge | `bit/s` | `network.interface.name`, `network.io.direction` |
| `netwatch.process.flows` | gauge | `{flow}` | `process.executable.name`, `container.name`, `netwatch.unit` |
| `netwatch.process.throughput` | gauge | `bit/s` | `process.executable.name`, `container.name`, `netwatch.unit`, `network.io.direction` |

The packet counters cover the primary interface since netwatch started. `netwatch.sources.active` counts sources seen in the last 10 minutes, `netwatch.sources.flagged` those at or above `ban.review_score`, and `netwatch.ssh.failures` failed logins in the last hour. `netwatch.direction` is `in` (they connected to us), `out` or `unknown`.

Through the collector's Prometheus exporter the names become `netwatch_packets_total`, `netwatch_flows_active`, `netwatch_interface_throughput_bit_per_second` and so on.

There are no per-address series: thousands of source addresses would overwhelm a metrics backend. Per-address detail is in the events. The per-process metrics name the 20 busiest processes (by name, container and service, never by pid) and add the rest up as `other`.

## Events

Each event is a log record with an event name, a severity, a readable body and attributes:

| Event | When | Severity | Attributes |
|---|---|---|---|
| `netwatch.started` | the daemon starts | INFO | `netwatch.mode`, `network.interface.name` |
| `netwatch.finding` | a finding is new or worse, and every 5 minutes while it lasts | WARN at or above `ban.recommend_ban_score`, else INFO; ERROR for the CVE-2026-98432 trigger | `source.address`, `netwatch.finding.kind`, `netwatch.score`, `netwatch.location` |
| `netwatch.proposal` | a ban or review is proposed | WARN for bans, INFO for reviews | `netwatch.proposal.id`, `netwatch.action`, `netwatch.target`, `netwatch.proposed_by`, `netwatch.confidence`, `netwatch.ttl` |
| `netwatch.ban` | a ban is applied: approved, manual, by policy in enforce mode or by the model | WARN | `netwatch.target`, `netwatch.banned_by`, `netwatch.ttl` |
| `netwatch.unban` | a ban expires or is lifted | INFO | `netwatch.target`, `netwatch.reason` |
| `netwatch.ssh` | an SSH or Tailscale SSH login, failure or invalid user | INFO | `netwatch.ssh.event`, `user.name`, `source.address`, `netwatch.ssh.method`, `netwatch.location` |
| `netwatch.listener` | a service starts or stops listening | WARN when it starts on a public or wildcard address, else INFO | `netwatch.listener.event`, `network.transport`, `server.address`, `server.port`, `netwatch.exposed`, `process.executable.name`, `process.pid`, `container.name`, `netwatch.unit` |

`netwatch.finding.kind` is one of the [finding kinds](/bans-and-policy#rules-as-json), and `netwatch.ttl` is in seconds. Unlike Slack, every event is sent: filter in the collector or the backend.

## When the collector is down

Exports run on their own threads and never block detection or bans. Events wait in a queue of 2048; while it is full, new events are dropped, and the log says so once (with the total when netwatch stops). Each failed export is logged:

```text
WARN  opentelemetry-otlp] name="Export.Failed.Exhausted" operation="HttpLogsClient.Export" retries=3 …
ERROR opentelemetry_sdk] name="BatchLogProcessor.ExportError" error="Operation failed: HTTP export failed: network error"
```

On shutdown netwatch sends what is still queued, waiting 5 seconds at most.
