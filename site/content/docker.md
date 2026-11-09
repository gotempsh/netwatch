---
title: Docker
description: Run netwatch from the multi-arch container image with docker run, and configure it with a mounted file.
---

Each release publishes a multi-arch image (`linux/amd64`, `linux/arm64`) to `ghcr.io/gotempsh/netwatch`, tagged with the version and `latest`. The server only needs Docker:

```shell
docker run -d --name netwatch --restart unless-stopped --stop-timeout 30 \
  --network host --pid host --privileged \
  -v netwatch-data:/var/lib/netwatch -v /run/netwatch:/run/netwatch \
  ghcr.io/gotempsh/netwatch:latest
docker exec netwatch netwatch status
```

## Why it needs these flags

netwatch watches the host it runs on, not the container:

- `--network host` attaches XDP and TC to the real interfaces. The UI stays on `127.0.0.1:9180` and no ports are published.
- `--pid host` lets it see which process or container owns each connection.
- `--privileged` is needed for eBPF, tracepoints and reading the host.

netwatch reads host files through `/proc/1/root`, and runs the host's own `sshd -T`, `journalctl`, `ip`, `wg` and `tailscale` inside the host's mount namespace. The image doesn't carry those tools and always sees the host's real configuration.

## Volumes

- `netwatch-data` keeps the SQLite database and the GeoIP databases, which are downloaded on first start and refreshed monthly.
- `/run/netwatch` holds the control socket and the socket [temps](/temps) sends to. Leave that mount out if you don't run temps.

## Running commands

The CLI is in the image. Commands that change state need the control socket, which `docker exec` reaches as root:

```shell
docker exec netwatch netwatch proposals
docker exec netwatch netwatch approve 7
docker exec netwatch netwatch flows --history --window 24h
```

## Configuration

Without a config file it runs with the defaults: the default-route interface, in observe mode. To change settings, print the defaults, edit them, and mount the file:

```shell
sudo mkdir -p /etc/netwatch
docker run --rm ghcr.io/gotempsh/netwatch default-config | sudo tee /etc/netwatch/netwatch.toml
# edit /etc/netwatch/netwatch.toml, then:
docker run -d --name netwatch --restart unless-stopped --stop-timeout 30 \
  --network host --pid host --privileged \
  -v netwatch-data:/var/lib/netwatch -v /run/netwatch:/run/netwatch \
  -v /etc/netwatch/netwatch.toml:/etc/netwatch/netwatch.toml:ro \
  -e NETWATCH_SLACK_WEBHOOK -e NETWATCH_LLM_API_KEY \
  ghcr.io/gotempsh/netwatch:latest
```

`-e NAME` passes that variable from your shell; you only need `NETWATCH_SLACK_WEBHOOK` or `NETWATCH_LLM_API_KEY` when you enable `[slack]` or `[llm]`. See the [configuration reference](/configuration).

## Compose

Compose is optional. The repository's `docker-compose.yml` runs the same container with `deploy/netwatch.toml` mounted:

```shell
docker compose up -d          # or --build to build the image from a checkout
```

## One copy per server

An interface takes one XDP program, so stop the old container before starting a new one. If a platform starts the new copy first, the new one fails to attach and keeps restarting until the old one exits.

On platforms with security policies for containers (such as Temps), an administrator has to allow privileged containers, host networking and the host PID namespace.
