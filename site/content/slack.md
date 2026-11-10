---
title: Slack notifications
nav: Slack
description: Post new ban proposals, possible compromises and new public listeners to a Slack incoming webhook.
---

netwatch can post to a Slack [incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/). It is outbound only: nothing in Slack can change netwatch, so approving a ban stays a CLI action.

```toml
[slack]
enabled = true
notify_reviews = false   # "review" proposals are the noisiest; compromise reviews are always sent
notify_logins = false    # every successful SSH/Tailscale login, not only suspicious ones
max_per_hour = 20
```

Put the webhook URL in `/etc/netwatch/env` (mode 0600):

```shell
NETWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

## What it posts

- **When it starts.**
- **Bans:** new ban proposals, with the `sudo netwatch approve <id>` command, and bans applied automatically in enforce mode.
- **Possible compromises:** a login after many failures, a login from a never-seen location, or the host talking to an address on a threat feed.
- **New public listeners:** a service that starts listening on a public or wildcard address.

Messages are batched (at most one every 10 s). Anything over the hourly limit is counted and mentioned in the next message.

## Listeners and DNS clients

A bound UDP socket is both a service and a resolver's source port, so a new one waits about 10 s to show which. One that sent well-formed DNS queries (from any port, answered or not) is a DNS client: it is hidden from the listener count and not announced. Servers, and sockets with no such evidence, are announced whatever their port; the kernel's ephemeral port range doesn't count either way.

Each listener carries a `role` (`client`, `server` or `unknown`) and the reason, in the API, the UI and `netwatch listeners`. This relies on DNS sampling (`sample_dns`) and on queries to port 53.
