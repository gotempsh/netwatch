---
title: temps
description: On a host running temps, netwatch matches temps' decrypted HTTPS requests against its exploit signatures, and temps enforces netwatch's bans at the HTTP level.
---

On a host that runs [temps](https://github.com/gotempsh/temps), the two exchange what each can't see.

## temps sends netwatch its requests

temps' proxy decrypts HTTPS, so it sends one line per request (client address, method, host, path, User-Agent, status, JA4 and temps' own verdict) to a Unix datagram socket. Each line goes through the same [exploit matching](/exploits) as a plaintext request, shown as served by `temps`. Lines arrive even for clients behind a CDN or tunnel, which never reach XDP themselves.

## temps reads netwatch's bans

temps polls `GET /api/bans` and blocks the banned addresses at the HTTP level, until each ban expires or netwatch has been gone for two minutes.

## Settings

```toml
[temps]
enabled = true                          # the default; with nothing sending, it costs nothing
socket = "/run/netwatch/requests.sock"  # root-only, like the control socket
```

Each line is a JSON object with a version field `v`; netwatch ignores versions it doesn't know. Neither side depends on the other: either runs the same when the other is missing.

In Docker, mount `/run/netwatch` from the host (`-v /run/netwatch:/run/netwatch`) so temps can reach the socket.
