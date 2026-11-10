# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's [Security tab](https://github.com/gotempsh/netwatch/security) and choose **Report a vulnerability**, or go straight to [the advisory form](https://github.com/gotempsh/netwatch/security/advisories/new). Only the maintainers see the report.

Don't open a public issue or pull request for a vulnerability until it has been fixed and released.

A useful report says:

- the netwatch version (`netwatch --version`) and the OS, kernel and architecture;
- what an attacker needs (local user, network access to the host, a crafted packet, …) and what they get;
- the steps or a proof of concept, and the relevant config if it isn't the default.

We'll acknowledge the report, keep you posted while we work on a fix, and credit you in the advisory unless you'd rather not be named.

## Supported versions

Fixes go into the latest release. `sudo netwatch update` installs it.

## Scope

netwatch runs as root and loads eBPF programs, so these are in scope among others:

- anything that lets a non-root user change state (bans, the allowlist, policy) or run code as root;
- packets or log lines that crash the daemon, make it ban the wrong address, or bypass the allowlist;
- the API or UI exposing secrets, or being reachable from anywhere but loopback;
- the installer, `netwatch update` or the release workflow installing something other than a release built by this repository.

What netwatch runs as root, what it sends where and what it stores is documented on the [Security and privacy](https://gotempsh.github.io/netwatch/security/) page.
