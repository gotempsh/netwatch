---
title: Compared to other tools
nav: Compared to other tools
description: How netwatch relates to fail2ban, CrowdSec, ntopng, Suricata, OpenSnitch and Little Snitch, and when to pick one of them instead.
---

netwatch watches one host's traffic from the kernel, records every connection with the process behind it, and proposes bans you approve. Several good tools overlap with part of that. Each section says what the other tool does (from its own documentation), where netwatch differs, and when the other tool is the better choice. Many people run netwatch next to one of them.

## fail2ban

- **What it does:** [fail2ban](https://github.com/fail2ban/fail2ban) scans log files such as `/var/log/auth.log` and bans addresses with too many failures by updating firewall rules for a set time. It ships filters for sshd, Apache and many other services, and you can write your own.
- **Where netwatch differs:** netwatch counts packets, so it also sees port scans, probes of closed ports and floods, which leave nothing in a log. For logins it only reads SSH. In observe mode, the default, it proposes bans instead of applying them.
- **Pick fail2ban when** you want to ban on application log lines (mail, web app logins, FTP), with the firewall actions it ships or your own, without eBPF or a recent kernel.

## CrowdSec

- **What it does:** the [CrowdSec](https://docs.crowdsec.net/docs/intro) Security Engine parses logs and HTTP requests with behaviour scenarios, and separate remediation components ("bouncers") block at the firewall, web server or reverse proxy. Unless you opt out, it shares signals (offending address, scenario, timestamp) with its Central API and downloads a community blocklist in return.
- **Where netwatch differs:** netwatch works from packets and connections on one host, not logs, and shares nothing: its threat feeds are public lists it downloads. It bans only at the host (XDP on Linux, pf on macOS).
- **Pick CrowdSec when** you protect many machines or services from one place, want blocking at the web or proxy layer, or want a blocklist built from other users' reports.

## ntopng

- **What it does:** [ntopng](https://www.ntop.org/guides/ntopng/what_is_ntopng.html) is a web-based traffic monitor that captures packets, collects NetFlow, sFlow and IPFIX, polls devices over SNMP, and identifies protocols with nDPI. The Community edition is free and open source; Professional and Enterprise need a license.
- **Where netwatch differs:** netwatch looks at the host it runs on, ties every connection to its process, systemd unit or container, follows SSH logins and bans attackers. It has no flow collector, no SNMP and no deep protocol classification.
- **Pick ntopng when** you monitor a network rather than a server: a router, a mirror port, or flow exports from switches and firewalls.

## Suricata

- **What it does:** [Suricata](https://docs.suricata.io/en/latest/what-is-suricata.html) is a network IDS, IPS and network security monitoring engine from the OISF. It runs signature rulesets, and deployed inline it can drop the packets a rule matches.
- **Where netwatch differs:** netwatch matches the first request of each connection against about 60 [exploit signatures](/exploits), plus behaviour (scans, brute force, floods, feed matches). It isn't a rule engine and doesn't reassemble streams.
- **Pick Suricata when** you need full signature-based intrusion detection, maintained rulesets, or protocol logging across a network.

## OpenSnitch

- **What it does:** [OpenSnitch](https://github.com/evilsocket/opensnitch) is an application firewall for GNU/Linux that filters outbound connections by rules: when a process wants a new connection, it asks you to allow or deny it.
- **Where netwatch differs:** netwatch never asks per connection and doesn't block by application. It records outbound connections with their process for you to review, and bans by remote address, mostly inbound attackers. It is built for servers without a desktop.
- **Pick OpenSnitch when** you want to decide, app by app, what may reach the internet from a Linux desktop.

## Little Snitch

- **What it does:** [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) is a paid network monitor and per-application firewall for macOS that alerts you when an app connects and lets you allow or deny it. [Little Snitch for Linux](https://obdev.at/products/littlesnitch-linux) (kernel 6.12 or newer) has a GPLv2 eBPF program and web UI with a proprietary, free daemon; its makers describe it as built for privacy, not security.
- **Where netwatch differs:** on macOS netwatch shows which process sent each connection too, but it has no per-app rules and no prompts. It is aimed at inbound attacks: scans, brute force, listed sources, SSH logins, and bans with pf. All of it is open source: MIT or Apache-2.0, and the eBPF code GPL-2.0, MIT or Apache-2.0.
- **Pick Little Snitch when** you want to control which apps on your Mac or Linux desktop may connect, with rules you click through as connections happen.
