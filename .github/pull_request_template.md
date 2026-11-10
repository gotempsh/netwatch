<!-- Title: a conventional commit subject that says what a user sees, e.g. "fix: a stopped Tailscale can no longer hold up startup". It becomes the release note. -->

## What changes

## How I tested it

<!-- The commands you ran and what they showed. Linux, macOS or both? -->

- [ ] `cargo fmt --check -p netwatch`, `cargo clippy -p netwatch --all-targets -- -D warnings` and `cargo test -p netwatch` pass
- [ ] A test covers the new behaviour
- [ ] Docs updated where users see the change (`site/content/`, `README.md`, `skills/netwatch/SKILL.md`)
- [ ] No real IPs, hostnames or usernames in code, fixtures or this description
