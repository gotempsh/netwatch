---
title: AI agents
nav: AI agents
description: Add the netwatch skill to Claude Code, Codex, Cursor or another coding agent, then ask it what is happening on your network.
---

netwatch ships a skill for AI coding agents. It teaches the agent which command answers which question, how to read the JSON API, how to read scores and private addresses, and to show you the evidence and ask before it bans anything. Add it once, then ask in plain language:

- What needs attention on this server?
- Who is attacking or scanning me, and from where?
- What does nginx connect to? Is postgres reachable from outside?
- Why was 203.0.113.9 flagged? Should I approve proposal 7?

This is separate from [AI analysis](/ai-analysis), where the daemon itself asks a model about sources the rules can't settle. The skill needs no model configured in netwatch: your agent does the work.

## Set it up with your agent

Paste this prompt into a coding agent running on the machine netwatch should watch. The agent installs netwatch, checks that the skill is in place, confirms the daemon runs and reports what it sees. It changes nothing else without asking:

<!-- copy-prompt -->

Or start the agent with it from the terminal:

```shell
claude "$(curl -fsSL https://gotempsh.github.io/netwatch/prompt.txt)"
codex "$(curl -fsSL https://gotempsh.github.io/netwatch/prompt.txt)"
```

`curl -fsSL https://gotempsh.github.io/netwatch/prompt.txt` shows the prompt first. Installing needs root: when `sudo` asks for a password, the agent stops and asks you to run the install command yourself, then carries on once you tell it you're done.

## Add the skill

The [install script](/installation#install-script) adds the skill for you, the person running it, for each coding agent with a folder in your home: `~/.claude/skills` when `~/.claude` or `~/.cursor` exists, `~/.agents/skills` when `~/.codex` or `~/.agents` exists. To add it yourself, or for an agent it didn't find, run the commands below as yourself, not with `sudo`, on the machine where the agent runs. The skill is built into the binary, so it always matches the netwatch you have installed. Start a new agent session afterwards so the agent picks it up.

Each command writes `<dir>/netwatch/SKILL.md`, creating the directory if needed, and prints where it went:

```console
$ netwatch skill --install --dir ~/.agents/skills
installed the netwatch 0.1.3 skill at /home/ana/.agents/skills/netwatch/SKILL.md
```

Under `sudo` it refuses unless you pass `--dir`, because files in your home directory would belong to root and a later install couldn't replace them.

### Claude Code

```shell
netwatch skill --install                        # for you: ~/.claude/skills
netwatch skill --install --dir .claude/skills   # this project only
```

### Codex

```shell
netwatch skill --install --dir ~/.agents/skills   # for you
netwatch skill --install --dir .agents/skills     # this project only
```

### Cursor

Cursor also reads Claude Code's skills folder, so the default install works:

```shell
netwatch skill --install                        # for you: ~/.claude/skills
netwatch skill --install --dir .cursor/skills   # this project only
```

### Other agents

Most other agents that support Agent Skills read `~/.agents/skills`, or `.agents/skills` in a project. Check your agent's documentation for its folder and pass it to `--dir`:

```shell
netwatch skill --install --dir ~/.agents/skills
```

### Agents without skills support

Print the skill and paste it into the agent's instructions file, such as `AGENTS.md`:

```shell
netwatch skill
```

### From GitHub, without netwatch installed

Agents and tools that add skills from a GitHub repository can take it from [`skills/netwatch`](https://github.com/gotempsh/netwatch/tree/main/skills/netwatch). With the [skills CLI](https://github.com/vercel-labs/skills):

```shell
npx skills add gotempsh/netwatch
```

That copy follows the main branch, which can be ahead of the release you run. Prefer `netwatch skill --install` on a machine with netwatch.

## Keep it current

Run the same `--install` command again after upgrading netwatch: it replaces the old copy. `netwatch update` upgrades the binary for the whole machine but doesn't touch skills in anyone's home directory.

## Where the agent runs

The skill uses the `netwatch` CLI and the daemon's JSON API, which listens on `127.0.0.1:9180` only. Run the agent on the host netwatch watches, for example Claude Code or Codex in an SSH session.

To run the agent on your own machine instead, open a tunnel to the server's API:

```shell
ssh -L 9180:127.0.0.1:9180 user@server
```

The JSON API and the CLI's read commands (`status`, `insights`, `sources`, `flows`, ...) then answer about the server, as long as no netwatch daemon runs on your machine on the same port. Changes go through a control socket on the server, so the agent has to run those over SSH.

## What the agent may change

Reading needs no privileges, so the agent can investigate freely. Every change (ban, unban, allow, approve, reject, policy, analyze) needs `sudo`. The skill tells the agent to show you the evidence, say exactly which command it would run and what it blocks, and wait for your go-ahead. It prefers approving a pending proposal over an ad-hoc ban, because the proposal carries the reason and the expiry.

In `mode = "observe"` (the default) netwatch never bans on its own; see [Bans and policy](/bans-and-policy).
