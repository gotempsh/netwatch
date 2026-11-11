---
title: AI analysis
description: Optional review of unsettled sources and plain-English policies by any OpenAI-compatible model, hosted or local, on a small token budget.
---

Detection and the ban rules work without a model. With one configured, netwatch:

- reviews the sources that are flagged but that no rule has settled, and turns its suggestions into proposals labelled `by llm`;
- compiles ban policies written in plain English into rules (see [Bans and policy](/bans-and-policy)).

## Configure a model

Any OpenAI-compatible `/chat/completions` endpoint works: OpenAI, OpenRouter, Groq, DeepSeek, Together, or a local Ollama, vLLM or llama.cpp server.

```toml
[llm]
enabled = true
base_url = "https://openrouter.ai/api/v1"     # or http://127.0.0.1:11434/v1 for Ollama
model = "google/gemini-2.5-flash-lite"        # any cheap model is fine
daily_token_budget = 200000
```

Put the key in `/etc/netwatch/env` (mode 0600) as `NETWATCH_LLM_API_KEY=...`, not in the TOML. A local server needs no key.

Check the endpoint before you rely on it:

```console
$ sudo netwatch llm check
qwen3:1.7b at http://127.0.0.1:11434/v1 works for netwatch: it answered the analysis prompt in 1.8 s (527 tokens) and proposed ban 198.51.100.66/32 24h (confidence 0.90)
```

It sends the analysis prompt the daemon uses, with two sample sources: an attacker (failed SSH logins, a port scan, a blocklist hit) and a harmless probe. The model passes when it flags the attacker and doesn't ban the other. It works with `enabled = false` too, so you can try a model before you turn it on. Otherwise it says what's wrong and what to do:

```console
$ sudo netwatch llm check
Error: Ollama at http://127.0.0.1:11434/v1 doesn't have phi4-mini; pull it: ollama pull phi4-mini
```

It reads the key the same way the daemon does, from the environment or `/etc/netwatch/env`, so run it with `sudo` when the key is there.

Run `sudo netwatch analyze` to trigger a run now. Runs, tokens and suggestions are on the Policy & AI page.

## A local model

A small model on the same machine works, and nothing leaves it. With [Ollama](https://ollama.com):

```shell
ollama pull qwen3:1.7b
```

```toml
[llm]
enabled = true
base_url = "http://127.0.0.1:11434/v1"
model = "qwen3:1.7b"
```

Then `sudo netwatch llm check` and `sudo netwatch restart`. llama.cpp's `llama-server`, vLLM and LM Studio work the same way, with their own `base_url`.

These models passed `netwatch llm check` with Ollama, three runs each:

| Model | Size | Result |
|---|---|---|
| `qwen3:1.7b` | 1.4 GB | passes |
| `lfm3:1.7b` | 1.7 GB | passes |
| `qwen2.5:3b` | 1.9 GB | passes |
| `granite4.2:3b` | 2.2 GB | passes |
| `llama3.2:3b` | 2.0 GB | passes |
| `gemma4:12b` | 7.7 GB | passes |
| `llama3.2:1b` | 1.3 GB | fails: misses the attacker |
| `gemma3:1b` | 0.8 GB | fails: its JSON doesn't parse |

On a laptop GPU the small ones answer in 2–3 s; a server without a GPU is slower, so run `netwatch llm check` there to see. Thinking models such as Qwen 3 get `reasoning_effort = "none"`, so they answer instead of spending the output budget on reasoning.

The daemon ignores any suggestion for an address that isn't among the sources it sent, so a small model can't ban an address it made up.

## How it keeps costs down

- **The rules decide first.** The model only sees sources that are flagged but that no rule has settled, at most 15 per call (`max_sources_per_call`).
- **Compact input.** Each source is one line (`ip cc asn score findings ports ssh`), not raw packets.
- **No new data, no call.** If the digest hasn't changed since the last run, the call is skipped.
- **Hard caps.** At most 6 calls per hour (`max_calls_per_hour`) and a daily token budget, with temperature 0, JSON output and a small `max_output_tokens`. A typical run is about 1–2k tokens.
- **Compatibility.** netwatch asks for a JSON schema and falls back to plain JSON mode. If an endpoint rejects `response_format`, `reasoning_effort`, `temperature` or `max_tokens`, netwatch notices and stops sending that option.

## Applying suggestions

The model's suggestions become proposals. With `auto_apply = true` in enforce mode, suggestions at or above `min_confidence` (default 0.9) are applied without approval. The allowlist and `never_ban` rules still apply to them.
