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

Run `sudo netwatch analyze` to trigger a run now. Runs, tokens and suggestions are on the Policy & AI page.

## How it keeps costs down

- **The rules decide first.** The model only sees sources that are flagged but that no rule has settled, at most 15 per call (`max_sources_per_call`).
- **Compact input.** Each source is one line (`ip cc asn score findings ports ssh`), not raw packets.
- **No new data, no call.** If the digest hasn't changed since the last run, the call is skipped.
- **Hard caps.** At most 6 calls per hour (`max_calls_per_hour`) and a daily token budget, with temperature 0, JSON output and a small `max_output_tokens`. A typical run is about 1–2k tokens.
- **Compatibility.** If an endpoint rejects `response_format`, `temperature` or `max_tokens`, netwatch notices and stops sending that option.

## Applying suggestions

The model's suggestions become proposals. With `auto_apply = true` in enforce mode, suggestions at or above `min_confidence` (default 0.9) are applied without approval. The allowlist and `never_ban` rules still apply to them.
