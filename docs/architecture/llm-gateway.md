# The LLM gateway

**Audience:** anyone changing how model calls are made, or asking what a scan costs.
**Scope:** the optional [Bifrost](https://github.com/maximhq/bifrost) gateway in front of
every model call - what it is for, what it measurably does and does not do.

**Prerequisite:** it is off by default. With `LLM_GATEWAY_URL` empty the agents call the
provider directly, exactly as before, which is what keeps the test suite and CI unaffected -
the same discipline as `OTEL_EXPORTER_OTLP_ENDPOINT`.

---

## Why

Four separate problems, three of them recorded as open audit findings, all solved in the
same place:

| Problem, as found | What the gateway does |
|---|---|
| Every scan 429'd for hours against one exhausted key, with nothing to say so | Per-key health, and failover across keys and providers |
| `llm_cost_usd_total` deferred in audit-01 §18 - a price table nobody wants to maintain | The gateway maintains it; `bifrost_cost_total` is real USD |
| Audit-01 P3-3's "unbounded model bill" | Virtual keys with hierarchical budgets |
| A single-provider dependency | A second provider turns an exhausted key from an outage into a failover |

The key-health point is the one worth stating plainly: **a process using a dead key cannot
tell you the key is dead.** It only sees 429s, which look exactly like rate limiting.

## The integration is one argument

Every model call in this project - six agents, the CLI and the eval harness - goes through
`build_client()` in `worker/app/agents/runner.py`. So the whole change is:

```python
base_url=LLM_GATEWAY_URL or None,
```

`None` and not `""`: the SDK falls back to its own default only for `None`, and would treat
an empty string as a real base URL.

Two things this codebase depends on had to survive the proxy, and were verified rather than
assumed: `response_format: {"type": "json_object"}` still produces a bare JSON object
(`parse_structured()` and every guard rest on it), and the `usage` block still comes back
(`_record_usage()` reads it). Both do.

### The model-name footgun

A gateway routes on `provider/model` and 404s on a bare model name. Rather than leave that
as a trap for whoever turns the gateway on and forgets to change `CVE_MODEL`, the prefix is
added in `worker/app/config/scanning.py` when the gateway is in use and the name carries no
`/`. An explicit `anthropic/claude-…` is left alone, which is how you point at a different
provider.

## What it exports

Scraped by Prometheus as a third job and surfaced on the Analytics page's Gateway tab:

| Metric | Why it is here and not in the application |
|---|---|
| `bifrost_cost_total{model,provider}` | Real USD. Audit-01 §18 deferred `llm_cost_usd_total` because a USD figure needs a per-model price table maintained against a vendor's pricing page, and a wrong number is worse than no number. |
| `bifrost_provider_key_up{key_name,provider}` | `1` while a key works, `0` after it fails. |
| upstream latency, requests, retries, tokens by model | |

## Caching: measured, and it does not fire

The plan for this work asserted that a repeat scan would show a cache hit and a lower token
count. It does not, and the claim is corrected here rather than left standing.

Two back-to-back CLI scans of `alpine:3.18` through the gateway:

```
run 1:  3703 input tokens    bifrost_cache_read_input_tokens_total = 4864
run 2:  3700 input tokens    bifrost_cache_read_input_tokens_total = 4864
```

No saving; the gateway's cache counter never moved. Two reasons, both real:

1. **Bifrost's semantic cache is a plugin**, needs a vector store, and is off by default.
2. **OpenAI's automatic prompt cache needs a 1024-token identical prefix**, and this
   workload's per-agent prompts are around 600 tokens. The path itself works - an
   1,816-token prompt sent twice read 1,664 cached tokens - it simply never reaches the
   threshold here.

The semantic cache is **deliberately left off**, not merely unconfigured. It answers a
near-match prompt with a previous answer, and on a security scanner that means one image's
findings reported against another's. That is a correctness hazard, not a performance
tradeoff.

## Not yet proven

**Failover is untested.** `ANTHROPIC_API_KEY` is wired through compose but empty, so there
is no second provider key to fail over to. The single key's health is exported and reads
`1`; that a second would take over is unproven, and it was the headline reason for adding
the gateway.

---

## Related

- [Configuration](../operations/configuration.md) - `LLM_GATEWAY_URL`, `BIFROST_PORT`, `ANTHROPIC_API_KEY`
- [Observability](observability.md) - where these metrics land
- `example.env` - the same findings, next to the setting they concern
