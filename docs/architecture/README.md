# Architecture

**The current system.** If one of these documents disagrees with the code, the document is
wrong and should be fixed.

| Document | Covers |
|---|---|
| [Overview](overview.md) | Components, the request path, why Redis carries progress |
| [The scan pipeline](pipeline.md) | One scan end to end; the six-agent DAG and the trust fan-in |
| [Observability](observability.md) | Collector, instruments, alerts, the in-app Analytics tabs |
| [The LLM gateway](llm-gateway.md) | Bifrost: cost, provider-key health, and what caching does not do |

Deliberately not here: how any of it was built. That is
[engineering history](../history/build-phases/README.md), and what is wrong with it is
[audits](../audits/README.md).
