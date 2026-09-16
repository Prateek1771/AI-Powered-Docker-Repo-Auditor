# The scan pipeline

**Audience:** anyone changing the orchestrator, an agent, or the progress protocol.
**Scope:** one scan, from `POST /api/v1/scans` to a stored report.

> **Both diagrams are in the repository README:**
> [the scan lifecycle](../../README.md#the-scan-lifecycle) and
> [the agent graph](../../README.md#the-agent-graph).

---

## Related

- [Architecture overview](overview.md) - the components this runs across
- [Observability](observability.md) - `agent_outcome_total`, `agent_duration_seconds` and the
  guard-rejection counter come from these same call sites
- [The LLM gateway](llm-gateway.md) - what the six agents cost
- Build phases [03](../history/build-phases/03-parallel-agents.md) and
  [04](../history/build-phases/04-dependent-agents.md) - how the fan-out and the fan-in were built
