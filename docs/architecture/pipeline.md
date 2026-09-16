# The scan pipeline

**Audience:** anyone changing the orchestrator, an agent, or the progress protocol.
**Scope:** one scan, from `POST /api/v1/scans` to a stored report. The component
diagram is in [the architecture overview](overview.md).

---

## The scan lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant A as FastAPI
    participant Q as SQS FIFO
    participant W as Worker
    participant S as Scanners
    participant G as Agents
    participant D as DynamoDB
    participant R as Redis

    B->>A: POST /api/v1/scans {repo_id, target}
    A->>A: verify JWT · rate limit · create_job()
    A->>Q: enqueue_scan() - MessageGroupId = repo_id
    A-->>B: 202 {job_id}

    B->>A: WS /ws/jobs/{job_id}?token=…
    Note over A,B: bad token or wrong tenant → close 1008,<br/>never a silent 1006

    Q->>W: receive (long poll)
    W->>D: claim_job() - tolerates redelivery

    W->>W: resolve_target() - upload:// → docker load
    W->>S: gather(trivy, history, inspect)
    S-->>W: raw reports
    W->>R: progress 10 · "Fetching image data"

    W->>G: run_scan_from_raw()
    W->>R: progress 40 · "Running agents"
    G-->>W: outcomes (analysed / failed / timed_out)

    W->>D: store_result() + report blob
    W->>R: progress 100 · "Scan complete"
    R-->>A: pub/sub frame
    A-->>B: {status, progress, step}

    Note over W,Q: PermanentFailure (bad tag, missing image)<br/>→ deleted, not retried three times
```

Every progress write is `update_progress()` **then** `bus.publish()`, and the publish sits in its own
`try` - delivery of a progress event is a nice-to-have, the scan result is not.

---

## The agent graph

```mermaid
graph LR
    T["Trivy<br/>vuln + secret"] --> VP["extract_vulnerabilities()"]
    H["docker history"] --> LP["extract_layers()"]
    I["docker inspect"] --> PR["build_profile()"]
    T --> PR
    LP --> PR

    VP --> CVE["cve_analyst"]
    LP --> BLOAT["bloat_detective"]
    PR --> BASE["base_image_strategist"]
    PR --> COMP["compliance_checker"]
    LP --> COMP

    CVE --> TRUST{"outcomes_by_agent()<br/>which inputs are trustworthy?"}
    BLOAT --> TRUST
    BASE --> TRUST
    COMP --> TRUST

    TRUST --> OPT["dockerfile_optimizer"]
    TRUST --> RISK["risk_scorer"]

    OPT --> OUT["ScanOutcome"]
    RISK --> OUT

    subgraph par["Parallel · asyncio.gather · 120s each"]
        CVE
        BLOAT
        BASE
        COMP
    end

    subgraph dep["Sequential · sees the fan-in"]
        OPT
        RISK
    end

    classDef fail fill:#3f1d1d,stroke:#dc2626,color:#fecaca
    class TRUST fail
```

The fan-in is the interesting part. `app/agents/trust.py` answers *which of my inputs can I believe?* -
`missing_inputs()` names the required agents whose output cannot be trusted, and `input_confidence()`
returns the fraction that can. The dependent agents receive that verdict rather than a silently
shorter list, so `risk_scorer` knows the difference between "no critical CVEs" and "the CVE agent
never ran".

`asyncio.gather(..., return_exceptions=True)` plus `_degrade()` is what keeps one bad agent from
killing five good ones.

---

## Related

- [Architecture overview](overview.md) - the components this runs across
- [Observability](observability.md) - `agent_outcome_total`, `agent_duration_seconds` and the
  guard-rejection counter come from these same call sites
- [The LLM gateway](llm-gateway.md) - what the six agents cost
- Build phases [03](../history/build-phases/03-parallel-agents.md) and
  [04](../history/build-phases/04-dependent-agents.md) - how the fan-out and the fan-in were built
