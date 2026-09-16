# Build phases

The reasoning behind each layer, written as it was built. Fourteen documents, roughly
twenty thousand lines - the largest body of writing in this repository.

**These are not architecture documentation.** Each describes the state of the code at the
time it was written, and several teach a bug on the way to fixing it - deliberately, because
the diagnosis is the point. For the current system read
[architecture](../../architecture/README.md); where the two disagree, architecture wins.

| | Phase | |
|---|---|---|
| 01 | [Scanner layer](01-scanner-layer.md) | Trivy runner and deterministic reduction |
| 02 | [The CVE analyst](02-cve-analysis-agent.md) | Structured output and fail-loud parsing |
| 03 | [Parallel agents](03-parallel-agents.md) | Visible degradation, failure isolation |
| 04 | [Dependent agents](04-dependent-agents.md) | The fan-in, degraded inputs |
| 05 | [Evaluation harness](05-evaluation-harness.md) | Recall, precision, stability |
| 06 | [Persistence](06-persistence.md) | Hot/cold tables, tenant keys, the Decimal problem |
| 07 | [The queue](07-queue.md) | FIFO groups, visibility arithmetic, idempotency |
| 08 | [The API](08-api-layer.md) | Verifying tokens, limiting cost, object-level authz |
| 09 | [Real-time progress](09-realtime-progress.md) | Why in-memory fan-out cannot work |
| 10 | [The frontend](10-frontend.md) | Two kinds of state, backoff, honest degradation |
| 11 | [Containerisation](11-containerisation.md) | Layers, ghosts, scanning your own work |
| 12 | [Infrastructure](12-infrastructure.md) | Build order, encoded fixes, what it costs |
| 13 | [CI/CD](13-cicd.md) | OIDC, matrices, rollback, the gate that matters |
| 14 | [Observability](14-observability.md) | Instruments for the failures that never raise |

## The code blocks are enforced

Phases 09-14 quote real files, and `scripts/check_code_blocks.py` diffs every quoted block
against the file it came from. It runs in CI, so a phase doc cannot drift from the code it
teaches:

```bash
python scripts/check_code_blocks.py            # report drift
python scripts/check_code_blocks.py --write    # push each file's contents back into its block
```

The code is the source of truth and the doc quotes it, which is why `--write` runs in that
direction. A handful of blocks are exempt - listed in the script, each because the doc is
quoting an excerpt to make a point rather than mirroring a whole file.

`ghost-demo/` holds the two Dockerfiles phase 11 §12 asks you to build, to see a deleted
file still occupying 500 MB of image.
