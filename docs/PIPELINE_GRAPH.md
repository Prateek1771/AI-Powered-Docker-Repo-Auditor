# Pipeline graph UI — design decision record

**Status:** backend landed · contract catch-up landed (AUDIT §17) · graph deferred
**Blocked on:** approval of one new dependency, `@xyflow/react`
**Related:** [AUDIT.md](AUDIT.md) §8.2 (observability), README "The agent graph"

---

## Why

The scan pipeline is a real fan-out/fan-in DAG — 3 scanners → 3 processors → 4 parallel
agents → a trust fan-in → 2 dependent agents. The UI renders it as a hardcoded four-item
list (`frontend/components/ScanProgress.tsx`):

```tsx
/** Mirrors the four _report() calls in app/orchestrator.py. */
const STEPS = [
  { at: 10, label: "Fetching image data" },
  { at: 40, label: "Running agents" },
  { at: 90, label: "Storing results" },
  { at: 100, label: "Complete" },
];
```

"Running agents" covers 40%→90% — the longest and most interesting stretch of a scan — as one
line of text. Nothing names `cve_analyst`, nothing shows that four agents run concurrently,
and per-agent outcomes only appear after the scan finishes, in `AgentTimings.tsx`.

Before this work the topology existed in exactly two places: `worker/app/orchestrator.py`
and a Mermaid diagram in the README. Nothing client-side knew it, and nothing on the wire
carried it.

## The decisions

### 1. Vendor the React Flow components; do not run the shadcn CLI

[reactflow.dev/ui](https://reactflow.dev/ui) ships its components through
`npx shadcn@latest add https://ui.reactflow.dev/<component>`. That is the documented route
and it is the wrong one here.

This project has **no shadcn setup** — no `components.json`, no Radix, no
`class-variance-authority`, no `tailwindcss-animate`. It hand-rolls four primitives in
`frontend/components/ui/` (`Badge`, `Button`, `Card`, `Skeleton`) with plain props and no CVA,
and its `cn()` helper lives at `lib/cn.ts`, not the `lib/utils.ts` the CLI emits.

Running `shadcn init` would create a config that fights the existing layout, and every React
Flow UI component pulls Radix primitives (Popover, Tooltip, Collapsible) that are currently
absent. Vendoring the two or three components actually needed — a base node, a status
indicator, an animated edge — costs less than the dependency tree and matches how
`components/ui/` was already built.

**Net dependency cost: one package, `@xyflow/react`.**

### 2. Add per-agent progress events rather than guessing from thresholds

A node graph driven by `progress >= 40` would light all four agents at once and learn nothing
the existing stepper does not already show. The graph is only worth building if it is
genuinely live.

`worker/app/orchestrator.py` already knew when each agent started and finished — `_timed()`
computes `duration_seconds` for every one of them. It just threw the timing into a Pydantic
field and told nobody until the scan ended. That was the change: announce it.

**This half is done.** See "What landed" below.

### 3. Keep `ScanProgress` and `AgentTimings`; the graph is additive

A React Flow canvas cannot carry `role="progressbar"`, `aria-valuenow`, or a meaningful tab
order. `ScanProgress` already has all three, plus a reduced-motion path through
`useMotionPrefs()`.

Replacing it with a canvas would trade working accessibility for a picture. The graph goes in
as a new section with `aria-hidden` on the canvas, and the stepper and timings table remain
the accessible representation of the same state.

### 4. Static layout, no `dagre` or `elk`

The graph is 14 nodes and never changes shape. A layout engine for a constant DAG is a
dependency earning nothing — hand-placed positions in a single `lib/pipeline.ts` are smaller,
faster, and produce a stable picture users can learn.

### 5. Dark mode maps through CSS variables, not a `.dark` class

React Flow's stylesheet and the upstream components assume a `.dark` class. This project has
none — `app/globals.css` does dark purely via `@media (prefers-color-scheme: dark)`, and
there is no theme toggle or `next-themes`.

So: import `@xyflow/react/dist/style.css`, then override React Flow's own CSS variables inside
the existing media query, mapping them onto the project's tokens (`--background`, `--surface`,
`--border`, `--foreground`, `--accent`). No new class, no new pattern, no new dependency.

---

## What landed (backend)

The wire protocol and the worker are done and verified — `ruff`, `ruff format` and
`mypy app eval` all clean.

**`worker/app/progress/bus.py`** — `ProgressEvent` gains two optional fields:

```python
node: str | None = None        # "trivy" | "cve_analyst" | ...
node_state: str | None = None  # "running" | AgentStatus
```

Additive on purpose. A stage frame names no node, and any client predating them keeps reading
`status` / `progress` / `step` exactly as before. `node` reuses the orchestrator's own names,
which are the same identifiers `AgentOutcome.agent` already uses — so a UI can key a graph off
them without a translation table.

**`worker/app/orchestrator.py`**

- `_timed()` announces `running` before awaiting and the real status after.
- A new `_scanned()` does the same for the three scanners, announcing `failed` before
  re-raising so a client learns *which* scanner died rather than only that something did.
- Degraded outcomes are announced after the gather. A timeout kills `_timed` before it can
  report, so without this a timed-out agent would sit on "running" for the rest of the scan.
- `_node_reporter()` builds the callback and owns the progress arithmetic. Scanners share the
  10→40 band and agents the 40→90 band, matching the stage frames exactly. The existing bar
  stops parking at 40% for most of the scan — a benefit even with no graph in front of it.

  The obvious version spread all nine nodes over one 10→90 span, and it made the bar go
  backwards: three settled scanners computed 37% immediately before the stage frame that
  says 40%. Caught by running a real scan, not by a test; `tests/test_node_progress.py` now
  pins it.
- `on_node` is optional at every level, so `run_scan_from_raw(...)` without it behaves exactly
  as before. That is what keeps the eval harness free of a progress bus.

Node frames are published but deliberately **not** written to the job row. `update_progress`
is a DynamoDB write, and nine extra writes per scan to move a bar is a cost the row does not
need; a client that misses them still recovers real state from the stage frames and the
report.

### One instrumentation point, two consumers

[AUDIT.md](AUDIT.md) §8.2 specifies `agent_outcome_total{agent,status}` and
`agent_duration_seconds{agent}` — emitted from this same `_timed()` call site. The hook now
exists. The OTel meter and the WebSocket read the same transitions.

---

## What remains (frontend)

> **Update (`docs/AUDIT.md` §17).** The frontend contract catch-up landed first and separately:
> `types/scan.ts` now matches the API, and `ProgressEvent` carries `node`/`node_state` as this
> document specified. `useScanProgress` still keeps only the latest event — accumulating
> `nodes: Record<string, NodeState>` remains part of the graph work below.
>
> Two of the three things this section says to lift into `lib/format.ts` are done:
> `STATUS_TEXT`/`STATUS_LABEL` and `isDegraded()` now live there, the latter because the
> predicate had been written inline in *three* places and every copy omitted
> `skipped_missing_input`.
>
> `ScoreCard.tsx` is deleted and `bandColor()` is deduplicated, both noted at the bottom of this
> file.
>
> The graph itself is still deferred, still blocked on `@xyflow/react`. Doing the contract first
> was deliberate — a graph built over types that could not express half the payload would have
> rested on the same sand.

| File | Role |
|---|---|
| `frontend/lib/pipeline.ts` | The 14-node DAG declared once, with static positions, mirroring `orchestrator.py` and the README Mermaid |
| `frontend/components/pipeline/PipelineGraph.tsx` | `<ReactFlow>` host — `fitView`, pan/zoom, `nodesDraggable={false}`, `nodesConnectable={false}` |
| `frontend/components/pipeline/PipelineNode.tsx` | Status dot, `AGENT_LABELS[id]`, `formatDuration()`, finding count |
| `frontend/components/pipeline/PipelineEdge.tsx` | Animated edge, gated on `useMotionPrefs().reduced` |
| `frontend/components/pipeline/PipelineLegend.tsx` | Status key — colour alone is not an accessible signal |
| `frontend/hooks/useScanProgress.ts` | Accumulate `nodes: Record<string, NodeState>`; today it keeps only the latest event, overwritten per message |
| `frontend/types/scan.ts` | `node` / `node_state` on `ProgressEvent` |
| `frontend/app/globals.css` | React Flow CSS variables mapped to the existing tokens |
| `frontend/app/scans/[jobId]/page.tsx` | Mount the graph in both the live and report phases |

Node state resolves in priority order: `report.outcomes` (authoritative once complete) →
accumulated per-agent events (live truth) → `progress` thresholds (fallback, and what a client
gets from a worker running the old code).

The trust fan-in node reads `report.risk.inputs_used` and `inputs_missing`, which
`FullReport` already carries and which today only feeds a count in `AgentTimings`.

### Reuse, do not rewrite

`cn()`, `Card` / `SectionHeading`, `Badge`, `AGENT_LABELS` and `formatDuration()`,
`useMotionPrefs()`, and every colour token (`text-ok`, `text-warn`, `text-critical`,
`text-faint`, `bg-accent`).

To lift into `lib/format.ts` as the first step, because each is already duplicated and the
graph would be the third copy:

- `STATUS_TEXT` / `STATUS_LABEL` — were private to `AgentTimings.tsx`
- `isDegraded(outcome)` — the predicate was written inline in both
  `app/scans/[jobId]/page.tsx` and `DegradedNotice.tsx`

### Verification when it resumes

The end-to-end check is the only one that matters: start a scan against `auditor-eval:bad`
and watch the four agent nodes **settle independently**. If they flip together, the per-agent
events are not reaching the browser and the feature is pointless. Then confirm the nodes agree
with what `AgentTimings` reports, kill the worker mid-scan to confirm failed nodes render as
failed rather than sticking on "running", and check reduced-motion and dark mode.

---

## Known unrelated breakage found on the way

`docs/learning/` was renamed to `docs/build_phases/` without updating its references. This
breaks CI now, independent of any of the above:

- ~~`.github/workflows/ci.yml:80` — `python3 docs/learning/check_code_blocks.py`, so the lint
  job fails~~ — **fixed in Phase 0**; the line now points at `docs/build_phases/`
- `.github/workflows/pages.yml:5` — stale comment
- `README.md` — roughly 15 links, including the entire phase table

~~Also noted, not in scope: `frontend/components/ScoreCard.tsx` is dead code imported nowhere
and still uses raw `text-neutral-600` classes predating the token system, and `bandColor()` is
defined identically in both `ScoreRing.tsx` and `ScoreBars.tsx`.~~ — both done in §17:
`ScoreCard.tsx` is deleted and `bandColor()` lives once in `lib/format.ts`, where it also
learned that a null score is not a zero one.
