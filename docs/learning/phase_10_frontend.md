# Phase 10 — The Frontend: Two Kinds of State, Backoff, and Honest Degradation

The UI is where every safeguard from Phases 2 through 4 either pays off or gets thrown away.

```text
     state that ARRIVES                 state that is FETCHED
   ┌────────────────────┐             ┌────────────────────┐
   │  WebSocket event   │             │  GET /scans/{id}   │
   │  progress, step    │             │  scores, findings  │
   │  lives ~90 seconds │             │  lives forever     │
   │  lossy, replayable │             │  authoritative     │
   └─────────┬──────────┘             └─────────┬──────────┘
             │                                   │
             ▼                                   ▼
      useScanProgress                     useScanResult
             │                                   │
             └─────────────────┬─────────────────┘
                               ▼
                          scan page
                               │
                     ┌─────────┴─────────┐
                     ▼                   ▼
              degraded = false     degraded = true
                     │                   │
                     ▼                   ▼
              show the score       show the score
              plainly              WITH what's missing
```

The rule for this phase:

```text
a partial result must never
render like a complete one
```

The styling here is deliberately plain. The lesson is state handling and honest presentation, not CSS.

---

# 1. Scaffold

```powershell
cd ..
npx create-next-app@latest frontend --typescript --tailwind --app --eslint --no-src-dir --import-alias "@/*"
cd frontend
```

Create `frontend/.env.local`:

```text
NEXT_PUBLIC_API_URL=http://localhost:8080
NEXT_PUBLIC_WS_URL=ws://localhost:8080
```

`NEXT_PUBLIC_` variables are inlined into the browser bundle at build time. Anything with
that prefix is public — never put a secret behind it.

One deletion before you go further. `create-next-app` writes this into `app/globals.css`:

```css
@media (prefers-color-scheme: dark) {
  :root { --background: #0a0a0a; --foreground: #ededed; }
}
```

Every component in this phase uses a single light palette — `text-neutral-900` for a
complete score, `bg-amber-50` for the degraded banner. On a machine set to dark that block
renders a **complete** score near-black on near-black while a **partial** one
(`text-neutral-500`) stays perfectly readable, which is the honesty argument running exactly
backwards. Delete it.

---

# 2. A dev token endpoint

You need a token in the browser. Cognito arrives in Phase 12, so extend the dev router from Phase 8.

In `app/api/main.py`, inside the `if DEV_AUTH:` block:

```python
    from app.dev.keys import mint_token

    @dev.get("/token")
    def dev_token(tenant_id: str = "demo-tenant") -> dict:
        return {
            "token": mint_token(tenant_id),
            "tenant_id": tenant_id,
            "expires_in": 3600,
        }
```

An endpoint that hands out tokens to anyone is exactly as dangerous as it sounds. It only mounts when `DEV_AUTH=1`, and section 15 has you verify it's absent otherwise.

---

# 3. The two-state principle

The reference implementation merges live events into one object:

```typescript
setJob((prev) => ({
  jobId,
  repoId: prev?.repoId || "",
  status: event.status as ScanStatus,
  progress: event.progress,
  startedAt: prev?.startedAt || event.timestamp,
  ...
}));
```

Every field carries a `prev?.x || fallback`, because the event doesn't contain the whole job. The state is a running merge of partial updates, and any dropped event leaves a field permanently wrong.

Progress and results are different data:

```text
progress    ephemeral, lossy, arrives unprompted, ~90s lifetime
results     durable, authoritative, fetched on demand, permanent
```

Keep them in separate hooks with separate lifecycles. When progress hits a terminal state, fetch the result. Don't try to grow one into the other.

---

# 4. Types

Create `frontend/types/scan.ts`, mirroring the backend models:

```typescript
export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type Effort = "trivial" | "moderate" | "involved";

export type Exploitability =
  | "actively_exploited"
  | "likely"
  | "unlikely"
  | "theoretical";

// All five, including skipped_degraded_input. If the type cannot express a
// failure, no component can render one.
export type AgentStatus =
  | "analysed"
  | "skipped_no_input"
  | "skipped_degraded_input"
  | "failed"
  | "timed_out";

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface ProgressEvent {
  job_id: string;
  status: ScanStatus;
  progress: number;
  step: string;
  at: string;
}

export interface ScanSummary {
  job_id: string;
  tenant_id: string;
  repo_id: string;
  tenant_repo: string;
  target: string;
  scan_date: string;
  degraded: boolean;
  confidence: number;
  overall: number;
  security: number;
  efficiency: number;
  compliance: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  report_key: string;
}

interface BaseFinding {
  severity: Severity;
  title: string;
  impact: string;
  fix: string;
  effort: Effort;
  priority: number;
}

// Discriminated on category, mirroring the backend union in
// app/models/outcomes.py. A flat interface with optional fields would drop the
// per-category evidence the agents actually produce.
export interface CVEFinding extends BaseFinding {
  category: "cve";
  vulnerability_id: string;
  exploitability: Exploitability;
}

export interface BloatFinding extends BaseFinding {
  category: "bloat";
  layer_index: number;
  wasted_bytes: number;
  root_cause_command: string;
}

export interface BaseImageFinding extends BaseFinding {
  category: "base_image";
  recommended_base: string;
  estimated_savings_bytes: number;
  breaking_risk: string;
}

export interface ComplianceFinding extends BaseFinding {
  category: "compliance";
  control_id: string;
  evidence: string;
}

export type Finding =
  | CVEFinding
  | BloatFinding
  | BaseImageFinding
  | ComplianceFinding;

export interface AgentOutcome {
  agent: string;
  status: AgentStatus;
  findings: Finding[];
  error: string | null;
  duration_seconds: number;
}

export interface FullReport {
  job_id: string;
  outcomes: AgentOutcome[];
  risk: {
    score: {
      overall: number;
      security: number;
      efficiency: number;
      compliance: number;
      summary: string;
      top_priorities: string[];
    };
    confidence: number;
    inputs_used: string[];
    inputs_missing: string[];
  } | null;
  dockerfile: {
    status: AgentStatus;
    optimization: {
      reconstructed: string;
      optimized: string;
      reconstruction_notes: string;
    } | null;
    skipped_because: string[];
  } | null;
}

/** One image on the Docker daemon the API can reach. */
export interface LocalImage {
  reference: string;
  image_id: string;
  size: string;
  created: string;
}
```

`AgentStatus` has all five values, including `skipped_degraded_input`. If your frontend types can't express a failure, your components can't render one.

---

# 5. The API client

Create `frontend/lib/api.ts`:

```typescript
import type { FullReport, LocalImage, ScanSummary } from "@/types/scan";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

let cachedToken: { value: string; expiresAt: number } | null = null;

/**
 * Fetch a dev token, reusing the cached one until it nears expiry.
 *
 * Refreshed a minute early, because a token that expires between our
 * check and the server's produces a 401 that looks like a bug.
 */
export async function getToken(): Promise<string> {
  if (cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken.value;
  }

  const resp = await fetch(`${API_URL}/dev/token`);

  if (!resp.ok) {
    throw new Error(
      "Could not get a token. Is the API running with DEV_AUTH=1?",
    );
  }

  const data = await resp.json();

  cachedToken = {
    value: data.token,
    // Refresh a minute early. A token that expires between our check and the
    // server's produces a 401 that looks like a bug.
    expiresAt: Date.now() + (data.expires_in - 60) * 1000,
  };

  return cachedToken.value;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getToken();

  const resp = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...init?.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  // Messages name the fix, not the mechanism. "Try again in an hour" tells a
  // person what to do; "HTTP 429" tells them what the protocol did.
  if (resp.status === 429) {
    throw new Error("Scan limit reached. Try again in an hour.");
  }

  if (resp.status === 404) {
    throw new Error("Not found.");
  }

  if (!resp.ok) {
    throw new Error(`Request failed (${resp.status}).`);
  }

  return resp.json() as Promise<T>;
}

/** List the images on the daemon the API can reach, empty in registry mode. */
export function listImages() {
  return request<LocalImage[]>("/api/v1/images");
}

/**
 * Upload a `docker save` tar and get back the target that names it.
 *
 * Its own fetch rather than `request`: that helper pins
 * `Content-Type: application/json`, and multipart has to set its own
 * boundary or the server cannot parse the body.
 */
export async function uploadImage(
  file: File,
): Promise<{ target: string; repo_id: string }> {
  const token = await getToken();

  const body = new FormData();

  body.append("file", file);

  const resp = await fetch(`${API_URL}/api/v1/images/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body,
  });

  if (!resp.ok) {
    const detail = await resp.json().catch(() => null);

    throw new Error(detail?.detail ?? `Upload failed (${resp.status}).`);
  }

  return resp.json();
}

/** Queue a scan and return its job id. */
export function startScan(repoId: string, target: string) {
  return request<{ job_id: string; status: string }>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ repo_id: repoId, target }),
  });
}

/** Fetch a scan's scores and counts. */
export function getSummary(jobId: string) {
  return request<ScanSummary>(`/api/v1/scans/${jobId}`);
}

/** Fetch a scan's full report, including every finding. */
export function getReport(jobId: string) {
  return request<FullReport>(`/api/v1/scans/${jobId}/report`);
}

/** Fetch previous scans of one repository, newest first. */
export function getHistory(repoId: string) {
  return request<ScanSummary[]>(`/api/v1/scans/history/${repoId}`);
}
```

The token expiry subtracts 60 seconds. A token that expires between your check and the server's check produces a 401 that looks like a bug. Always refresh early.

Error messages name the fix, not the mechanism. "Scan limit reached. Try again in an hour." tells a person what to do; "HTTP 429 Too Many Requests" tells them what the protocol did.

---

# 6. The reconnect bug

Here's the reference implementation's close handler:

```typescript
ws.current.onclose = () => {
  setConnected(false);
  if (shouldReconnect.current && jobId) {
    reconnectTimer.current = setTimeout(() => connect(), 3000);
  }
};
```

`shouldReconnect` is only set false on unmount. So:

```text
scan completes
    ↓
server closes the socket normally
    ↓
onclose fires, shouldReconnect is still true
    ↓
reconnect in 3s
    ↓
server closes it again immediately
    ↓
forever, every 3 seconds, until the tab closes
```

A user who leaves a finished scan open in a background tab makes twenty requests a minute, indefinitely.

Three separate things are missing.

**Close-code awareness.** WebSocket close codes tell you whether retrying makes sense. Our backend sends 1000 on a finished job and 1008 on an auth or authorization failure. Neither improves on retry — one is done, the other will fail identically. Only abnormal closures (1006 and friends) are worth retrying.

**Backoff.** A fixed 3-second retry against a server that is down is a request every 3 seconds from every open tab. Exponential backoff turns that into a trickle.

**A cap.** After six failed attempts something is genuinely wrong, and the honest move is to tell the user rather than retry silently forever.

---

# 7. The unmount race

There's a subtler bug in the same hook:

```typescript
const connect = useCallback(async () => {
  if (!jobId || !WS_URL) return;
  const token = await getIdToken();      // <- suspends here
  const url = `${WS_URL}?token=${token}&jobId=${jobId}`;
  ws.current = new WebSocket(url);       // <- may run after unmount
  ...
}, [jobId]);
```

If the component unmounts during `await getIdToken()`, cleanup runs and closes `ws.current` — which is still null. The await then resolves and opens a socket that nothing will ever close.

```text
t=0   effect runs, connect() called
t=1   await getIdToken() suspends
t=2   user navigates away, cleanup runs, ws.current is null
t=3   token resolves, new WebSocket(url) opens
      → orphaned socket, no cleanup path
```

Navigate back and forth a few times and you accumulate sockets, each holding a Redis subscription on the server.

The fix is a cancellation flag captured in the effect closure, checked after every await.

---

# 8. The hook, done properly

Create `frontend/hooks/useScanProgress.ts`:

```typescript
"use client";

import { useEffect, useRef, useState } from "react";

import { getToken } from "@/lib/api";
import type { ProgressEvent } from "@/types/scan";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL!;

// 1000 = the job finished and the server closed cleanly. 1008 = auth or
// authorization failure. Neither improves on retry, and retrying 1000 is the
// reference implementation's every-3-seconds-forever bug.
const NO_RETRY_CODES = new Set([1000, 1008]);
const MAX_ATTEMPTS = 6;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;

type Connection = "connecting" | "open" | "closed" | "abandoned";

/**
 * Exponential backoff with jitter, capped so retries stay polite.
 *
 * The jitter matters when a server restart drops every socket at once:
 * without it they all reconnect on the same schedule.
 */
function backoffMs(attempt: number): number {
  const base = Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);

  // Jitter matters when the API restarts: without it every open tab
  // reconnects at the same instant, is refused together, and retries together.
  return base + Math.random() * 0.3 * base;
}

/**
 * Subscribe to a job's live progress over a WebSocket.
 *
 * Reconnects with backoff, except on the close codes that mean trying
 * again cannot help - a normal close and an authorization failure are
 * both final. Reports its connection state so the UI can say the scan is
 * still running when the socket is not.
 */
export function useScanProgress(jobId: string | null) {
  const [event, setEvent] = useState<ProgressEvent | null>(null);
  const [connection, setConnection] = useState<Connection>("closed");

  const attempts = useRef(0);

  useEffect(() => {
    if (!jobId) return;

    // Captured in the effect closure and checked after every await and in
    // every callback. Without it, unmounting during getToken() leaves the
    // resolved socket open with no cleanup path.
    let cancelled = false;
    let socket: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;

    attempts.current = 0;

    const open = async () => {
      if (cancelled) return;

      setConnection("connecting");

      let token: string;

      try {
        token = await getToken();
      } catch {
        if (!cancelled) setConnection("abandoned");

        return;
      }

      if (cancelled) return;

      socket = new WebSocket(
        `${WS_URL}/ws/jobs/${jobId}?token=${encodeURIComponent(token)}`,
      );

      socket.onopen = () => {
        if (cancelled) return;

        // A connection that succeeds then drops an hour later starts over at
        // one second, not thirty.
        attempts.current = 0;

        setConnection("open");
      };

      socket.onmessage = (raw) => {
        if (cancelled) return;

        let parsed: unknown;

        try {
          parsed = JSON.parse(raw.data);
        } catch {
          console.warn("Dropping unparseable progress frame");

          return;
        }

        const data = parsed as Partial<ProgressEvent> & { type?: string };

        if (data.type === "ping") return;

        // Logged, never silently swallowed. A dropped event you cannot see is
        // a UI stuck at 40% with no explanation.
        if (typeof data.progress !== "number" || !data.status) {
          console.warn("Dropping malformed progress event", data);

          return;
        }

        setEvent(data as ProgressEvent);
      };

      socket.onclose = (closeEvent) => {
        if (cancelled) return;

        setConnection("closed");

        if (NO_RETRY_CODES.has(closeEvent.code)) return;

        if (attempts.current >= MAX_ATTEMPTS) {
          setConnection("abandoned");

          return;
        }

        const delay = backoffMs(attempts.current);

        attempts.current += 1;

        timer = setTimeout(open, delay);
      };
    };

    void open();

    return () => {
      cancelled = true;

      if (timer) clearTimeout(timer);

      socket?.close(1000);
    };
  }, [jobId]);

  const isTerminal =
    event?.status === "completed" || event?.status === "failed";

  return { event, connection, isTerminal };
}
```

Five decisions worth naming.

**`cancelled` is checked after every await and in every callback.** That closes the race from section 7.

**`NO_RETRY_CODES`** stops the infinite loop. A completed job closes with 1000 and the hook goes quiet.

**Jitter.** `Math.random() * 0.3 * base` matters when your API restarts and every open tab reconnects at once. Without jitter they arrive simultaneously, get refused together, and retry simultaneously forever.

**`attempts.current = 0` on open.** A connection that succeeds then drops an hour later starts over at one second, not thirty.

**Malformed frames are logged, not swallowed.** The reference has `catch { /* ignore malformed messages */ }` — the same silent-empty pattern we spent Phase 2 eliminating on the backend. A dropped event you can't see is a UI stuck at 40% with no explanation.

The `connection` state has four values because the UI needs to distinguish "reconnecting, hang on" from "we've stopped trying." Two booleans can't express that.

---

# 9. The result hook

Create `frontend/hooks/useScanResult.ts`:

```typescript
"use client";

import { useCallback, useEffect, useState } from "react";

import { getReport, getSummary } from "@/lib/api";
import type { FullReport, ScanSummary } from "@/types/scan";

/**
 * Load a finished scan's summary and report together.
 *
 * Every setState lands in a promise callback behind a cancellation flag,
 * so a component unmounted mid-fetch does not write to dead state.
 * `reload` is what makes the abandoned-connection path recoverable: the
 * socket can be gone while the scan is still running to completion.
 */
export function useScanResult(jobId: string | null, ready: boolean) {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [report, setReport] = useState<FullReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Every setState lands in a promise callback rather than in the effect body.
  // That is what react-hooks/set-state-in-effect asks for, and the `signal`
  // closes the same unmount race section 7 makes a whole argument about for
  // useScanProgress - navigating away mid-fetch must not resolve into state.
  const load = useCallback(
    (signal: { cancelled: boolean }) => {
      if (!jobId) return Promise.resolve();

      return Promise.all([getSummary(jobId), getReport(jobId)])
        .then(([nextSummary, nextReport]) => {
          if (signal.cancelled) return;

          setSummary(nextSummary);
          setReport(nextReport);
          setError(null);
        })
        .catch((err: unknown) => {
          if (signal.cancelled) return;

          setError(
            err instanceof Error ? err.message : "Could not load results.",
          );
        });
    },
    [jobId],
  );

  useEffect(() => {
    if (!ready) return;

    const signal = { cancelled: false };

    void load(signal);

    return () => {
      signal.cancelled = true;
    };
  }, [ready, load]);

  const reload = useCallback(() => void load({ cancelled: false }), [load]);

  return { summary, report, error, reload };
}
```

Two hooks, two lifecycles. `useScanProgress` runs while the scan runs; `useScanResult` fires once when `ready` flips true. Neither reaches into the other's state.

---

# 10. Rendering degradation honestly

> **A note on the code in this section and the next.** The components below are the minimal
> version that makes the argument, and they are what this phase is about. The shipped
> components in `frontend/components/` have since been rebuilt on a design system with
> animation, so they no longer match these blocks byte-for-byte — `docs/learning/check_code_blocks.py`
> lists them as exempt. What survives unchanged is the logic the argument rests on:
> `DegradedNotice` still excludes `skipped_no_input`, `FindingsEmpty` still renders two
> different messages for the same zero, and `ScoreCard`'s confidence signal still makes a
> partial score visually distinct. The six tests in section 13 pass against both versions,
> which is the point of writing them against behaviour rather than markup.

This is the section the whole course has been building toward.

Phase 3 made agents fail without killing the scan. Phase 4 made the optimizer refuse on bad input and the scorer report computed confidence. All of that is wasted if the UI renders a degraded scan identically to a complete one — which is what the reference implementation does. Its `Scores` type has no confidence field and its components never mention a failed agent.

Create `frontend/components/DegradedNotice.tsx`:

```typescript
import type { FullReport } from "@/types/scan";

const AGENT_LABELS: Record<string, string> = {
  cve_analyst: "Vulnerability analysis",
  bloat_detective: "Image size analysis",
  base_image_strategist: "Base image review",
  compliance_checker: "Compliance checks",
  dockerfile_optimizer: "Dockerfile rewrite",
  risk_scorer: "Risk scoring",
};

const STATUS_LABELS: Record<string, string> = {
  failed: "did not complete",
  timed_out: "timed out",
  skipped_degraded_input:
    "was skipped because it depends on a check that failed",
};

export function DegradedNotice({
  report,
  onRescan,
}: {
  report: FullReport;
  onRescan: () => void;
}) {
  // skipped_no_input is deliberately absent: it means the agent had nothing to
  // analyse because the image was clean, which is a correct outcome. Treat it
  // as degradation and every healthy scan gets a banner, which teaches people
  // to ignore the banner.
  const broken = report.outcomes.filter(
    (outcome) =>
      outcome.status === "failed" ||
      outcome.status === "timed_out" ||
      outcome.status === "skipped_degraded_input",
  );

  if (broken.length === 0) return null;

  return (
    <section
      role="status"
      className="rounded border-l-4 border-amber-500 bg-amber-50 p-4"
    >
      <h2 className="font-semibold text-amber-900">This scan is incomplete</h2>

      <p className="mt-1 text-sm text-amber-900">
        {broken.length} of {report.outcomes.length} checks did not finish. The
        findings below are partial, and the scores reflect only the checks that
        completed.
      </p>

      <ul className="mt-3 space-y-1 text-sm text-amber-900">
        {broken.map((outcome) => (
          <li key={outcome.agent}>
            <span className="font-medium">
              {AGENT_LABELS[outcome.agent] ?? outcome.agent}
            </span>{" "}
            {STATUS_LABELS[outcome.status] ?? outcome.status}
            {outcome.error ? `: ${outcome.error}` : ""}
          </li>
        ))}
      </ul>

      <button
        onClick={onRescan}
        className="mt-4 rounded bg-amber-900 px-3 py-1.5 text-sm text-white"
      >
        Run the scan again
      </button>
    </section>
  );
}
```

Note the copy. It names which checks failed and in plain terms — "Vulnerability analysis did not complete", not "cve_analyst: failed". It says what that means for the numbers on screen. It offers the action. It does not apologise, and it is never vague about what happened.

Now the score, which must carry its own confidence:

Create `frontend/components/ScoreCard.tsx`:

```typescript
export function ScoreCard({
  label,
  value,
  confidence,
}: {
  label: string;
  value: number;
  confidence: number;
}) {
  const partial = confidence < 1;

  return (
    <div className={`rounded border p-4 ${partial ? "border-dashed" : ""}`}>
      <p className="text-sm text-neutral-600">{label}</p>

      {/* The number is still shown - hiding it would be its own dishonesty -
          but a dashed border and muted numerals stop it being mistaken for a
          complete one at a glance. */}
      <p
        className={`mt-1 text-3xl font-semibold tabular-nums ${
          partial ? "text-neutral-500" : "text-neutral-900"
        }`}
      >
        {value}
        <span className="text-base font-normal text-neutral-500">/100</span>
      </p>

      {partial && (
        <p className="mt-1 text-xs text-neutral-600">
          Based on {Math.round(confidence * 100)}% of the usual inputs
        </p>
      )}
    </div>
  );
}
```

A dashed border and muted numerals for partial data. The number is still shown — hiding it would be its own kind of dishonesty — but it cannot be mistaken for a complete one at a glance.

```text
82/100  solid border, dark text     → all four inputs
82/100  dashed border, grey text    → three of four
        "Based on 75% of the usual inputs"
```

The empty state is where this matters most, because it is the exact ambiguity Phase 2 was built to eliminate:

Create `frontend/components/FindingsEmpty.tsx`:

```typescript
export function FindingsEmpty({ degraded }: { degraded: boolean }) {
  // Same zero findings, two completely different meanings. Every guard and
  // trust gate on the backend exists so this component can tell them apart.
  if (degraded) {
    return (
      <div className="rounded border border-dashed p-6 text-center">
        <p className="font-medium">No findings recorded</p>
        <p className="mt-1 text-sm text-neutral-600">
          Some checks did not finish, so this image has not been fully
          reviewed. Run the scan again for a complete picture.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded border p-6 text-center">
      <p className="font-medium">Nothing to fix</p>
      <p className="mt-1 text-sm text-neutral-600">
        Every check completed and none of them found a problem.
      </p>
    </div>
  );
}
```

Same zero findings, two completely different messages.

```text
findings 0, degraded false  →  "Nothing to fix"
findings 0, degraded true   →  "has not been fully reviewed"
```

Every guard, every `return_exceptions=True`, every trust gate exists so this component can tell those apart. Render them the same and the whole chain was theatre.

---

# 11. Never invent a metric

The reference implementation renders this:

```tsx
{scanResult.estimatedFixTime}h estimated fix time
```

And computes it like this:

```python
estimatedFixTime = len(all_findings) * 2
```

Two hours per finding, regardless of what the finding is. Bumping a base image tag and rewriting a build into multi-stage both count as two hours. The number is presented in the UI with a unit, next to real measurements, and a reader has no way to tell it apart from data.

You already have real effort data — every finding carries `effort` from a model that judged it:

Create `frontend/components/EffortBreakdown.tsx`:

```typescript
import type { Finding } from "@/types/scan";

// Counts of something an agent actually assessed, rather than
// len(findings) * 2 presented in hours next to real measurements.
export function EffortBreakdown({ findings }: { findings: Finding[] }) {
  const counts = findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.effort] = (acc[finding.effort] ?? 0) + 1;

    return acc;
  }, {});

  return (
    <dl className="flex gap-6 text-sm">
      {(["trivial", "moderate", "involved"] as const).map((level) => (
        <div key={level}>
          <dt className="capitalize text-neutral-600">{level}</dt>
          <dd className="text-lg font-semibold tabular-nums">
            {counts[level] ?? 0}
          </dd>
        </div>
      ))}
    </dl>
  );
}
```

Counts of things an agent actually assessed, rather than a multiplication dressed up as an estimate.

```text
if a number appears in your UI it must
come from data or be labelled a guess
```

---

# 12. The scan page

Create `frontend/app/scans/[jobId]/page.tsx`:

```typescript
"use client";

import { use } from "react";

import { DegradedNotice } from "@/components/DegradedNotice";
import { EffortBreakdown } from "@/components/EffortBreakdown";
import { FindingsEmpty } from "@/components/FindingsEmpty";
import { ScoreCard } from "@/components/ScoreCard";
import { useScanProgress } from "@/hooks/useScanProgress";
import { useScanResult } from "@/hooks/useScanResult";

export default function ScanPage({
  params,
}: {
  params: Promise<{ jobId: string }>;
}) {
  const { jobId } = use(params);

  const { event, connection, isTerminal } = useScanProgress(jobId);

  const { summary, report, error, reload } = useScanResult(jobId, isTerminal);

  // A failed scan never reaches store_result, so there is no summary to fetch
  // and asking for one yields "Not found." - which reads as a missing job
  // rather than a failed one. The real reason already arrived over the socket:
  // the orchestrator publishes str(exc)[:200] as the step.
  if (event?.status === "failed") {
    return (
      <main className="mx-auto max-w-2xl p-8">
        <h1 className="text-xl font-semibold">Scan failed</h1>

        <p className="mt-2 text-sm text-neutral-700">
          {event.step || "The worker did not say why."}
        </p>

        <p className="mt-4 text-sm text-neutral-600">
          Nothing was stored for this run, so there are no partial results to
          show.
        </p>
      </main>
    );
  }

  // Not `!isTerminal`: reload() on the abandoned path below sets summary
  // without any socket event, and gating on isTerminal alone would leave that
  // state unreachable and the button inert.
  if (!isTerminal && !summary) {
    return (
      <main className="mx-auto max-w-2xl p-8">
        <h1 className="text-xl font-semibold">Scanning</h1>

        <div className="mt-6 h-2 overflow-hidden rounded bg-neutral-200">
          <div
            className="h-full bg-neutral-900 transition-all duration-500"
            style={{ width: `${event?.progress ?? 0}%` }}
          />
        </div>

        <p className="mt-2 text-sm text-neutral-600">
          {event?.step ?? "Waiting for the worker to pick this up"}
        </p>

        {connection === "connecting" && (
          <p className="mt-4 text-sm text-neutral-500">Reconnecting…</p>
        )}

        {connection === "abandoned" && (
          <div className="mt-4 rounded border p-4">
            <p className="text-sm">
              Lost the live connection. The scan is still running on the server.
            </p>
            <button onClick={reload} className="mt-2 text-sm underline">
              Check for results
            </button>
          </div>
        )}

        {error && <p className="mt-4 text-sm text-neutral-600">{error}</p>}
      </main>
    );
  }

  if (error && !summary) {
    return (
      <main className="mx-auto max-w-2xl p-8">
        <p>{error}</p>
        <button onClick={reload} className="mt-2 text-sm underline">
          Try again
        </button>
      </main>
    );
  }

  if (!summary || !report) {
    return <main className="mx-auto max-w-2xl p-8">Loading results…</main>;
  }

  const findings = report.outcomes.flatMap((outcome) => outcome.findings);

  return (
    <main className="mx-auto max-w-3xl space-y-6 p-8">
      <header>
        <h1 className="text-xl font-semibold">{summary.target}</h1>
        <p className="text-sm text-neutral-600">
          Scanned {new Date(summary.scan_date).toLocaleString()}
        </p>
      </header>

      <DegradedNotice report={report} onRescan={reload} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <ScoreCard
          label="Overall"
          value={summary.overall}
          confidence={summary.confidence}
        />
        <ScoreCard
          label="Security"
          value={summary.security}
          confidence={summary.confidence}
        />
        <ScoreCard
          label="Efficiency"
          value={summary.efficiency}
          confidence={summary.confidence}
        />
        <ScoreCard
          label="Compliance"
          value={summary.compliance}
          confidence={summary.confidence}
        />
      </div>

      {report.risk && (
        <p className="text-sm leading-relaxed">{report.risk.score.summary}</p>
      )}

      {findings.length === 0 ? (
        <FindingsEmpty degraded={summary.degraded} />
      ) : (
        <>
          <EffortBreakdown findings={findings} />

          <ul className="space-y-3">
            {findings
              .sort((a, b) => b.priority - a.priority)
              .map((finding, index) => (
                <li key={index} className="rounded border p-4">
                  <div className="flex items-baseline justify-between gap-4">
                    <h3 className="font-medium">{finding.title}</h3>
                    <span className="shrink-0 text-xs uppercase text-neutral-600">
                      {finding.severity} · {finding.priority}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-neutral-700">
                    {finding.impact}
                  </p>
                  <p className="mt-2 text-sm">
                    <span className="text-neutral-600">Fix: </span>
                    {finding.fix}
                  </p>
                </li>
              ))}
          </ul>
        </>
      )}

      {report.dockerfile?.status === "skipped_degraded_input" && (
        <section className="rounded border border-dashed p-4">
          <h2 className="font-medium">No Dockerfile rewrite</h2>
          <p className="mt-1 text-sm text-neutral-600">
            The rewrite needs results from{" "}
            {report.dockerfile.skipped_because.join(", ")}, which did not
            finish. A partial rewrite could remove a fix you need.
          </p>
        </section>
      )}
    </main>
  );
}
```

Four things here are load-bearing.

The gate is `!isTerminal && !summary`, not `!isTerminal` alone. The abandoned branch below
calls `reload`, and gating on the socket alone would load `summary` into state this early
return makes unreachable — the button would re-render the same spinner. That branch is the
one path where the socket has given up and the API is the only way to find out anything, so
it is exactly when the button has to work.

The `status === "failed"` branch comes **before** the result fetch. A failed scan never
reaches `store_result`, so asking for a summary returns 404 and the client turns that into
"Not found." — telling the user their job does not exist when it ran and failed. The real
reason is already in hand: the orchestrator publishes `str(exc)[:200]` as the progress
`step`, and the socket delivered it before closing.

The `connection === "abandoned"` branch matters. When the socket gives up, the scan is still
running server-side — the UI says so and offers a manual check, rather than spinning forever
or claiming failure.

The `skipped_degraded_input` block explains *why* there's no Dockerfile. Phase 4 decided the
optimizer should refuse rather than produce something misleading; this is where a user finds
out that decision was made on their behalf.

One page left. Nothing so far can *start* a scan — `startScan` and `getHistory` in section 5
have no caller, and `create-next-app` left a boilerplate `app/page.tsx` that has to go
anyway. Replacing it with a form is less code than deleting the template.

Replace `frontend/app/page.tsx`:

```typescript
"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { startScan } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();

  const [target, setTarget] = useState("python:3.8");
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const submit = async (formEvent: React.FormEvent) => {
    formEvent.preventDefault();

    setStarting(true);
    setError(null);

    try {
      // The repo id is the image name without its tag, matching what
      // app/scripts/enqueue.py does.
      const { job_id } = await startScan(target.split(":")[0], target);

      router.push(`/scans/${job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start a scan.");

      setStarting(false);
    }
  };

  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-xl font-semibold">Scan a container image</h1>

      <form onSubmit={submit} className="mt-6 flex gap-2">
        <label htmlFor="target" className="sr-only">
          Image reference
        </label>

        <input
          id="target"
          value={target}
          onChange={(inputEvent) => setTarget(inputEvent.target.value)}
          placeholder="python:3.8"
          className="flex-1 rounded border px-3 py-2 text-sm"
        />

        <button
          type="submit"
          disabled={starting || !target.trim()}
          className="rounded bg-neutral-900 px-4 py-2 text-sm text-white disabled:opacity-50"
        >
          {starting ? "Starting…" : "Scan"}
        </button>
      </form>

      {error && <p className="mt-4 text-sm text-red-700">{error}</p>}

      <p className="mt-6 text-sm text-neutral-600">
        The image is pulled and scanned on the server. Progress streams live;
        results are stored when it finishes.
      </p>
    </main>
  );
}
```

`getHistory` still has no caller. A repo history view is its own scope.

---

# 13. Tests

```powershell
npm install -D vitest @testing-library/react @testing-library/dom @testing-library/jest-dom jsdom @vitejs/plugin-react
```

`@testing-library/dom` is a *peer* of `@testing-library/react` 16, not a transitive
dependency, so it has to be named explicitly.

Create `frontend/vitest.config.mts` — the `.mts` extension matters, or Vite loads the
config as CommonJS, warns about it, and leaves `__dirname` undefined:

```typescript
import path from "path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    // Installing @testing-library/jest-dom does not register its matchers.
    // Without this, toBeEmptyDOMElement() below is undefined at call time.
    setupFiles: ["./vitest.setup.ts"],
  },
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "./") },
  },
});
```

Create `frontend/vitest.setup.ts`:

```typescript
import "@testing-library/jest-dom/vitest";
```

One line, and without it two of the six tests below fail with `toBeEmptyDOMElement is not
a function` — which reads like a broken component rather than a missing import.

Create `frontend/components/__tests__/degraded.test.tsx`:

```typescript
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DegradedNotice } from "@/components/DegradedNotice";
import { FindingsEmpty } from "@/components/FindingsEmpty";
import type { AgentStatus, FullReport } from "@/types/scan";

function report(statuses: AgentStatus[]): FullReport {
  return {
    job_id: "j1",
    outcomes: statuses.map((status, i) => ({
      agent: ["cve_analyst", "bloat_detective", "risk_scorer"][i],
      status,
      findings: [],
      error: status === "failed" ? "timeout after 120s" : null,
      duration_seconds: 1,
    })),
    risk: null,
    dockerfile: null,
  };
}

describe("DegradedNotice", () => {
  it("renders nothing when every check completed", () => {
    const { container } = render(
      <DegradedNotice
        report={report(["analysed", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("names the check that failed in plain language", () => {
    render(
      <DegradedNotice
        report={report(["failed", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(screen.getByText(/Vulnerability analysis/)).toBeDefined();
    expect(screen.getByText(/incomplete/i)).toBeDefined();
  });

  it("counts a skipped dependent check as incomplete", () => {
    render(
      <DegradedNotice
        report={report(["analysed", "skipped_degraded_input", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(screen.getByText(/depends on a check that failed/)).toBeDefined();
  });

  it("does not flag a clean image that was skipped for having no input", () => {
    const { container } = render(
      <DegradedNotice
        report={report(["skipped_no_input", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});

describe("FindingsEmpty", () => {
  it("says the image is clean when nothing failed", () => {
    render(<FindingsEmpty degraded={false} />);

    expect(screen.getByText("Nothing to fix")).toBeDefined();
  });

  it("says the review is incomplete when something failed", () => {
    render(<FindingsEmpty degraded />);

    expect(screen.getByText(/not been fully reviewed/)).toBeDefined();
  });
});
```

Add to `package.json`:

```json
"scripts": {
  "test": "vitest run"
}
```

```powershell
npm test
```

The fourth `DegradedNotice` test is the important one. `skipped_no_input` means the agent had nothing to analyse because the image was clean — a correct outcome, not a failure. Treat it as degradation and every scan of a healthy image gets a warning banner, which trains users to ignore the banner entirely.

And the two `FindingsEmpty` tests are the whole architecture reduced to two assertions: zero findings means two different things, and the UI has to say which.

---

# 14. Run it

Four containers, three processes.

```powershell
docker start dynamodb-local elasticmq redis
```

API:

```powershell
$env:DEV_AUTH = "1"
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run uvicorn app.api.main:app --port 8080 --reload
```

Worker:

```powershell
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run python -m app.main
```

Frontend:

```powershell
cd frontend
npm run dev
```

Open `http://localhost:3000`, submit the form, and it routes you to the scan page.

Four things to verify.

**The bar moves.** Progress advances through the phases and the step text changes.

**The reconnect stops.** DevTools → Network → WS shows one closed socket and no new
attempts, but the assertion is easier to run than to watch. On a page whose scan has already
finished, paste this into the console and wait:

```javascript
window.__ws = 0;
const Real = window.WebSocket;
window.WebSocket = function (...a) { window.__ws++; return new Real(...a); };
// twenty seconds later:
window.__ws;   // 0
```

Zero. Patching the constructor *after* mount is the point — only reconnects get counted.
Swap in the reference's `setTimeout(() => connect(), 3000)` and it is six, and it never
stops.

**Backoff works.** Stop the API mid-scan. The hook should retry at roughly 1s, 2s, 4s, 8s, 16s, 30s and then show "Lost the live connection." Restart the API and reload.

**Degradation shows.** Set `CVE_MODEL` to a nonexistent model in the worker, scan again, and
confirm you get the amber banner naming the failed check, dashed borders on the score cards,
and an explanation of the missing Dockerfile rewrite. Every agent shares that one model
constant, so all six fail and confidence lands at 0% — which is the case worth seeing, zero
findings rendered as *"has not been fully reviewed"* rather than *"Nothing to fix"*.

For the partial case — a dashed card with a real number on it — break exactly one agent
instead. A `raise` at the top of `run_cve_analyst` does it: the other three still run, the
trust gate skips `dockerfile_optimizer`, and `risk_scorer` reports 0.75.

That last test is the one to actually run. It is the only way to know the honesty work in
this phase functions.

---

# 15. Quality gate

```powershell
cd frontend
npm run lint
npx tsc --noEmit
npm test
npm run build
```

Then confirm the dev token endpoint is properly gated:

```powershell
# stop the API, restart WITHOUT DEV_AUTH, then:
curl.exe -i http://localhost:8080/dev/token
```

Expect a 404. If you get a token, the gate is broken and you have an endpoint that mints credentials for anyone.

You should have:

```text
✓ Progress and results in separate hooks with separate lifecycles
✓ Reconnect stops on close codes 1000 and 1008
✓ Exponential backoff with jitter and an attempt cap
✓ Cancellation flag closes the unmount race
✓ Malformed frames logged, never silently dropped
✓ Failed checks named in plain language with a next action
✓ Partial scores visually distinct from complete ones
✓ Zero findings renders two different messages
✓ No invented metrics; effort counts come from agent output
✓ Dev token endpoint absent without DEV_AUTH
```

---

# 16. Where this sits

```text
 Phase 8       Phase 9          Phase 10  ◄── here
┌──────────┐ ┌─────────────┐ ┌──────────────────┐
│ API +    │→│ live        │→│ UI that tells    │
│ authz    │ │ progress    │ │ the truth        │
└──────────┘ └─────────────┘ └──────────────────┘
                                      │
                                      ▼
                             ┌──────────────────┐
                             │    Phase 11      │
                             │  containerise    │
                             └──────────────────┘
```

The product works end to end on your laptop. Everything from here is packaging and deployment.

The thing worth keeping from this phase is narrow and general: **the UI is the last place a system can lie.** You can build careful guards, timeouts, trust gates, and confidence arithmetic through five phases, and one component that renders 82 the same way whether it rests on four inputs or two throws all of it away. The backend can only make honesty *possible*.

---

# Errata — found while implementing this phase

*The code above has been corrected. This section records what was wrong with it and why,
which is the part worth keeping.*

**`useScanResult` fails Next 16's lint, and has the exact race section 7 warns about.**
`eslint-config-next` 16 ships `react-hooks/set-state-in-effect`, and §9's hook trips it:

```text
hooks/useScanResult.ts:36:21  error  Avoid calling setState() directly within an effect
  35 |   useEffect(() => {
> 36 |     if (ready) void load();
```

`load` runs `setLoading(true)` synchronously before its first `await`, so the effect body
sets state and cascades a render. The rule's own message names the fix — set state *in a
callback*, not in the effect body — and taking it seriously fixes a second bug for free.

§7 makes an entire section out of the unmount race in `useScanProgress`, then §9 writes a
sibling hook with the identical race and no flag: navigate away mid-fetch and both
`setSummary` and `setReport` land on an unmounted component. Restructuring so every
`setState` sits inside a promise callback gives somewhere natural to put the check:

```typescript
const load = useCallback(
  (signal: { cancelled: boolean }) => {
    if (!jobId) return Promise.resolve();

    return Promise.all([getSummary(jobId), getReport(jobId)])
      .then(([nextSummary, nextReport]) => {
        if (signal.cancelled) return;
        setSummary(nextSummary);
        setReport(nextReport);
        setError(null);
      })
      .catch((err: unknown) => {
        if (signal.cancelled) return;
        setError(err instanceof Error ? err.message : "Could not load results.");
      });
  },
  [jobId],
);

useEffect(() => {
  if (!ready) return;
  const signal = { cancelled: false };
  void load(signal);
  return () => { signal.cancelled = true; };
}, [ready, load]);
```

`loading` goes away entirely — §12 never destructures it, and it was the only thing forcing
a synchronous `setState`. `reload` stays as a plain callback, where setting state is fine
because an event handler is not an effect.

**"Check for results" does nothing.** §12 gates the whole page on `if (!isTerminal)`, and
the `connection === "abandoned"` branch sits inside that early return with
`onClick={reload}`. `reload` loads `summary` and `report` into state the early return makes
unreachable, so the button re-renders the same spinner forever. That branch is the one path
where the socket has given up and the API is the only way to find out what happened, which
is exactly when the button needs to work.

```diff
- if (!isTerminal) {
+ if (!isTerminal && !summary) {
```

Show results once you have them, regardless of how you found out.

**A failed scan renders as "Not found."** A scan that throws never reaches `store_result` —
`run_and_store`'s failure path only calls `_report` — so `GET /scans/{id}` 404s and §5's
client turns that into `"Not found."` next to a "Try again" button. The user is told their
job does not exist when it ran and failed.

The real reason is already on the client. The orchestrator publishes `str(exc)[:200]` as the
progress `step`, and the WebSocket delivered it before the socket closed:

```typescript
if (event?.status === "failed") {
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-xl font-semibold">Scan failed</h1>
      <p className="mt-2 text-sm text-neutral-700">
        {event.step || "The worker did not say why."}
      </p>
      ...
```

Branch on it *before* the result fetch, rather than asking for a result that will never
exist.

**`toBeEmptyDOMElement()` is never registered.** §13 installs `@testing-library/jest-dom`
and never imports it, so two of the six tests fail with "not a function". Vitest needs a
setup file:

```typescript
// vitest.setup.ts
import "@testing-library/jest-dom/vitest";
```

referenced as `test: { setupFiles: ["./vitest.setup.ts"] }`.

**Two more things about the vitest config.** `@testing-library/dom` is a *peer* of
`@testing-library/react` 16, not a transitive dependency, so it belongs in the install line.
And `__dirname` is undefined in the config as loaded — use `import.meta.dirname`, or name
the file `vitest.config.mts`, which is the cleaner fix and also silences

```text
(!) Your Vite config uses features that are unsupported by `configLoader: 'native'`
  - ESM syntax in a file loaded as CommonJS (vitest.config.ts:1:1)
```

**`create-next-app` ships a dark mode the components cannot survive.** The generated
`app/globals.css` carries

```css
@media (prefers-color-scheme: dark) {
  :root { --background: #0a0a0a; --foreground: #ededed; }
}
```

and every component in §10 and §11 uses a single light palette — `text-neutral-900` for a
complete score, `bg-amber-50` for the degraded banner. On a machine set to dark, a *complete*
score renders near-black on near-black and is invisible, while a *partial* one
(`text-neutral-500`) stays readable. The honesty argument runs backwards: the trustworthy
number is the one that disappears. Delete the block; the phase is not about CSS.

**`EffortBreakdown` is written and never mounted.** §11's argument is that real effort counts
should *replace* the reference implementation's `len(all_findings) * 2`. Leaving the
component unrendered removes the invented number without supplying the real one. Render it
above the findings list.

**Nothing can start a scan.** §12 builds only `/scans/[jobId]`, §5 exports `startScan` and
`getHistory` that nothing calls, and §14 tells you to start the scan from the API and paste
the id into the URL. `create-next-app` leaves a boilerplate `app/page.tsx` that has to go
anyway, so replacing it with a form that calls `startScan` and routes to the scan page is
*less* code than deleting the template. `getHistory` is still unused.

**Type notes.** `Finding` should be a discriminated union on `category`, mirroring
`app/models/outcomes.py`. §4's flat interface with optional fields silently drops six fields
the agents produce — `exploitability`, `root_cause_command`, `recommended_base`,
`estimated_savings_bytes`, `breaking_risk`, `evidence` — which is the same argument §4 makes
about `AgentStatus` applied one level down. `ScanSummary` is also missing `tenant_repo`.

**What the proof looks like when it works.** The same page, three scans.

Complete — solid borders, dark numerals, no banner, effort counts from agent output:

```text
Overall 25/100   Security 20/100   Efficiency 40/100   Compliance 30/100
Trivial 10       Moderate 4        Involved 1
```

One agent broken — the trust cascade rendered honestly, and the number the `ScoreCard` was
written for:

```text
This scan is incomplete
  2 of 6 checks did not finish.
  Vulnerability analysis did not complete: ...
  Dockerfile rewrite was skipped because it depends on a check that failed

Overall 40/100  (dashed, muted)
  Based on 75% of the usual inputs
```

Every agent broken (`CVE_MODEL` pointed at a nonexistent model), which is the case the whole
course was building toward:

```text
Overall 0/100   Based on 0% of the usual inputs

No findings recorded
  Some checks did not finish, so this image has not been fully reviewed.
```

Zero findings, and the UI says *which* zero. Render that as "Nothing to fix" and every guard,
timeout and trust gate from Phases 2 through 4 was theatre.

**The reconnect check, made falsifiable.** DevTools works, but the assertion is easier to run
than to watch. Patch the constructor on an already-completed scan page and wait:

```javascript
window.__ws = 0;
const Real = window.WebSocket;
window.WebSocket = function (...a) { window.__ws++; return new Real(...a); };
// 20 seconds later: __ws === 0
```

Zero. With `setTimeout(() => connect(), 3000)` and no close-code check it is six, and it
never stops.

---

## Next: Phase 11 — Containerisation

Three images from one repository, and every line in each Dockerfile is now something you can justify.

```text
   worker image              api image              frontend image
   ┌────────────┐          ┌────────────┐         ┌────────────┐
   │ python     │          │ python     │         │ node build │
   │ + trivy    │          │ slim       │         │     ↓      │
   │ + vuln DB  │          │            │         │ standalone │
   │ baked in   │          │            │         │ runtime    │
   └────────────┘          └────────────┘         └────────────┘
     same build context, different targets
```

You'll be scanning your own images with your own scanner, which is the closest thing this project has to a victory lap. The bad fixture from Phase 5 gives you the failing baseline to compare against.

```text
1. why the vulnerability DB goes in at build time,
   and what it costs you when it doesn't

2. why cleanup must happen in the SAME layer as the
   install — the "ghost file" your bloat agent hunts

3. multi-stage builds where the compiler never
   reaches the runtime image

4. running as non-root, and what breaks when you
   add USER to an image that assumed root
```

Then you point the auditor at its own worker image and see what score it gives you. If it comes back under 80, you have work to do — and you'll have written the tool that told you.