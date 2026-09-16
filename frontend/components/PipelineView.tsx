"use client";

import { Check, Circle, Loader2, X } from "lucide-react";

import { cn } from "@/lib/cn";
import { AGENT_LABELS, STATUS_LABEL, STATUS_TEXT } from "@/lib/format";
import type { AgentStatus } from "@/types/scan";

/**
 * The nine nodes of a scan, lighting up as they settle.
 *
 * Order and names mirror _SCANNER_NODES and _AGENT_NODES in
 * app/orchestrator.py - the scanners run together, then four agents run
 * together, then two that depend on their output run in sequence.
 *
 * The data for this has been arriving over the WebSocket since the progress
 * layer was built and was thrown away on receipt, so a running scan showed a
 * single bar and no clue which of nine things was working - or which one was
 * hanging. See docs/audits/audit-02-frontend-worker-observability.md.
 */

const SCANNERS = ["trivy", "docker_history", "image_inspect"];

const AGENTS = [
  "cve_analyst",
  "bloat_detective",
  "base_image_strategist",
  "compliance_checker",
  "dockerfile_optimizer",
  "risk_scorer",
];

function isAgentStatus(value: string): value is AgentStatus {
  return value in STATUS_LABEL;
}

function Node({ name, state }: { name: string; state?: string }) {
  const settled = Boolean(state) && state !== "running";
  const running = state === "running";

  const bad =
    state === "failed" || state === "timed_out" || state?.startsWith("skipped");

  return (
    <li className="flex items-center gap-2.5 py-1.5">
      <span className="flex size-4 shrink-0 items-center justify-center">
        {running ? (
          <Loader2 aria-hidden className="size-3.5 animate-spin text-accent" />
        ) : settled ? (
          bad ? (
            <X aria-hidden className="size-3.5 text-warn" />
          ) : (
            <Check aria-hidden className="size-3.5 text-ok" />
          )
        ) : (
          <Circle aria-hidden className="size-2 text-border-strong" />
        )}
      </span>

      <span
        className={cn(
          "text-sm",
          settled || running ? "text-foreground" : "text-faint",
        )}
      >
        {AGENT_LABELS[name] ?? name}
      </span>

      <span
        className={cn(
          "ml-auto text-xs",
          // Reuse the report's own status vocabulary rather than inventing a
          // second one, so "input never arrived" reads the same in both places.
          state && isAgentStatus(state) ? STATUS_TEXT[state] : "text-faint",
        )}
      >
        {running
          ? "running"
          : state
            ? isAgentStatus(state)
              ? STATUS_LABEL[state]
              : state
            : "queued"}
      </span>
    </li>
  );
}

export function PipelineView({ nodes }: { nodes: Record<string, string> }) {
  // Node frames are published to the bus and deliberately NOT written to the
  // job row - nine extra DynamoDB writes per scan to move a bar is a cost the
  // row does not need. The consequence is that they cannot be replayed: a
  // client that subscribes late gets the stage snapshot and no node history.
  //
  // So render nothing rather than nine rows reading "queued" over a scan that
  // is already storing its results. An empty pipeline is honest; a pipeline
  // claiming nothing has started is not.
  if (Object.keys(nodes).length === 0) return null;

  // A client that subscribes mid-scan missed the earlier frames, and showing
  // the scanners as "queued" while an agent is already analysed is a state the
  // pipeline cannot be in. The ordering is guaranteed rather than guessed:
  // run_scan awaits _fetch_raw - all three scanners - before run_scan_from_raw
  // starts any agent, and a scanner failure is fatal to the scan. So if any
  // agent has reported at all, every scanner finished and finished cleanly.
  const anyAgentReported = AGENTS.some((name) => nodes[name]);

  const resolved: Record<string, string> = anyAgentReported
    ? { ...Object.fromEntries(SCANNERS.map((n) => [n, "analysed"])), ...nodes }
    : nodes;

  const done = Object.values(resolved).filter((s) => s !== "running").length;

  return (
    <section className="mt-6 rounded-lg border border-border bg-surface-raised p-4">
      <div className="mb-2 flex items-baseline justify-between gap-4">
        <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-faint">
          Pipeline
        </h2>
        <span className="text-xs text-faint">
          {done} of {SCANNERS.length + AGENTS.length} settled
        </span>
      </div>

      <div className="grid gap-x-8 sm:grid-cols-2">
        <div>
          <p className="mb-1 text-xs text-faint">Scanners</p>
          <ul className="divide-y divide-border">
            {SCANNERS.map((name) => (
              <Node key={name} name={name} state={resolved[name]} />
            ))}
          </ul>
        </div>

        <div className="mt-4 sm:mt-0">
          <p className="mb-1 text-xs text-faint">Agents</p>
          <ul className="divide-y divide-border">
            {AGENTS.map((name) => (
              <Node key={name} name={name} state={resolved[name]} />
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
