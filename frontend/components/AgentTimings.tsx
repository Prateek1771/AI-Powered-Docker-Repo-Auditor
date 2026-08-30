import { Card, SectionHeading } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import { AGENT_LABELS, formatDuration } from "@/lib/format";
import type { AgentOutcome, AgentStatus } from "@/types/scan";

const STATUS_TEXT: Record<AgentStatus, string> = {
  analysed: "text-ok",
  skipped_no_input: "text-faint",
  skipped_degraded_input: "text-warn",
  failed: "text-critical",
  timed_out: "text-critical",
};

const STATUS_LABEL: Record<AgentStatus, string> = {
  analysed: "analysed",
  skipped_no_input: "nothing to analyse",
  skipped_degraded_input: "skipped",
  failed: "failed",
  timed_out: "timed out",
};

/**
 * Show how long each agent took and which of them can be trusted.
 *
 * Every agent is listed including the ones that failed, because the
 * absence of an agent is itself the finding.
 */
export function AgentTimings({
  outcomes,
  inputsMissing,
}: {
  outcomes: AgentOutcome[];
  inputsMissing: string[];
}) {
  const slowest = Math.max(...outcomes.map((o) => o.duration_seconds), 0.001);

  return (
    <section>
      <SectionHeading
        hint={
          inputsMissing.length > 0
            ? `${inputsMissing.length} input${inputsMissing.length === 1 ? "" : "s"} missing`
            : undefined
        }
      >
        Agents
      </SectionHeading>

      <Card className="divide-y divide-border">
        {outcomes.map((outcome) => (
          <div
            key={outcome.agent}
            className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1 p-3"
          >
            <span className="text-sm text-foreground">
              {AGENT_LABELS[outcome.agent] ?? outcome.agent}
            </span>

            <span className="font-mono text-xs tabular-nums text-faint">
              {outcome.duration_seconds > 0
                ? formatDuration(outcome.duration_seconds)
                : "—"}
            </span>

            <div className="h-1 overflow-hidden rounded-full bg-border">
              <div
                className={cn(
                  "h-full rounded-full",
                  outcome.status === "analysed" ? "bg-accent/60" : "bg-border-strong",
                )}
                style={{
                  width: `${Math.max(2, (outcome.duration_seconds / slowest) * 100)}%`,
                }}
              />
            </div>

            <span
              className={cn(
                "text-right text-xs",
                STATUS_TEXT[outcome.status],
              )}
            >
              {STATUS_LABEL[outcome.status]}
            </span>
          </div>
        ))}
      </Card>
    </section>
  );
}
