import { AlertTriangle, RotateCw } from "lucide-react";

import { Button } from "@/components/ui/Button";
import { AGENT_LABELS } from "@/lib/format";
import type { FullReport } from "@/types/scan";

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
      className="overflow-hidden rounded-lg border border-warn/40 bg-warn/[0.07]"
    >
      <div className="flex gap-3 p-4">
        <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0 text-warn" />

        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold text-foreground">
            This scan is incomplete
          </h2>

          <p className="mt-1 text-sm text-muted">
            {broken.length} of {report.outcomes.length} checks did not finish.
            The findings below are partial, and the scores reflect only the
            checks that completed.
          </p>

          <ul className="mt-3 space-y-1.5">
            {broken.map((outcome) => (
              <li key={outcome.agent} className="text-sm text-muted">
                <span className="font-medium text-foreground">
                  {AGENT_LABELS[outcome.agent] ?? outcome.agent}
                </span>{" "}
                {STATUS_LABELS[outcome.status] ?? outcome.status}
                {outcome.error ? (
                  <span className="mt-1 block break-words font-mono text-xs text-faint">
                    {outcome.error}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>

          <Button variant="outline" onClick={onRescan} className="mt-4">
            <RotateCw aria-hidden className="size-3.5" />
            Run the scan again
          </Button>
        </div>
      </div>
    </section>
  );
}
