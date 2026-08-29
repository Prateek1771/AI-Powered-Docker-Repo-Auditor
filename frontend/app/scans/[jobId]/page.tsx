"use client";

import { AlertOctagon, FileWarning } from "lucide-react";
import { motion } from "motion/react";
import { use } from "react";

import { AgentTimings } from "@/components/AgentTimings";
import { DegradedNotice } from "@/components/DegradedNotice";
import { DockerfileDiff } from "@/components/DockerfileDiff";
import { EffortBreakdown } from "@/components/EffortBreakdown";
import { FindingsEmpty } from "@/components/FindingsEmpty";
import { FindingsList } from "@/components/FindingsList";
import { ScanProgress } from "@/components/ScanProgress";
import { ScoreBars } from "@/components/ScoreBars";
import { ScoreRing } from "@/components/ScoreRing";
import { SeverityStrip } from "@/components/SeverityStrip";
import { TopPriorities } from "@/components/TopPriorities";
import { Button } from "@/components/ui/Button";
import { Card, SectionHeading } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { useScanProgress } from "@/hooks/useScanProgress";
import { useScanResult } from "@/hooks/useScanResult";
import { useMotionPrefs } from "@/lib/motion";

function Shell({ children }: { children: React.ReactNode }) {
  return <main className="mx-auto max-w-5xl px-6 py-12">{children}</main>;
}

export default function ScanPage({
  params,
}: {
  params: Promise<{ jobId: string }>;
}) {
  const { jobId } = use(params);

  const { event, connection, isTerminal } = useScanProgress(jobId);

  const { summary, report, error, reload } = useScanResult(jobId, isTerminal);

  const { section, stagger } = useMotionPrefs();

  // A failed scan never reaches store_result, so there is no summary to fetch
  // and asking for one yields "Not found." - which reads as a missing job
  // rather than a failed one. The real reason already arrived over the socket:
  // the orchestrator publishes str(exc)[:200] as the step.
  if (event?.status === "failed") {
    return (
      <Shell>
        <div className="flex gap-3">
          <AlertOctagon
            aria-hidden
            className="mt-1 size-5 shrink-0 text-critical"
          />
          <div>
            <h1 className="text-lg font-semibold text-foreground">
              Scan failed
            </h1>
            <p className="mt-2 font-mono text-sm text-muted">
              {event.step || "The worker did not say why."}
            </p>
            <p className="mt-4 text-sm text-faint">
              Nothing was stored for this run, so there are no partial results
              to show.
            </p>
          </div>
        </div>
      </Shell>
    );
  }

  // Not `!isTerminal`: reload() on the abandoned path below sets summary
  // without any socket event, and gating on isTerminal alone would leave that
  // state unreachable and the button inert.
  if (!isTerminal && !summary) {
    return (
      <Shell>
        <ScanProgress event={event} connection={connection} />

        {connection === "abandoned" && (
          <Card className="mt-8 p-4">
            <p className="text-sm text-muted">
              Lost the live connection. The scan is still running on the server.
            </p>
            <Button variant="outline" onClick={reload} className="mt-3">
              Check for results
            </Button>
          </Card>
        )}

        {error && <p className="mt-4 text-sm text-muted">{error}</p>}
      </Shell>
    );
  }

  if (error && !summary) {
    return (
      <Shell>
        <p className="text-sm text-foreground">{error}</p>
        <Button variant="outline" onClick={reload} className="mt-3">
          Try again
        </Button>
      </Shell>
    );
  }

  if (!summary || !report) {
    return (
      <Shell>
        <Skeleton className="h-8 w-64" />
        <div className="mt-8 grid gap-8 sm:grid-cols-[auto_1fr]">
          <Skeleton className="size-[168px] rounded-full" />
          <Skeleton className="h-32" />
        </div>
        <Skeleton className="mt-8 h-64" />
      </Shell>
    );
  }

  const findings = report.outcomes.flatMap((outcome) => outcome.findings);
  const optimization = report.dockerfile?.optimization ?? null;
  const degradedOutcomes = report.outcomes.some(
    (outcome) =>
      outcome.status === "failed" ||
      outcome.status === "timed_out" ||
      outcome.status === "skipped_degraded_input",
  );

  return (
    <Shell>
      <motion.div
        initial="hidden"
        animate="show"
        variants={stagger}
        className="space-y-8"
      >
        <motion.header variants={section}>
          <h1 className="font-mono text-xl font-semibold text-foreground">
            {summary.target}
          </h1>
          <p className="mt-1 text-sm text-faint">
            Scanned {new Date(summary.scan_date).toLocaleString()} ·{" "}
            {summary.finding_count} finding
            {summary.finding_count === 1 ? "" : "s"}
          </p>
        </motion.header>

        {degradedOutcomes && (
          <motion.div variants={section}>
            <DegradedNotice report={report} onRescan={reload} />
          </motion.div>
        )}

        <motion.section
          variants={section}
          className="grid items-center gap-8 rounded-lg border border-border bg-surface-raised p-6 sm:grid-cols-[auto_1fr]"
        >
          <ScoreRing
            value={summary.overall}
            confidence={summary.confidence}
            label="Overall"
          />

          <ScoreBars
            confidence={summary.confidence}
            scores={[
              { label: "Security", value: summary.security },
              { label: "Efficiency", value: summary.efficiency },
              { label: "Compliance", value: summary.compliance },
            ]}
          />
        </motion.section>

        {findings.length > 0 && (
          <motion.section variants={section}>
            <SectionHeading>Severity</SectionHeading>
            <SeverityStrip findings={findings} />
          </motion.section>
        )}

        {report.risk && (
          <motion.p
            variants={section}
            className="text-sm leading-relaxed text-muted"
          >
            {report.risk.score.summary}
          </motion.p>
        )}

        {report.risk && report.risk.score.top_priorities.length > 0 && (
          <motion.div variants={section}>
            <TopPriorities priorities={report.risk.score.top_priorities} />
          </motion.div>
        )}

        <motion.section variants={section}>
          <SectionHeading
            hint={findings.length > 0 ? `${findings.length} total` : undefined}
          >
            Findings
          </SectionHeading>

          {findings.length === 0 ? (
            <FindingsEmpty degraded={summary.degraded} />
          ) : (
            <>
              <div className="mb-4">
                <EffortBreakdown findings={findings} />
              </div>
              <FindingsList findings={findings} />
            </>
          )}
        </motion.section>

        {optimization && (
          <motion.div variants={section}>
            <DockerfileDiff optimization={optimization} />
          </motion.div>
        )}

        {report.dockerfile?.status === "skipped_degraded_input" && (
          <motion.section
            variants={section}
            className="rounded-lg border border-dashed border-border-strong p-4"
          >
            <div className="flex gap-3">
              <FileWarning
                aria-hidden
                className="mt-0.5 size-4 shrink-0 text-warn"
              />
              <div>
                <h2 className="text-sm font-medium text-foreground">
                  No Dockerfile rewrite
                </h2>
                <p className="mt-1 text-sm text-muted">
                  The rewrite needs results from{" "}
                  {report.dockerfile.skipped_because.join(", ")}, which did not
                  finish. A partial rewrite could remove a fix you need.
                </p>
              </div>
            </div>
          </motion.section>
        )}

        <motion.div variants={section}>
          <AgentTimings
            outcomes={report.outcomes}
            inputsMissing={report.risk?.inputs_missing ?? []}
          />
        </motion.div>
      </motion.div>
    </Shell>
  );
}
