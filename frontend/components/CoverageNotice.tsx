import { SEVERITIES } from "@/lib/format";
import type { ScanCoverage } from "@/types/scan";

/**
 * Say how much of the image the report actually covers.
 *
 * Only the worst N vulnerabilities ever reach a model; the rest are counted
 * and dropped. Without this the report showed a handful of findings over an
 * image with eleven thousand vulnerabilities and implied that was all of them
 * — which is the difference between a report and a sample presented as one.
 *
 * `role="status"` rather than a bare div: this changes what the numbers below
 * it mean, so a screen reader should hear it with them.
 */
export function CoverageNotice({ coverage }: { coverage: ScanCoverage }) {
  const { total_vulnerabilities: total, sent_to_model: analysed, dropped } = coverage;

  if (total === 0) return null;

  const counts = SEVERITIES.map((severity) => ({
    severity,
    count: coverage.counts_by_severity?.[severity] ?? 0,
  })).filter(({ count }) => count > 0);

  return (
    <section
      role="status"
      className="rounded-lg border border-border bg-surface-raised p-4"
    >
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="font-mono text-2xl tabular-nums text-foreground">
          {total.toLocaleString()}
        </span>
        <span className="text-sm text-muted">
          vulnerabilities found by the scanner
        </span>
      </div>

      {dropped > 0 ? (
        <p className="mt-2 text-sm text-warn">
          {analysed.toLocaleString()} of them were analysed in depth.{" "}
          <strong className="font-medium">
            {dropped.toLocaleString()} were not
          </strong>{" "}
          — the findings below are the worst of them, not all of them.
        </p>
      ) : (
        <p className="mt-2 text-sm text-muted">
          All of them were analysed. This report is complete.
        </p>
      )}

      {counts.length > 0 && (
        <dl className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
          {counts.map(({ severity, count }) => (
            <div key={severity} className="flex items-baseline gap-1.5">
              <dt className="text-xs uppercase tracking-[0.1em] text-faint">
                {severity}
              </dt>
              <dd className="font-mono text-sm tabular-nums text-foreground">
                {count.toLocaleString()}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {/* The scanner's counts, not the model's. These come straight from
          Trivy, so they are the one number in the report nothing can
          hallucinate. */}
      <p className="mt-3 text-xs text-faint">
        Counted by {coverage.scanner_image || "the scanner"}
        {coverage.total_secrets > 0 &&
          ` · ${coverage.total_secrets} secret${coverage.total_secrets === 1 ? "" : "s"} detected`}
        {coverage.kev_available === false && " · CISA KEV feed unavailable"}
        {coverage.epss_available === false && " · EPSS feed unavailable"}
      </p>
    </section>
  );
}
