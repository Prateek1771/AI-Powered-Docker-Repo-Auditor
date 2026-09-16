"use client";

import {
  Boxes,
  ChevronRight,
  CircleAlert,
  ExternalLink,
  HardDrive,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { cn } from "@/lib/cn";
import { CATEGORY_LABELS, formatBytes, nvdUrl } from "@/lib/format";
import type { Exploitability, Finding } from "@/types/scan";

const CATEGORY_ICON: Record<string, typeof ShieldAlert> = {
  cve: ShieldAlert,
  bloat: HardDrive,
  base_image: Boxes,
  compliance: ShieldCheck,
  secret: KeyRound,
};

// A category this build has never heard of renders with this rather than
// taking the page down. `secret` WAS that case: the lookup returned undefined,
// React threw "Element type is invalid", and with no error boundary the whole
// report was replaced by Next's error page. Typed Record<string, ...> on
// purpose - indexing by the union made TypeScript certify a lookup that was
// undefined at runtime, which is why nothing caught it.
const FALLBACK_ICON = CircleAlert;

const EXPLOITABILITY_LABEL: Record<Exploitability, string> = {
  actively_exploited: "actively exploited",
  likely: "exploitation likely",
  unlikely: "exploitation unlikely",
  theoretical: "theoretical",
};

/** Only the top two warrant colour; the rest would cry wolf. */
const EXPLOITABILITY_CLASS: Record<Exploitability, string> = {
  actively_exploited: "text-critical border-critical/40 bg-critical/10",
  likely: "text-high border-high/40 bg-high/10",
  unlikely: "",
  theoretical: "",
};

function Detail({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-3 py-1.5 max-sm:grid-cols-1 max-sm:gap-0.5">
      <dt className="text-xs uppercase tracking-[0.1em] text-faint">{term}</dt>
      <dd className="min-w-0 text-sm text-foreground">{children}</dd>
    </div>
  );
}

/**
 * The per-category fields are the whole reason types/scan.ts models Finding as
 * a union discriminated on `category` - each branch narrows and renders the
 * evidence its agent actually produced.
 */
function CategoryDetails({ finding }: { finding: Finding }) {
  switch (finding.category) {
    case "cve": {
      // primary_url is the scanner's own advisory link and is authoritative.
      // nvdUrl only guesses, and cannot resolve a GHSA or vendor id at all -
      // it stays as the fallback for reports stored before the enrichment.
      const url = finding.primary_url || nvdUrl(finding.vulnerability_id);

      const fixed = finding.fixed_version;

      return (
        <>
          <Detail term="Identifier">
            {url ? (
              <a
                href={url}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 font-mono text-accent hover:underline"
              >
                {finding.vulnerability_id}
                <ExternalLink aria-hidden className="size-3" />
                <span className="sr-only">(opens the advisory in a new tab)</span>
              </a>
            ) : (
              <span className="font-mono">{finding.vulnerability_id}</span>
            )}
          </Detail>

          {finding.package && (
            <Detail term="Package">
              <span className="font-mono">
                {finding.installed_version
                  ? `${finding.package} ${finding.installed_version}`
                  : finding.package}
              </span>
            </Detail>
          )}

          {/* The single most actionable field in a vulnerability report: is
              there a version to move to, or is nobody offering one yet. */}
          <Detail term="Fixed in">
            {fixed ? (
              <span className="font-mono text-ok">{fixed}</span>
            ) : (
              <span className="text-muted">No fix available yet</span>
            )}
          </Detail>

          {finding.cvss_score ? (
            <Detail term="CVSS">
              <span className="font-mono">{finding.cvss_score.toFixed(1)}</span>
              {finding.cvss_vector && (
                <span className="ml-2 font-mono text-xs text-faint">
                  {finding.cvss_vector}
                </span>
              )}
            </Detail>
          ) : null}

          {/* Measured, not judged. kev_listed === null means the feed was
              unavailable, which is NOT the same as "not listed" and must not
              render as a reassuring absence. */}
          {finding.kev_listed === true && (
            <Detail term="CISA KEV">
              <span className="text-critical">
                Known to be exploited in the wild
              </span>
            </Detail>
          )}

          {typeof finding.epss_score === "number" && (
            <Detail term="EPSS">
              <span className="font-mono">
                {(finding.epss_score * 100).toFixed(1)}%
              </span>
              <span className="ml-2 text-xs text-faint">
                chance of exploitation in the next 30 days
              </span>
            </Detail>
          )}

          {finding.cwe_ids && finding.cwe_ids.length > 0 && (
            <Detail term="Weakness">
              <span className="font-mono">{finding.cwe_ids.join(", ")}</span>
            </Detail>
          )}

          <Detail term="Exploitability">
            {EXPLOITABILITY_LABEL[finding.exploitability]}
            <span className="ml-2 text-xs text-faint">
              (the model&apos;s judgement)
            </span>
          </Detail>
        </>
      );
    }

    case "bloat":
      return (
        <>
          <Detail term="Wasted">{formatBytes(finding.wasted_bytes)}</Detail>
          <Detail term="Layer">
            <span className="font-mono">#{finding.layer_index}</span>
          </Detail>
          <Detail term="Root cause">
            <code className="block overflow-x-auto whitespace-pre-wrap break-words rounded bg-surface px-2 py-1.5 font-mono text-xs text-muted">
              {finding.root_cause_command}
            </code>
          </Detail>
        </>
      );

    case "base_image":
      return (
        <>
          <Detail term="Recommended">
            <span className="font-mono">{finding.recommended_base}</span>
          </Detail>
          <Detail term="Saves">
            {formatBytes(finding.estimated_savings_bytes)}
          </Detail>
          <Detail term="Breaking risk">{finding.breaking_risk}</Detail>
        </>
      );

    case "compliance":
      return (
        <>
          <Detail term="Control">
            <span className="font-mono">{finding.control_id}</span>
          </Detail>
          <Detail term="Evidence">{finding.evidence}</Detail>
        </>
      );

    case "secret":
      return (
        <>
          <Detail term="File">
            <span className="font-mono">
              {finding.line > 0
                ? `${finding.file_path}:${finding.line}`
                : finding.file_path}
            </span>
          </Detail>
          <Detail term="Rule">
            <span className="font-mono">{finding.rule_id}</span>
          </Detail>
          {/* A redaction, never the credential - the backend stores a short
              prefix and asterisks, so a report cannot leak the secret it is
              warning you about. Enough to find it, not enough to use it. */}
          <Detail term="Match">
            <span className="font-mono">{finding.redacted_match}</span>
          </Detail>
        </>
      );

    default:
      // Title, severity and fix still render above; only the per-category
      // evidence is unknown. Degrading beats an outage.
      return null;
  }
}

/**
 * Render one finding, expanding to the evidence its agent produced.
 *
 * Built on native details/summary, which is keyboard and screen-reader
 * operable without any of the state a custom disclosure would need.
 */
export function FindingCard({ finding }: { finding: Finding }) {
  const Icon = CATEGORY_ICON[finding.category] ?? FALLBACK_ICON;
  const identifier =
    finding.category === "cve"
      ? finding.vulnerability_id
      : finding.category === "compliance"
        ? finding.control_id
        : null;

  return (
    <details
      className={cn(
        "group rounded-lg border border-border bg-surface-raised open:border-border-strong",
        // Dimmed, not hidden. The backend marks rather than deletes so an
        // accepted risk stays reviewable; hiding it here would undo that.
        finding.suppressed && "opacity-60",
      )}
    >
      <summary className="flex cursor-pointer items-start gap-3 p-4">
        <ChevronRight
          aria-hidden
          className="mt-0.5 size-4 shrink-0 text-faint transition-transform group-open:rotate-90"
        />

        <Icon aria-hidden className="mt-0.5 size-4 shrink-0 text-faint" />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {identifier && (
              <span className="font-mono text-xs text-muted">{identifier}</span>
            )}
            <h3 className="text-sm font-medium text-foreground">
              {finding.title}
            </h3>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={finding.severity} />
            <Badge>{CATEGORY_LABELS[finding.category]}</Badge>
            {finding.category === "cve" &&
              EXPLOITABILITY_CLASS[finding.exploitability] && (
                <Badge className={EXPLOITABILITY_CLASS[finding.exploitability]}>
                  {EXPLOITABILITY_LABEL[finding.exploitability]}
                </Badge>
              )}
            <Badge>{finding.effort} fix</Badge>
            {finding.suppressed && (
              <Badge className="text-faint">suppressed</Badge>
            )}
          </div>
        </div>

        <span
          className="shrink-0 font-mono text-xs tabular-nums text-faint"
          title="Priority assigned by the agent"
        >
          {finding.priority}
        </span>
      </summary>

      <div className={cn("border-t border-border px-4 pb-4 pt-3", "sm:pl-15")}>
        <dl>
          {/* Stated first, because everything below it is context for a
              finding the team has already decided not to act on. */}
          {finding.suppressed && (
            <Detail term="Suppressed">
              {finding.suppressed_reason || "No reason recorded"}
              {finding.suppressed_until && (
                <span className="ml-2 text-xs text-faint">
                  until {finding.suppressed_until}
                </span>
              )}
            </Detail>
          )}
          <Detail term="Impact">{finding.impact}</Detail>
          <Detail term="Fix">{finding.fix}</Detail>
          <CategoryDetails finding={finding} />
        </dl>
      </div>
    </details>
  );
}
