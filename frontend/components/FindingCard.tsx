"use client";

import {
  Boxes,
  ChevronRight,
  ExternalLink,
  HardDrive,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { cn } from "@/lib/cn";
import { CATEGORY_LABELS, formatBytes, nvdUrl } from "@/lib/format";
import type { Exploitability, Finding } from "@/types/scan";

const CATEGORY_ICON = {
  cve: ShieldAlert,
  bloat: HardDrive,
  base_image: Boxes,
  compliance: ShieldCheck,
} as const;

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
      const url = nvdUrl(finding.vulnerability_id);

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
                <span className="sr-only">(opens NVD in a new tab)</span>
              </a>
            ) : (
              <span className="font-mono">{finding.vulnerability_id}</span>
            )}
          </Detail>
          <Detail term="Exploitability">
            {EXPLOITABILITY_LABEL[finding.exploitability]}
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
  }
}

/**
 * Render one finding, expanding to the evidence its agent produced.
 *
 * Built on native details/summary, which is keyboard and screen-reader
 * operable without any of the state a custom disclosure would need.
 */
export function FindingCard({ finding }: { finding: Finding }) {
  const Icon = CATEGORY_ICON[finding.category];
  const identifier =
    finding.category === "cve"
      ? finding.vulnerability_id
      : finding.category === "compliance"
        ? finding.control_id
        : null;

  return (
    <details className="group rounded-lg border border-border bg-surface-raised open:border-border-strong">
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
          <Detail term="Impact">{finding.impact}</Detail>
          <Detail term="Fix">{finding.fix}</Detail>
          <CategoryDetails finding={finding} />
        </dl>
      </div>
    </details>
  );
}
