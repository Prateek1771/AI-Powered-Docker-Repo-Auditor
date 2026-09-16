import { Card, SectionHeading } from "@/components/ui/Card";
import type { ScanDiff } from "@/types/scan";

/**
 * What changed since the last scan of this repository.
 *
 * The single most useful thing a repeat scan can tell you, and it was computed
 * and stored for several phases while nothing displayed it. "Did my fix work?"
 * is answered by `fixed`; "did I make it worse?" by `new`.
 *
 * Joined on the finding fingerprint rather than on prose, because the wording
 * varies run to run and there would otherwise be nothing stable to compare.
 */
export function ScanDiffSummary({ diff }: { diff: ScanDiff }) {
  const rows = [
    {
      label: "New",
      count: diff.new.length,
      tone: "text-critical",
      hint: "not present in the previous scan",
    },
    {
      label: "Fixed",
      count: diff.fixed.length,
      tone: "text-ok",
      hint: "present before, gone now",
    },
    {
      label: "Still there",
      count: diff.persisting.length,
      tone: "text-muted",
      hint: "unchanged since the previous scan",
    },
  ];

  return (
    <Card as="section" className="p-4">
      <SectionHeading
        hint={
          diff.previous_scan_date
            ? `since ${diff.previous_scan_date.slice(0, 10)}`
            : undefined
        }
      >
        Since the last scan
      </SectionHeading>

      <dl className="grid grid-cols-3 gap-4">
        {rows.map(({ label, count, tone, hint }) => (
          <div key={label}>
            <dd className={`font-mono text-2xl tabular-nums ${tone}`}>
              {count}
            </dd>
            <dt className="mt-0.5 text-xs text-foreground">{label}</dt>
            <p className="mt-0.5 text-xs text-faint">{hint}</p>
          </div>
        ))}
      </dl>
    </Card>
  );
}
