import { Card } from "@/components/ui/Card";
import type { Finding } from "@/types/scan";

// Counts of something an agent actually assessed, rather than
// len(findings) * 2 presented in hours next to real measurements.
export function EffortBreakdown({ findings }: { findings: Finding[] }) {
  const counts = findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.effort] = (acc[finding.effort] ?? 0) + 1;

    return acc;
  }, {});

  return (
    <Card className="flex divide-x divide-border">
      {(["trivial", "moderate", "involved"] as const).map((level) => (
        <dl key={level} className="flex-1 px-4 py-3">
          <dt className="text-xs uppercase tracking-[0.1em] text-faint">
            {level}
          </dt>
          <dd className="mt-1 font-mono text-xl tabular-nums text-foreground">
            {counts[level] ?? 0}
          </dd>
        </dl>
      ))}
    </Card>
  );
}
