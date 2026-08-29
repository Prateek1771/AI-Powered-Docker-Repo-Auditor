"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Card, SectionHeading } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { getHistory } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { ScanSummary } from "@/types/scan";

function band(value: number) {
  if (value >= 80) return "text-ok";
  if (value >= 50) return "text-medium";
  if (value >= 25) return "text-high";
  return "text-critical";
}

export function RecentScans({ repoId }: { repoId: string }) {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);

  useEffect(() => {
    if (!repoId) return;

    const signal = { cancelled: false };

    getHistory(repoId)
      .then((history) => {
        if (!signal.cancelled) setScans(history);
      })
      // A missing history is not worth an error state on the landing page.
      .catch(() => {
        if (!signal.cancelled) setScans([]);
      });

    return () => {
      signal.cancelled = true;
    };
  }, [repoId]);

  if (scans !== null && scans.length === 0) return null;

  return (
    <section className="mt-10">
      <SectionHeading hint={repoId}>Previous scans</SectionHeading>

      {scans === null ? (
        <div className="space-y-2">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      ) : (
        <Card className="divide-y divide-border">
          {scans.slice(0, 5).map((scan) => (
            <Link
              key={scan.job_id}
              href={`/scans/${scan.job_id}`}
              className="flex items-center gap-4 p-3 transition-colors hover:bg-surface"
            >
              <span
                className={cn(
                  "font-mono text-lg tabular-nums",
                  scan.degraded ? "text-muted" : band(scan.overall),
                )}
              >
                {scan.overall}
              </span>

              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-sm text-foreground">
                  {scan.target}
                </span>
                <span className="block text-xs text-faint">
                  {new Date(scan.scan_date).toLocaleString()}
                  {scan.degraded && " · incomplete"}
                </span>
              </span>

              <span className="font-mono text-xs text-faint">
                {scan.finding_count} findings
              </span>

              <ArrowRight aria-hidden className="size-4 shrink-0 text-faint" />
            </Link>
          ))}
        </Card>
      )}
    </section>
  );
}
