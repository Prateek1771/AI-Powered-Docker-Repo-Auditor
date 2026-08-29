"use client";

import { motion } from "motion/react";

import { cn } from "@/lib/cn";
import { countBySeverity, SEVERITIES } from "@/lib/format";
import { useMotionPrefs } from "@/lib/motion";
import type { Finding, Severity } from "@/types/scan";

const BAR: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  informational: "bg-informational",
};

const DOT: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  informational: "text-informational",
};

export function SeverityStrip({ findings }: { findings: Finding[] }) {
  const counts = countBySeverity(findings);
  const total = findings.length;
  const { reduced } = useMotionPrefs();

  if (total === 0) return null;

  const present = SEVERITIES.filter((s) => counts[s] > 0);

  return (
    <div>
      <div
        className="flex h-2 overflow-hidden rounded-full bg-border"
        role="img"
        aria-label={present
          .map((s) => `${counts[s]} ${s}`)
          .join(", ")}
      >
        {present.map((severity, index) => (
          <motion.div
            key={severity}
            className={BAR[severity]}
            initial={{
              width: reduced ? `${(counts[severity] / total) * 100}%` : 0,
            }}
            animate={{ width: `${(counts[severity] / total) * 100}%` }}
            transition={
              reduced
                ? { duration: 0 }
                : { duration: 0.7, delay: 0.2 + index * 0.06, ease: [0.16, 1, 0.3, 1] }
            }
          />
        ))}
      </div>

      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
        {present.map((severity) => (
          <li key={severity} className="flex items-center gap-1.5">
            <span aria-hidden className={cn("text-xs", DOT[severity])}>
              ■
            </span>
            <span className="font-mono text-sm tabular-nums text-foreground">
              {counts[severity]}
            </span>
            <span className="text-xs uppercase tracking-[0.1em] text-faint">
              {severity}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
