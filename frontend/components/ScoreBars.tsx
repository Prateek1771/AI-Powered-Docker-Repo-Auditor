"use client";

import { motion } from "motion/react";

import { cn } from "@/lib/cn";
import { bandColor, NOT_ASSESSED } from "@/lib/format";
import { useMotionPrefs } from "@/lib/motion";

/** Show the security, efficiency and compliance scores as bars. */
export function ScoreBars({
  scores,
  confidence,
}: {
  scores: { label: string; value: number | null }[];
  confidence: number;
}) {
  const partial = confidence < 1;
  const { reduced } = useMotionPrefs();

  return (
    <dl className="w-full space-y-4">
      {scores.map(({ label, value }, index) => (
        <div key={label} className="grid grid-cols-[7.5rem_1fr_3rem] items-center gap-3">
          <dt className="text-xs uppercase tracking-[0.12em] text-faint">
            {label}
          </dt>

          <div
            className={cn(
              "h-1.5 overflow-hidden rounded-full bg-border",
              partial && "opacity-70",
            )}
          >
            <motion.div
              className="h-full rounded-full"
              style={{ background: bandColor(value) }}
              /* `${null}%` is the literal string "null%", an invalid CSS
                 width. An unassessed axis draws no bar at all. */
              initial={{ width: reduced ? `${value ?? 0}%` : 0 }}
              animate={{ width: `${value ?? 0}%` }}
              transition={
                reduced
                  ? { duration: 0 }
                  : { duration: 0.9, delay: 0.15 + index * 0.08, ease: [0.16, 1, 0.3, 1] }
              }
            />
          </div>

          <dd
            className={cn(
              "text-right font-mono text-sm tabular-nums",
              value === null ? "text-faint" : partial ? "text-muted" : "text-foreground",
            )}
            title={value === null ? NOT_ASSESSED : undefined}
          >
            {value === null ? "--" : value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
