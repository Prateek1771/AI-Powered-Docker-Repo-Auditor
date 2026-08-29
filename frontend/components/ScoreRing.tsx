"use client";

import { animate, motion, useMotionValue, useTransform } from "motion/react";
import { useEffect } from "react";

import { cn } from "@/lib/cn";
import { useMotionPrefs } from "@/lib/motion";

const SIZE = 168;
const STROKE = 10;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function bandColor(value: number): string {
  if (value >= 80) return "var(--ok)";
  if (value >= 50) return "var(--sev-medium)";
  if (value >= 25) return "var(--sev-high)";
  return "var(--sev-critical)";
}

export function ScoreRing({
  value,
  confidence,
  label,
}: {
  value: number;
  confidence: number;
  label: string;
}) {
  const partial = confidence < 1;
  const { reduced } = useMotionPrefs();

  const progress = useMotionValue(reduced ? value : 0);
  const offset = useTransform(
    progress,
    (v) => CIRCUMFERENCE - (Math.max(0, Math.min(100, v)) / 100) * CIRCUMFERENCE,
  );
  const shown = useTransform(progress, (v) => Math.round(v));

  useEffect(() => {
    if (reduced) {
      progress.set(value);

      return;
    }

    const controls = animate(progress, value, {
      duration: 1.1,
      ease: [0.16, 1, 0.3, 1],
    });

    return () => controls.stop();
  }, [value, reduced, progress]);

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: SIZE, height: SIZE }}>
        <svg width={SIZE} height={SIZE} className="-rotate-90" aria-hidden>
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
            className="stroke-border"
            /* The track goes dashed on partial input. The arc itself cannot -
               it needs strokeDasharray for the draw-on animation - so the
               "this rests on incomplete data" signal moves here, and is
               backed by the muted numeral and the caption below. */
            {...(partial ? { strokeDasharray: "4 7" } : {})}
          />
          <motion.circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
            strokeLinecap="round"
            stroke={bandColor(value)}
            strokeDasharray={CIRCUMFERENCE}
            style={{ strokeDashoffset: offset }}
            opacity={partial ? 0.55 : 1}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="flex items-baseline">
            <motion.span
              className={cn(
                "font-mono text-5xl font-semibold tabular-nums",
                partial ? "text-muted" : "text-foreground",
              )}
            >
              {shown}
            </motion.span>
            <span className="ml-0.5 font-mono text-lg text-faint">/100</span>
          </div>
          <span className="mt-1 text-xs uppercase tracking-[0.14em] text-faint">
            {label}
          </span>
        </div>
      </div>

      {partial && (
        <p className="mt-3 max-w-[15rem] text-center text-xs text-muted">
          Based on {Math.round(confidence * 100)}% of the usual inputs
        </p>
      )}
    </div>
  );
}
