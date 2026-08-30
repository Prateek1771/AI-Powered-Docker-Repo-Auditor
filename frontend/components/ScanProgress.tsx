"use client";

import { Check, Loader2, Radio, WifiOff } from "lucide-react";
import { motion } from "motion/react";

import { cn } from "@/lib/cn";
import { useMotionPrefs } from "@/lib/motion";
import type { ProgressEvent } from "@/types/scan";

/** Mirrors the four _report() calls in app/orchestrator.py. */
const STEPS = [
  { at: 10, label: "Fetching image data" },
  { at: 40, label: "Running agents" },
  { at: 90, label: "Storing results" },
  { at: 100, label: "Complete" },
];

type Connection = "connecting" | "open" | "closed" | "abandoned";

const CONNECTION_COPY: Record<Connection, { text: string; tone: string }> = {
  open: { text: "live", tone: "text-ok" },
  connecting: { text: "reconnecting", tone: "text-warn" },
  closed: { text: "reconnecting", tone: "text-warn" },
  abandoned: { text: "offline", tone: "text-critical" },
};

/**
 * Show a running scan's stage and the health of its live connection.
 *
 * The connection state is surfaced rather than hidden, because a dropped
 * socket does not mean a dropped scan and the user needs that told to
 * them rather than inferred from a stalled bar.
 */
export function ScanProgress({
  event,
  connection,
  target,
}: {
  event: ProgressEvent | null;
  connection: Connection;
  target?: string;
}) {
  const progress = event?.progress ?? 0;
  const { reduced, spring } = useMotionPrefs();
  const chip = CONNECTION_COPY[connection];

  return (
    <div>
      <div className="flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-foreground">
            {target ? (
              <span className="font-mono">{target}</span>
            ) : (
              "Scanning"
            )}
          </h1>
          <p className="mt-0.5 text-sm text-muted">
            {event?.step ?? "Waiting for a worker to pick this up"}
          </p>
        </div>

        <span className={cn("flex items-center gap-1.5 text-xs", chip.tone)}>
          {connection === "abandoned" ? (
            <WifiOff aria-hidden className="size-3" />
          ) : connection === "open" ? (
            <Radio aria-hidden className="size-3" />
          ) : (
            <Loader2 aria-hidden className="size-3 animate-spin" />
          )}
          {chip.text}
        </span>
      </div>

      <div
        className="mt-6 h-1.5 overflow-hidden rounded-full bg-border"
        role="progressbar"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Scan progress"
      >
        <motion.div
          className="h-full rounded-full bg-accent"
          initial={false}
          animate={{ width: `${progress}%` }}
          transition={spring}
        />
      </div>

      <ol className="mt-6 space-y-3">
        {STEPS.map((step) => {
          const done = progress >= step.at;
          const active = !done && progress >= (STEPS[STEPS.indexOf(step) - 1]?.at ?? 0);

          return (
            <li
              key={step.label}
              className={cn(
                "flex items-center gap-3 text-sm transition-colors",
                done ? "text-foreground" : active ? "text-muted" : "text-faint",
              )}
            >
              <span
                className={cn(
                  "flex size-5 shrink-0 items-center justify-center rounded-full border",
                  done
                    ? "border-ok/50 bg-ok/10 text-ok"
                    : active
                      ? "border-accent/50 bg-accent/10 text-accent"
                      : "border-border text-faint",
                )}
              >
                {done ? (
                  <motion.span
                    initial={reduced ? false : { scale: 0.6, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ duration: reduced ? 0 : 0.2 }}
                  >
                    <Check aria-hidden className="size-3" />
                  </motion.span>
                ) : active ? (
                  <Loader2 aria-hidden className="size-3 animate-spin" />
                ) : (
                  <span aria-hidden className="size-1 rounded-full bg-current" />
                )}
              </span>

              {step.label}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
