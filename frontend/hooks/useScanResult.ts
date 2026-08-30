"use client";

import { useCallback, useEffect, useState } from "react";

import { getReport, getSummary } from "@/lib/api";
import type { FullReport, ScanSummary } from "@/types/scan";

/**
 * Load a finished scan's summary and report together.
 *
 * Every setState lands in a promise callback behind a cancellation flag,
 * so a component unmounted mid-fetch does not write to dead state.
 * `reload` is what makes the abandoned-connection path recoverable: the
 * socket can be gone while the scan is still running to completion.
 */
export function useScanResult(jobId: string | null, ready: boolean) {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [report, setReport] = useState<FullReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Every setState lands in a promise callback rather than in the effect body.
  // That is what react-hooks/set-state-in-effect asks for, and the `signal`
  // closes the same unmount race section 7 makes a whole argument about for
  // useScanProgress - navigating away mid-fetch must not resolve into state.
  const load = useCallback(
    (signal: { cancelled: boolean }) => {
      if (!jobId) return Promise.resolve();

      return Promise.all([getSummary(jobId), getReport(jobId)])
        .then(([nextSummary, nextReport]) => {
          if (signal.cancelled) return;

          setSummary(nextSummary);
          setReport(nextReport);
          setError(null);
        })
        .catch((err: unknown) => {
          if (signal.cancelled) return;

          setError(
            err instanceof Error ? err.message : "Could not load results.",
          );
        });
    },
    [jobId],
  );

  useEffect(() => {
    if (!ready) return;

    const signal = { cancelled: false };

    void load(signal);

    return () => {
      signal.cancelled = true;
    };
  }, [ready, load]);

  const reload = useCallback(() => void load({ cancelled: false }), [load]);

  return { summary, report, error, reload };
}
