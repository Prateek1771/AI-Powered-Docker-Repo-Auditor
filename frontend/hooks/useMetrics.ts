"use client";

import { useEffect, useState } from "react";

import type { PanelName } from "@/lib/panels";

/** One Prometheus series: its labels, and either a range or a single point. */
export interface PromSeries {
  metric: Record<string, string>;
  values?: [number, string][];
  value?: [number, string];
}

export type MetricsState =
  | { status: "loading" }
  | { status: "ok"; series: PromSeries[]; legend: string | null }
  | { status: "not_configured" }
  | { status: "unreachable" };

/**
 * Fetch one named panel from the app's own metrics route.
 *
 * Named, not a query string: the expression lives on the server (lib/panels.ts)
 * so this cannot become an open PromQL proxy.
 *
 * `not_configured` and `unreachable` are kept apart on purpose. The first means
 * this deployment has no metrics backend at all; the second means the
 * observability profile is not running. They want different sentences, and
 * collapsing them into "error" is how a user ends up restarting the wrong
 * thing.
 */
export function useMetrics(panel: PanelName, refreshMs = 15_000): MetricsState {
  const [state, setState] = useState<MetricsState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const resp = await fetch(`/api/metrics?panel=${panel}`);

        if (cancelled) return;

        if (resp.status === 501) {
          setState({ status: "not_configured" });

          return;
        }

        if (!resp.ok) {
          setState({ status: "unreachable" });

          return;
        }

        const body = await resp.json();

        if (cancelled) return;

        setState({
          status: "ok",
          series: body.result ?? [],
          legend: body.legend ?? null,
        });
      } catch {
        if (!cancelled) setState({ status: "unreachable" });
      }
    };

    void load();

    const timer = setInterval(load, refreshMs);

    return () => {
      cancelled = true;

      clearInterval(timer);
    };
  }, [panel, refreshMs]);

  return state;
}

/** The current value of an instant panel, summed across its series. */
export function total(state: MetricsState): number {
  if (state.status !== "ok") return 0;

  return state.series.reduce(
    (sum, s) => sum + Number(s.value?.[1] ?? 0),
    0,
  );
}

/** Instant series flattened to {label, value}, biggest first. */
export function rows(
  state: MetricsState,
  label: (metric: Record<string, string>) => string,
): { label: string; value: number }[] {
  if (state.status !== "ok") return [];

  return state.series
    .map((s) => ({ label: label(s.metric), value: Number(s.value?.[1] ?? 0) }))
    .filter((r) => Number.isFinite(r.value))
    .sort((a, b) => b.value - a.value);
}
