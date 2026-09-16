"use client";

import {
  BarRows,
  Panel,
  StatTile,
  TimeSeries,
} from "@/components/charts/primitives";
import { rows, total, useMetrics } from "@/hooks/useMetrics";
import { formatDuration } from "@/lib/format";

/**
 * The collector's own health.
 *
 * A different question from the Prometheus tab. That one asks what the
 * pipeline did; this one asks whether the thing carrying those numbers is
 * coping. The collector is the single egress point for every signal, so it is
 * also the single point that can quietly drop them - and until its internal
 * telemetry was exposed on :8888, nothing in this stack could say so.
 */
export function OtelTab() {
  const accepted = useMetrics("otel_accepted_points");
  const refused = useMetrics("otel_refused_points");
  const logs = useMetrics("otel_accepted_logs");
  const failures = useMetrics("otel_export_failures");
  const queue = useMetrics("otel_queue_size");
  const uptime = useMetrics("otel_uptime");

  const refusedNow = refused.status === "ok"
    ? refused.series.reduce((max, s) => {
        const last = s.values?.at(-1)?.[1];

        return Math.max(max, Number(last ?? 0));
      }, 0)
    : 0;

  const failureCount = total(failures);

  const throughput = [
    ...(accepted.status === "ok"
      ? accepted.series.map((s) => ({
          label: "accepted",
          color: "var(--ok)",
          points: (s.values ?? []).map(
            ([t, v]) => [t, Number(v)] as [number, number],
          ),
        }))
      : []),
    ...(refused.status === "ok"
      ? refused.series.map((s) => ({
          label: "refused",
          color: "var(--critical)",
          points: (s.values ?? []).map(
            ([t, v]) => [t, Number(v)] as [number, number],
          ),
        }))
      : []),
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-3">
        <StatTile
          label="Collector uptime"
          value={
            total(uptime) > 0 ? formatDuration(total(uptime)) : "—"
          }
          hint="since the container last started"
        />
        <StatTile
          label="Refused points"
          value={refusedNow.toFixed(2)}
          tone={refusedNow > 0 ? "critical" : "ok"}
          hint={
            refusedNow > 0
              ? "the memory limiter is shedding load"
              : "nothing is being dropped at the receiver"
          }
        />
        <StatTile
          label="Export failures"
          value={failureCount.toLocaleString()}
          tone={failureCount > 0 ? "critical" : "ok"}
          hint={
            failureCount > 0
              ? "points the collector could not hand on"
              : "every batch reached its backend"
          }
        />
      </div>

      <Panel
        title="Metric points through the collector"
        hint="per second, accepted vs refused"
      >
        <TimeSeries
          series={throughput}
          empty="The collector has reported no internal telemetry yet."
        />
      </Panel>

      <Panel title="Log records accepted" hint="per second">
        <TimeSeries
          series={
            logs.status === "ok"
              ? logs.series.map((s) => ({
                  label: "log records",
                  color: "var(--series-1)",
                  points: (s.values ?? []).map(
                    ([t, v]) => [t, Number(v)] as [number, number],
                  ),
                }))
              : []
          }
          empty="No log records have reached the collector in this window."
        />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Exporter queue" hint="batches waiting to be sent">
          <BarRows
            rows={rows(queue, (m) => m.exporter ?? "exporter")}
            format={(n) => n.toFixed(0)}
            empty="No exporter is queueing."
          />
        </Panel>

        <Panel title="Failed sends by exporter">
          <BarRows
            rows={rows(failures, (m) => m.exporter ?? "exporter").map((r) => ({
              ...r,
              color: r.value > 0 ? "var(--critical)" : "var(--ok)",
            }))}
            format={(n) => n.toFixed(0)}
            empty="Nothing has failed to send."
          />
        </Panel>
      </div>
    </div>
  );
}
