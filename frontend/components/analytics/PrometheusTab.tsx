"use client";

import {
  BarRows,
  Panel,
  StatTile,
  TimeSeries,
  seriesColor,
} from "@/components/charts/primitives";
import { rows, total, useMetrics, type MetricsState } from "@/hooks/useMetrics";
import { AGENT_LABELS, formatDuration } from "@/lib/format";

/** Turn a range panel into chart series, one per distinct label value. */
function toSeries(state: MetricsState, key: string | null) {
  if (state.status !== "ok") return [];

  return state.series.map((s, i) => ({
    label: key ? (s.metric[key] ?? "total") : "total",
    color: seriesColor(i),
    points: (s.values ?? []).map(
      ([t, v]) => [t, Number(v)] as [number, number],
    ),
  }));
}

/** Status colours are reserved - never reused as another categorical slot. */
function statusColor(status: string): string {
  if (status === "analysed") return "var(--ok)";
  if (status === "failed" || status === "timed_out") return "var(--critical)";
  if (status.startsWith("skipped")) return "var(--warn)";

  return "var(--muted)";
}

export function PrometheusTab() {
  const outcomes = useMetrics("scan_outcomes");
  const duration = useMetrics("scan_duration_p95");
  const latency = useMetrics("agent_latency");
  const agentOutcomes = useMetrics("agent_outcomes");
  const tokens = useMetrics("llm_tokens");
  const scans = useMetrics("scans_total");
  const degraded = useMetrics("scans_degraded");
  const vulns = useMetrics("vulnerabilities");
  const dropped = useMetrics("vulnerabilities_dropped");
  const ratelimit = useMetrics("ratelimit");

  const scanCount = total(scans);
  const degradedCount = total(degraded);
  const share = scanCount > 0 ? (degradedCount / scanCount) * 100 : 0;

  const vulnCount = total(vulns);
  const droppedCount = total(dropped);

  const agentName = (m: Record<string, string>) =>
    AGENT_LABELS[m.agent] ?? m.agent;

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Scans"
          value={scanCount.toLocaleString()}
          hint="since this Prometheus started"
        />
        <StatTile
          label="Degraded"
          value={`${share.toFixed(0)}%`}
          tone={share > 20 ? "warn" : "default"}
          hint={`${degradedCount.toLocaleString()} of ${scanCount.toLocaleString()} returned an incomplete report`}
        />
        <StatTile
          label="Vulnerabilities"
          value={vulnCount.toLocaleString()}
          hint="found by the scanner, all scans"
        />
        <StatTile
          label="Dropped before analysis"
          value={droppedCount.toLocaleString()}
          tone={droppedCount > 0 ? "warn" : "ok"}
          hint={
            droppedCount > 0
              ? "counted, then never shown to a model"
              : "every finding reached an agent"
          }
        />
      </div>

      <Panel title="Scan outcomes" hint="last 6 hours">
        <TimeSeries
          series={toSeries(outcomes, "outcome")}
          empty="No scans in this window."
        />
      </Panel>

      <Panel title="Scan duration by stage" hint="p95, last 6 hours">
        <TimeSeries
          series={toSeries(duration, "stage")}
          unit="s"
          empty="Not enough samples yet — run a scan."
        />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Agent latency" hint="mean seconds per run">
          <BarRows
            rows={rows(latency, agentName).map((r) => ({
              ...r,
              color: "var(--series-1)",
            }))}
            format={(n) => formatDuration(n)}
            empty="No agent has been timed yet."
          />
        </Panel>

        <Panel title="Agent outcomes" hint="every run, by status">
          <BarRows
            rows={
              agentOutcomes.status === "ok"
                ? agentOutcomes.series
                    .map((s) => ({
                      label: `${AGENT_LABELS[s.metric.agent] ?? s.metric.agent} · ${s.metric.status}`,
                      value: Number(s.value?.[1] ?? 0),
                      color: statusColor(s.metric.status ?? ""),
                    }))
                    .sort((a, b) => b.value - a.value)
                : []
            }
            format={(n) => n.toFixed(0)}
            empty="No agent runs recorded."
          />
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Model tokens" hint="by agent and kind">
          <BarRows
            rows={rows(
              tokens,
              (m) => `${AGENT_LABELS[m.agent] ?? m.agent} · ${m.kind}`,
            )}
            format={(n) => n.toLocaleString()}
            empty="No usage reported — the provider returned no token counts."
          />
        </Panel>

        <Panel title="Rate limit decisions" hint="fail_closed means Redis is gone">
          <BarRows
            rows={rows(ratelimit, (m) => m.decision ?? "unknown").map((r) => ({
              ...r,
              color:
                r.label === "allowed"
                  ? "var(--ok)"
                  : r.label === "fail_closed"
                    ? "var(--critical)"
                    : "var(--warn)",
            }))}
            format={(n) => n.toFixed(0)}
            empty="No requests have reached the limiter."
          />
        </Panel>
      </div>
    </div>
  );
}
