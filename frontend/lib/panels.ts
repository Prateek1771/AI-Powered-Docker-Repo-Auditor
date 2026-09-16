/**
 * The queries the analytics route will run, by name.
 *
 * Server-owned deliberately. A proxy that forwards a caller's `query` string is
 * an open Prometheus with extra steps - anyone who can reach the app could run
 * arbitrary PromQL against it, and `{__name__=~".+"}` is a cheap way to hurt a
 * server. The browser asks for a name; the expression lives here.
 *
 * Shared with the client only as the KEY type, so a typo in a panel name is a
 * compile error rather than an empty chart.
 */

export type PanelKind = "range" | "instant";

export interface PanelSpec {
  /** PromQL. */
  query: string;
  /** `range` for a time series, `instant` for a single current value. */
  kind: PanelKind;
  /** Legend label built from the series labels Prometheus returns. */
  legend?: string;
}

export const PANELS = {
  // --- the scan pipeline, over time ------------------------------------
  scan_outcomes: {
    // increase() over the whole window, which reads as "scans in the last six
    // hours" rolling forward.
    //
    // Not the raw cumulative counter: each worker restart mints a new series
    // (a new service_instance_id), so summing cumulative counters across
    // restarts makes the total JUMP when instances overlap and COLLAPSE when
    // the old one goes stale - measured here as a line running 1 → 8 → back to
    // 4 over four scans. increase() is reset-aware and did not. It undercounts
    // by the first sample of each new series, which at this volume is the
    // cheaper of the two lies.
    query: "sum by (outcome) (increase(scan_result_total[6h]))",
    kind: "range",
    legend: "outcome",
  },
  scan_duration_p95: {
    query:
      "histogram_quantile(0.95, sum by (le, stage) (rate(scan_duration_seconds_bucket[1h])))",
    kind: "range",
    legend: "stage",
  },

  // --- the agents -------------------------------------------------------
  agent_outcomes: {
    query: "sum by (agent, status) (agent_outcome_total)",
    kind: "instant",
  },
  // The metric that read zero for six of eight agents until the duration fix,
  // which is why it is worth a panel: this is where that regression would show.
  agent_latency: {
    query:
      "sum by (agent) (agent_duration_seconds_sum) / clamp_min(sum by (agent) (agent_duration_seconds_count), 1)",
    kind: "instant",
  },

  // --- what it cost and what it covered ---------------------------------
  llm_tokens: {
    query: "sum by (agent, kind) (llm_tokens_total)",
    kind: "instant",
  },
  vulnerabilities: {
    query:
      "sum(vulnerabilities_total) or vector(0)",
    kind: "instant",
  },
  vulnerabilities_dropped: {
    query: "sum(vulnerabilities_dropped_total) or vector(0)",
    kind: "instant",
  },
  scans_total: {
    query: "sum(scan_result_total) or vector(0)",
    kind: "instant",
  },
  scans_degraded: {
    query: 'sum(scan_result_total{outcome="degraded"}) or vector(0)',
    kind: "instant",
  },
  ratelimit: {
    query: "sum by (decision) (ratelimit_decision_total)",
    kind: "instant",
  },
  guard_rejections: {
    query: "sum by (reason) (agent_guard_rejection_total)",
    kind: "instant",
  },

  // --- the collector's own health --------------------------------------
  //
  // otelcol_* come from the collector's internal telemetry on :8888, a
  // different scrape job from the application metrics on :8889. "Accepted"
  // and "refused" are the pair that matters: refused is the memory_limiter
  // shedding load, and nothing else in this stack would ever tell you.
  otel_accepted_points: {
    query: "sum(rate(otelcol_receiver_accepted_metric_points_total[5m]))",
    kind: "range",
  },
  otel_refused_points: {
    query: "sum(rate(otelcol_receiver_refused_metric_points_total[5m]))",
    kind: "range",
  },
  otel_export_failures: {
    query:
      "sum by (exporter) (otelcol_exporter_send_failed_metric_points_total)",
    kind: "instant",
  },
  otel_queue_size: {
    query: "sum by (exporter) (otelcol_exporter_queue_size)",
    kind: "instant",
  },
  otel_accepted_logs: {
    query: "sum(rate(otelcol_receiver_accepted_log_records_total[5m]))",
    kind: "range",
  },
  otel_uptime: {
    query: "max(otelcol_process_uptime_seconds_total) or vector(0)",
    kind: "instant",
  },
} satisfies Record<string, PanelSpec>;

export type PanelName = keyof typeof PANELS;

export function isPanelName(value: string): value is PanelName {
  return Object.prototype.hasOwnProperty.call(PANELS, value);
}
