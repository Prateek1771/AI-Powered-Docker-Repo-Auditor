"use client";

import {
  BarRows,
  Panel,
  StatTile,
} from "@/components/charts/primitives";
import { rows, total, useMetrics } from "@/hooks/useMetrics";
import { formatDuration } from "@/lib/format";

/**
 * The LLM gateway: what the model calls cost, and whether the keys still work.
 *
 * Two things here the application genuinely cannot report about itself.
 *
 * Cost, because pricing lives at the provider. The audit asked for
 * llm_cost_usd_total and §18 deferred it: a USD figure needs a per-model price
 * table maintained against a vendor's pricing page, and a wrong number is
 * worse than no number. The gateway keeps that table, so this is the real
 * figure rather than tokens multiplied by a guess.
 *
 * And key health, because a process using a dead key cannot tell you the key
 * is dead - it only sees 429s that look like rate limiting. Every scan in this
 * project failed that way for hours.
 */

function usd(value: number): string {
  if (value === 0) return "$0.00";
  if (value < 0.01) return `$${value.toFixed(4)}`;

  return `$${value.toFixed(2)}`;
}

export function GatewayTab() {
  const costTotal = useMetrics("gateway_cost_total");
  const costByModel = useMetrics("gateway_cost");
  const requests = useMetrics("gateway_requests");
  const success = useMetrics("gateway_success");
  const latency = useMetrics("gateway_latency");
  const keyHealth = useMetrics("gateway_key_health");
  const retries = useMetrics("gateway_retries");
  const tokens = useMetrics("gateway_tokens");

  const spend = total(costTotal);
  const requestCount = total(requests);
  const successCount = total(success);

  const keys = rows(keyHealth, (m) => m.key_name ?? m.provider ?? "key");
  const down = keys.filter((k) => k.value < 1);

  // Not configured and reachable-but-idle are different facts, and only one of
  // them is a problem.
  if (costTotal.status === "not_configured") {
    return (
      <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted">
        No metrics backend is configured for this build.
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Spend"
          value={usd(spend)}
          hint="actual USD, priced by the gateway"
        />
        <StatTile
          label="Requests"
          value={requestCount.toLocaleString()}
          hint={`${successCount.toLocaleString()} succeeded upstream`}
        />
        <StatTile
          label="Keys healthy"
          value={`${keys.length - down.length}/${keys.length || 0}`}
          tone={down.length > 0 ? "critical" : "ok"}
          hint={
            down.length > 0
              ? `${down.map((k) => k.label).join(", ")} failing`
              : "every provider key answered"
          }
        />
        <StatTile
          label="Retries"
          value={total(retries).toLocaleString()}
          tone={total(retries) > 0 ? "warn" : "default"}
          hint="upstream attempts beyond the first"
        />
      </div>

      <Panel title="Upstream latency" hint="mean seconds per request">
        <BarRows
          rows={rows(latency, (m) => m.model ?? "model")}
          format={(n) => formatDuration(n)}
          empty="No requests have gone through the gateway yet."
        />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Cost by model" hint="USD">
          <BarRows
            rows={rows(costByModel, (m) => m.model ?? "model")}
            format={usd}
            empty="Nothing has been spent through the gateway."
          />
        </Panel>

        <Panel title="Tokens by model">
          <BarRows
            rows={rows(tokens, (m) => m.model ?? "model")}
            format={(n) => n.toLocaleString()}
            empty="No tokens recorded."
          />
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Provider key health" hint="1 = last attempt succeeded">
          <BarRows
            rows={keys.map((k) => ({
              ...k,
              color: k.value < 1 ? "var(--critical)" : "var(--ok)",
              note: k.value < 1 ? "last attempt failed" : undefined,
            }))}
            format={(n) => (n >= 1 ? "up" : "down")}
            empty="No provider keys registered."
          />
        </Panel>

        <Panel title="Requests by provider">
          <BarRows
            rows={rows(requests, (m) => m.provider ?? "provider")}
            format={(n) => n.toFixed(0)}
            empty="No upstream requests."
          />
        </Panel>
      </div>
    </div>
  );
}
