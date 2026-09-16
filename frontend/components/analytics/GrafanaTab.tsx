"use client";

import { ExternalLink } from "lucide-react";
import { useState } from "react";

import { cn } from "@/lib/cn";

/**
 * The five provisioned dashboards, embedded.
 *
 * Embedded rather than reimplemented: they are checked-in JSON under
 * observability/grafana/dashboards/ and they are the operator view. Drawing
 * them again in React would be a second copy to keep in step with the first,
 * and the first is the one the alerts are written against.
 *
 * Grafana sends X-Frame-Options: deny by default, so this needs
 * GF_SECURITY_ALLOW_EMBEDDING=true on that service - set in docker-compose.yml.
 */

const GRAFANA_URL = process.env.NEXT_PUBLIC_GRAFANA_URL ?? "";

export const grafanaConfigured = Boolean(GRAFANA_URL);

const DASHBOARDS = [
  { uid: "auditor-pipeline", label: "Pipeline", slug: "scan-pipeline-health" },
  { uid: "auditor-agents", label: "Agents", slug: "agent-quality" },
  { uid: "auditor-cost", label: "Cost", slug: "model-cost" },
  { uid: "auditor-queue", label: "Queue", slug: "queue-and-reliability" },
  { uid: "auditor-security", label: "Security", slug: "security-signal" },
];

export function GrafanaTab() {
  const [active, setActive] = useState(DASHBOARDS[0]);

  if (!grafanaConfigured) {
    return (
      <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted">
        No Grafana URL is configured for this build. Set{" "}
        <code className="font-mono text-xs">NEXT_PUBLIC_GRAFANA_URL</code> and
        rebuild to embed the dashboards here.
      </p>
    );
  }

  // kiosk strips Grafana's own chrome, so the embed reads as part of this page
  // rather than a browser inside a browser.
  const src = `${GRAFANA_URL}/d/${active.uid}/${active.slug}?kiosk&theme=dark&from=now-6h&to=now`;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {DASHBOARDS.map((dash) => (
          <button
            key={dash.uid}
            type="button"
            onClick={() => setActive(dash)}
            className={cn(
              "rounded-md border px-3 py-1.5 text-sm transition-colors",
              dash.uid === active.uid
                ? "border-border-strong bg-surface-raised text-foreground"
                : "border-border text-muted hover:text-foreground",
            )}
          >
            {dash.label}
          </button>
        ))}

        <a
          href={`${GRAFANA_URL}/d/${active.uid}/${active.slug}`}
          target="_blank"
          rel="noreferrer"
          className="ml-auto flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
        >
          Open in Grafana
          <ExternalLink aria-hidden className="size-3.5" />
        </a>
      </div>

      <iframe
        key={active.uid}
        src={src}
        title={`${active.label} dashboard`}
        className="h-180 w-full rounded-lg border border-border bg-surface-raised"
      />

      <p className="text-xs text-faint">
        If this stays blank, the observability profile is not running:{" "}
        <code className="font-mono">
          docker compose --profile observability up -d
        </code>
      </p>
    </div>
  );
}
