"use client";

import { useState } from "react";

import { GatewayTab } from "@/components/analytics/GatewayTab";
import { GrafanaTab } from "@/components/analytics/GrafanaTab";
import { OtelTab } from "@/components/analytics/OtelTab";
import { PrometheusTab } from "@/components/analytics/PrometheusTab";
import { cn } from "@/lib/cn";

const TABS = [
  {
    id: "prometheus",
    label: "Prometheus",
    hint: "what the pipeline did",
  },
  {
    id: "otel",
    label: "OpenTelemetry",
    hint: "whether the collector is coping",
  },
  {
    id: "gateway",
    label: "Gateway",
    hint: "what the models cost, and whether the keys still work",
  },
  {
    id: "grafana",
    label: "Grafana",
    hint: "the provisioned dashboards",
  },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function AnalyticsPage() {
  const [active, setActive] = useState<TabId>("prometheus");

  const current = TABS.find((t) => t.id === active)!;

  return (
    <main className="mx-auto max-w-5xl px-6 py-12">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Analytics
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-muted">
          Every scan pushes metrics and logs to an OpenTelemetry collector,
          which Prometheus scrapes and Grafana draws. This is that data, in the
          product rather than in a second tab nobody opens.
        </p>
      </header>

      {/* Tabs as a real tablist: arrow keys and roles, not styled divs. */}
      <div
        role="tablist"
        aria-label="Analytics source"
        className="mt-8 flex gap-1 border-b border-border"
      >
        {TABS.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={tab.id === active}
            aria-controls={`panel-${tab.id}`}
            onClick={() => setActive(tab.id)}
            className={cn(
              "-mb-px border-b-2 px-4 py-2.5 text-sm transition-colors",
              tab.id === active
                ? "border-accent font-medium text-foreground"
                : "border-transparent text-muted hover:text-foreground",
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <p className="mt-3 text-xs text-faint">{current.hint}</p>

      <div
        role="tabpanel"
        id={`panel-${active}`}
        aria-labelledby={`tab-${active}`}
        className="mt-6"
      >
        {active === "prometheus" && <PrometheusTab />}
        {active === "otel" && <OtelTab />}
        {active === "gateway" && <GatewayTab />}
        {active === "grafana" && <GrafanaTab />}
      </div>
    </main>
  );
}
