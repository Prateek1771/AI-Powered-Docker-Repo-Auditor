import { ShieldAlert } from "lucide-react";

import { Card, SectionHeading } from "@/components/ui/Card";
import { formatBytes } from "@/lib/format";
import type { ImageProfile } from "@/types/scan";

/**
 * What the image actually is, read from its own config.
 *
 * This is the only part of a report that owes nothing to a model. It is
 * decided from the image config before any agent runs, which means no amount
 * of injected text in a layer can change it and it survives every agent
 * failing - on a scan where four agents returned 429 and every score was
 * null, this was the only trustworthy content in the report and the UI showed
 * none of it. See docs/audits/audit-02-frontend-worker-observability.md F13.
 */
export function ImageProfileCard({ profile }: { profile: ImageProfile }) {
  // Running as root is the one fact here that is a finding in its own right,
  // so it is called out rather than left as a row for the reader to notice.
  // An empty user means the image never set one, which Docker treats as root.
  const root = !profile.user || profile.user === "root" || profile.user === "0";

  const rows: { label: string; value: React.ReactNode }[] = [
    { label: "Base", value: profile.base_reference || "unknown" },
    {
      label: "OS",
      value: profile.os_name
        ? `${profile.os_family} ${profile.os_name}`
        : profile.os_family || "unknown",
    },
    { label: "User", value: profile.user || "root (unset)" },
    {
      label: "Ports",
      value: profile.exposed_ports.length
        ? profile.exposed_ports.join(", ")
        : "none",
    },
    { label: "Healthcheck", value: profile.has_healthcheck ? "yes" : "no" },
    { label: "Layers", value: profile.layer_count },
    { label: "Size", value: formatBytes(profile.total_size_bytes) },
  ];

  return (
    <section>
      <SectionHeading hint="measured, not inferred">Image</SectionHeading>

      <Card className="p-4">
        <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
          {rows.map((row) => (
            <div key={row.label} className="flex justify-between gap-4">
              <dt className="text-sm text-faint">{row.label}</dt>
              <dd className="truncate font-mono text-sm text-foreground">
                {row.value}
              </dd>
            </div>
          ))}
        </dl>

        {root && (
          <p className="mt-4 flex gap-2 border-t border-border pt-3 text-sm text-warn">
            <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
            <span>
              This image runs as root. A process that escapes the container
              starts with more than it needs.
            </span>
          </p>
        )}
      </Card>
    </section>
  );
}
