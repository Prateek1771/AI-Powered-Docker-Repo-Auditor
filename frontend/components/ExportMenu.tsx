"use client";

import { Download } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/Button";
import { downloadReport } from "@/lib/api";
import type { ExportFormat } from "@/types/scan";

const FORMATS: { format: ExportFormat; label: string; hint: string }[] = [
  { format: "sarif", label: "SARIF", hint: "GitHub code scanning" },
  { format: "cyclonedx", label: "CycloneDX", hint: "SBOM" },
  { format: "csv", label: "CSV", hint: "spreadsheet" },
  { format: "junit", label: "JUnit", hint: "CI test report" },
];

/**
 * Download the report in a format something else can read.
 *
 * The API has served all four of these for a while and nothing in the UI
 * pointed at them, so the only way to get a SARIF file out was curl. A report
 * a pipeline can consume is most of the point of generating one.
 */
export function ExportMenu({ jobId }: { jobId: string }) {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save(format: ExportFormat) {
    setBusy(format);
    setError(null);

    try {
      const { blob, filename } = await downloadReport(jobId, format);

      // The anchor is revoked immediately after the click: an object URL holds
      // the whole blob in memory until it is, and a report can be megabytes.
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");

      anchor.href = url;
      anchor.download = filename;
      anchor.click();

      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        {FORMATS.map(({ format, label, hint }) => (
          <Button
            key={format}
            variant="outline"
            onClick={() => save(format)}
            disabled={busy !== null}
            title={hint}
          >
            <Download aria-hidden className="size-3.5" />
            {busy === format ? `Preparing ${label}...` : label}
          </Button>
        ))}
      </div>

      {error && (
        <p role="alert" className="text-xs text-critical">
          {error}
        </p>
      )}
    </div>
  );
}
