"use client";

import { useState } from "react";

import { Card, SectionHeading } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import type { Package } from "@/types/scan";

// Enough to show the shape of the bill of materials without rendering eleven
// thousand rows into the DOM. The rest are a download away, which is what the
// CycloneDX export is for.
const PREVIEW = 50;

/**
 * The bill of materials the scan already collected.
 *
 * Trivy reports every package on every scan, the backend stores the list, and
 * CycloneDX export renders it - but nothing ever showed it. Someone who came
 * to look at a scan had to download a file to find out what was in the image.
 * See docs/AUDIT_02 F14.
 */
export function PackagesTable({ packages }: { packages: Package[] }) {
  const [open, setOpen] = useState(false);

  if (packages.length === 0) return null;

  const shown = open ? packages.slice(0, PREVIEW) : [];

  return (
    <section>
      <SectionHeading hint={`${packages.length} total`}>
        Packages
      </SectionHeading>

      <Card className="p-4">
        <div className="flex items-center justify-between gap-4">
          <p className="text-sm text-muted">
            Everything the scanner found installed in the image.
          </p>
          <Button variant="outline" onClick={() => setOpen(!open)}>
            {open ? "Hide" : "Show"}
          </Button>
        </div>

        {open && (
          <>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase tracking-[0.12em] text-faint">
                    <th className="pb-2 pr-4 font-semibold">Name</th>
                    <th className="pb-2 pr-4 font-semibold">Version</th>
                    <th className="pb-2 font-semibold">Licences</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((pkg) => (
                    <tr
                      key={pkg.purl || `${pkg.name}@${pkg.version}`}
                      className="border-t border-border"
                    >
                      <td className="py-2 pr-4 font-mono text-foreground">
                        {pkg.name}
                      </td>
                      <td className="py-2 pr-4 font-mono text-muted">
                        {pkg.version}
                      </td>
                      <td className="py-2 text-muted">
                        {pkg.licenses.length ? pkg.licenses.join(", ") : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {packages.length > PREVIEW && (
              <p className="mt-3 text-xs text-faint">
                Showing the first {PREVIEW} of {packages.length}. Export
                CycloneDX above for the full bill of materials.
              </p>
            )}
          </>
        )}
      </Card>
    </section>
  );
}
