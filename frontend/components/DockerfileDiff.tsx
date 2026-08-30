"use client";

import { useState } from "react";

import { Button } from "@/components/ui/Button";
import { Card, SectionHeading } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import type { FullReport } from "@/types/scan";

type Optimization = NonNullable<
  NonNullable<FullReport["dockerfile"]>["optimization"]
>;

function Pane({ title, body }: { title: string; body: string }) {
  return (
    <div className="min-w-0">
      <p className="mb-2 text-xs uppercase tracking-[0.1em] text-faint">
        {title}
      </p>
      <pre className="overflow-x-auto rounded-md border border-border bg-surface p-3 font-mono text-xs leading-relaxed text-foreground">
        {body || "(empty)"}
      </pre>
    </div>
  );
}

/**
 * Show the rewritten Dockerfile, with the reconstruction beside it.
 *
 * The original is reconstructed from layer history rather than read, so
 * the notes about what could not be recovered ship with it.
 */
export function DockerfileDiff({
  optimization,
}: {
  optimization: Optimization;
}) {
  const [view, setView] = useState<"optimized" | "both">("optimized");

  return (
    <section>
      <SectionHeading
        hint={
          <Button
            variant="ghost"
            className="px-2 py-1 text-xs"
            onClick={() => setView(view === "both" ? "optimized" : "both")}
          >
            {view === "both" ? "Show result only" : "Compare with original"}
          </Button>
        }
      >
        Suggested Dockerfile
      </SectionHeading>

      <Card className="p-4">
        <div
          className={cn(
            "grid gap-4",
            view === "both" && "lg:grid-cols-2",
          )}
        >
          {view === "both" && (
            <Pane title="Reconstructed from layers" body={optimization.reconstructed} />
          )}
          <Pane title="Optimized" body={optimization.optimized} />
        </div>

        {optimization.reconstruction_notes && (
          <p className="mt-4 border-t border-border pt-3 text-xs text-muted">
            {/* The reconstruction is inferred from `docker history`, not read
                from a real Dockerfile, and the agent's caveats about that
                belong next to the output rather than buried in the report. */}
            {optimization.reconstruction_notes}
          </p>
        )}
      </Card>
    </section>
  );
}
