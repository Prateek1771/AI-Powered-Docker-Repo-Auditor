"use client";

import { useEffect } from "react";

import { Button } from "@/components/ui/Button";

/**
 * The last line of defence for a render that throws.
 *
 * There was none, which is why one finding in a category the UI did not know
 * about replaced the entire scan report with Next's default error page. The
 * category is handled now; this is what keeps the next one from doing it
 * again. See docs/audits/audit-01-backend.md.
 *
 * `retry`, not `reset` - the prop was renamed in Next 16.
 */
export default function Error({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <main className="mx-auto flex max-w-2xl flex-col items-start gap-4 px-4 py-16">
      <h1 className="text-lg font-medium text-foreground">
        This page could not be rendered
      </h1>

      <p className="text-sm text-muted">
        The scan itself is unaffected — the report is stored and this is a
        display failure. Retrying re-renders it; if it fails again the report
        contains something this build does not know how to show.
      </p>

      {error.digest && (
        <p className="font-mono text-xs text-faint">Digest: {error.digest}</p>
      )}

      <Button onClick={retry}>Try again</Button>
    </main>
  );
}
