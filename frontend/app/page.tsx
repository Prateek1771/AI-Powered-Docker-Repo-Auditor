"use client";

import { ArrowRight, Loader2 } from "lucide-react";
import { motion } from "motion/react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { ImageSource, type Selection } from "@/components/ImageSource";
import { RecentScans } from "@/components/RecentScans";
import { startScan } from "@/lib/api";
import { useMotionPrefs } from "@/lib/motion";

export default function HomePage() {
  const router = useRouter();
  const { section, reduced } = useMotionPrefs();

  const [selection, setSelection] = useState<Selection>({
    target: "python:3.8",
    repoId: "python",
  });

  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const submit = async (formEvent: React.FormEvent) => {
    formEvent.preventDefault();

    setStarting(true);
    setError(null);

    try {
      const { job_id } = await startScan(
        selection.repoId,
        selection.target.trim(),
      );

      router.push(`/scans/${job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start a scan.");

      setStarting(false);
    }
  };

  return (
    <main className="mx-auto max-w-5xl px-6 py-16">
      <motion.div
        initial="hidden"
        animate="show"
        variants={section}
        transition={{ duration: reduced ? 0 : 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Audit a container image
        </h1>
        <p className="mt-2 max-w-xl text-sm text-muted">
          Six agents check the image for vulnerabilities, wasted layers, base
          image drift and CIS compliance. If any of them fail, the report says
          so rather than quietly scoring you on less evidence.
        </p>

        <form onSubmit={submit} className="mt-8">
          <ImageSource
            value={selection}
            onChange={setSelection}
            disabled={starting}
          />

          <button
            type="submit"
            disabled={starting || !selection.target.trim()}
            className="mt-4 inline-flex shrink-0 items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-medium text-accent-fg transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting ? (
              <>
                <Loader2 aria-hidden className="size-4 animate-spin" />
                Starting
              </>
            ) : (
              <>
                Scan
                <ArrowRight aria-hidden className="size-4" />
              </>
            )}
          </button>
        </form>

        {error && (
          <p role="alert" className="mt-4 text-sm text-critical">
            {error}
          </p>
        )}
      </motion.div>

      <RecentScans repoId={selection.repoId} />
    </main>
  );
}
