"use client";

import { ArrowRight, Loader2 } from "lucide-react";
import { motion } from "motion/react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { RecentScans } from "@/components/RecentScans";
import { startScan } from "@/lib/api";
import { useMotionPrefs } from "@/lib/motion";

const PRESETS = ["python:3.8", "node:18-alpine", "nginx:latest", "alpine:3.20"];

export default function HomePage() {
  const router = useRouter();
  const { section, reduced } = useMotionPrefs();

  const [target, setTarget] = useState("python:3.8");
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const repoId = target.split(":")[0].trim();

  const submit = async (formEvent: React.FormEvent) => {
    formEvent.preventDefault();

    setStarting(true);
    setError(null);

    try {
      // The repo id is the image name without its tag, matching what
      // app/scripts/enqueue.py does.
      const { job_id } = await startScan(repoId, target.trim());

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

        <form onSubmit={submit} className="mt-8 flex gap-2">
          <label htmlFor="target" className="sr-only">
            Image reference
          </label>

          <input
            id="target"
            value={target}
            onChange={(inputEvent) => setTarget(inputEvent.target.value)}
            placeholder="python:3.8"
            spellCheck={false}
            autoComplete="off"
            className="min-w-0 flex-1 rounded-md border border-border bg-surface-raised px-3 py-2.5 font-mono text-sm text-foreground placeholder:text-faint"
          />

          <button
            type="submit"
            disabled={starting || !target.trim()}
            className="inline-flex shrink-0 items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-medium text-accent-fg transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
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

        <div className="mt-3 flex flex-wrap gap-1.5">
          {PRESETS.map((preset) => (
            <button
              key={preset}
              type="button"
              onClick={() => setTarget(preset)}
              className="rounded-full border border-border px-2.5 py-1 font-mono text-xs text-muted transition-colors hover:border-border-strong hover:text-foreground"
            >
              {preset}
            </button>
          ))}
        </div>

        {error && (
          <p role="alert" className="mt-4 text-sm text-critical">
            {error}
          </p>
        )}
      </motion.div>

      <RecentScans repoId={repoId} />
    </main>
  );
}
