"use client";

import { Check, Loader2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Skeleton } from "@/components/ui/Skeleton";
import { listImages, uploadImage } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { LocalImage } from "@/types/scan";

export interface Selection {
  target: string;
  repoId: string;
}

const PRESETS = ["python:3.8", "node:18-alpine", "nginx:latest", "alpine:3.20"];

type Tab = "registry" | "local" | "upload";

const TABS: { id: Tab; label: string }[] = [
  { id: "registry", label: "Registry" },
  { id: "local", label: "My images" },
  { id: "upload", label: "Upload" },
];

/** The repo id is the image name without its tag, matching app/scripts/enqueue.py. */
function repoFor(reference: string) {
  return reference.split(":")[0].trim();
}

/**
 * Choose what to scan: a registry reference, an image already on the
 * daemon, or a `docker save` tar from disk.
 *
 * The last two only exist in socket mode, so the tabs disappear entirely
 * when GET /api/v1/images 404s rather than rendering controls that cannot
 * work. All three produce the same thing - a target string - which is why
 * nothing downstream of the form knows there is more than one source.
 */
export function ImageSource({
  value,
  onChange,
  disabled,
}: {
  value: Selection;
  onChange: (selection: Selection) => void;
  disabled?: boolean;
}) {
  const [tab, setTab] = useState<Tab>("registry");

  const [images, setImages] = useState<LocalImage[] | null>(null);
  const [daemon, setDaemon] = useState(true);

  const [uploading, setUploading] = useState(false);
  const [uploaded, setUploaded] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;

    listImages()
      .then((found) => {
        if (!cancelled) setImages(found);
      })
      // A 404 is registry mode: there is no daemon here and never will be.
      .catch(() => {
        if (!cancelled) setDaemon(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const pick = async (file: File) => {
    setUploading(true);
    setUploadError(null);
    setUploaded(null);

    try {
      const { target, repo_id } = await uploadImage(file);

      onChange({ target, repoId: repo_id });

      setUploaded(file.name);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const select = (next: Tab) => {
    setTab(next);

    // Each tab owns its own target. Leaving the previous one in place would
    // let a click on Upload scan whatever the registry box still held.
    if (next !== "upload") onChange({ target: "", repoId: "" });
  };

  return (
    <div>
      {daemon && (
        <div
          role="tablist"
          aria-label="Image source"
          className="mb-4 flex gap-1 border-b border-border"
        >
          {TABS.map((entry) => (
            <button
              key={entry.id}
              type="button"
              role="tab"
              aria-selected={tab === entry.id}
              onClick={() => select(entry.id)}
              className={cn(
                "-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
                tab === entry.id
                  ? "border-accent text-foreground"
                  : "border-transparent text-muted hover:text-foreground",
              )}
            >
              {entry.label}
            </button>
          ))}
        </div>
      )}

      {tab === "registry" && (
        <>
          <label htmlFor="target" className="sr-only">
            Image reference
          </label>

          <input
            id="target"
            value={value.target}
            onChange={(event) =>
              onChange({
                target: event.target.value,
                repoId: repoFor(event.target.value),
              })
            }
            placeholder="python:3.8"
            spellCheck={false}
            autoComplete="off"
            className="w-full rounded-md border border-border bg-surface-raised px-3 py-2.5 font-mono text-sm text-foreground placeholder:text-faint"
          />

          <div className="mt-3 flex flex-wrap gap-1.5">
            {PRESETS.map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() =>
                  onChange({ target: preset, repoId: repoFor(preset) })
                }
                className="rounded-full border border-border px-2.5 py-1 font-mono text-xs text-muted transition-colors hover:border-border-strong hover:text-foreground"
              >
                {preset}
              </button>
            ))}
          </div>
        </>
      )}

      {tab === "local" && (
        <div className="max-h-64 overflow-y-auto rounded-md border border-border">
          {images === null ? (
            <div className="space-y-2 p-3">
              <Skeleton className="h-8" />
              <Skeleton className="h-8" />
            </div>
          ) : images.length === 0 ? (
            <p className="p-4 text-sm text-muted">
              No tagged images on this daemon yet. Pull one, or use the Registry
              tab.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {images.map((image) => (
                <li key={image.image_id + image.reference}>
                  <button
                    type="button"
                    onClick={() =>
                      onChange({
                        target: image.reference,
                        repoId: repoFor(image.reference),
                      })
                    }
                    className={cn(
                      "flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-surface",
                      value.target === image.reference && "bg-surface",
                    )}
                  >
                    {value.target === image.reference ? (
                      <Check
                        aria-hidden
                        className="size-4 shrink-0 text-accent"
                      />
                    ) : (
                      <span aria-hidden className="size-4 shrink-0" />
                    )}

                    <span className="min-w-0 flex-1 truncate font-mono text-sm text-foreground">
                      {image.reference}
                    </span>

                    <span className="shrink-0 font-mono text-xs text-faint">
                      {image.size}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tab === "upload" && (
        <div>
          <input
            ref={fileInput}
            id="tarball"
            type="file"
            accept=".tar"
            className="sr-only"
            onChange={(event) => {
              const file = event.target.files?.[0];

              if (file) void pick(file);
            }}
          />

          <button
            type="button"
            disabled={disabled || uploading}
            onClick={() => fileInput.current?.click()}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-dashed border-border-strong px-4 py-8 text-sm text-muted transition-colors hover:border-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
          >
            {uploading ? (
              <>
                <Loader2 aria-hidden className="size-4 animate-spin" />
                Uploading
              </>
            ) : (
              <>
                <Upload aria-hidden className="size-4" />
                {uploaded ?? "Choose a .tar from docker save"}
              </>
            )}
          </button>

          <p className="mt-2 text-xs text-faint">
            Produce one with{" "}
            <code className="font-mono">
              docker save alpine:3.20 -o alpine.tar
            </code>
            . The worker loads it, scans it, and deletes the tar.
          </p>

          {uploadError && (
            <p role="alert" className="mt-2 text-sm text-critical">
              {uploadError}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
