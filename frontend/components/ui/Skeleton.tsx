import { cn } from "@/lib/cn";

/** A placeholder block shown while content loads. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      aria-hidden
      className={cn("animate-pulse rounded bg-border/60", className)}
    />
  );
}
