import { cn } from "@/lib/cn";
import type { Severity } from "@/types/scan";

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "text-critical border-critical/40 bg-critical/10",
  high: "text-high border-high/40 bg-high/10",
  medium: "text-medium border-medium/40 bg-medium/10",
  low: "text-low border-low/40 bg-low/10",
  informational: "text-informational border-informational/40 bg-informational/10",
};

/** A small label chip. */
export function Badge({
  children,
  className,
  mono,
}: {
  children: React.ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] leading-none",
        "border-border bg-surface text-muted",
        mono && "font-mono tracking-tight",
        className,
      )}
    >
      {children}
    </span>
  );
}

/**
 * A badge coloured by severity that always spells the severity out.
 *
 * The word is not decoration: colour alone excludes anyone who cannot
 * distinguish these hues.
 */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge
      className={cn("font-medium uppercase tracking-wide", SEVERITY_CLASS[severity])}
    >
      {/* The dot is decoration; the word is the signal. Colour alone would
          leave this unreadable for anyone who cannot separate the hues. */}
      <span aria-hidden className="size-1.5 rounded-full bg-current" />
      {severity}
    </Badge>
  );
}

export { SEVERITY_CLASS };
