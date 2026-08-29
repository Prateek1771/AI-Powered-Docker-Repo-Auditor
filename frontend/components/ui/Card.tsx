import { cn } from "@/lib/cn";

export function Card({
  children,
  className,
  as: Tag = "div",
}: {
  children: React.ReactNode;
  className?: string;
  as?: "div" | "section" | "li" | "article";
}) {
  return (
    <Tag
      className={cn(
        "rounded-lg border border-border bg-surface-raised",
        className,
      )}
    >
      {children}
    </Tag>
  );
}

export function SectionHeading({
  children,
  hint,
}: {
  children: React.ReactNode;
  hint?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-4">
      <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-faint">
        {children}
      </h2>
      {hint && <span className="text-xs text-faint">{hint}</span>}
    </div>
  );
}
