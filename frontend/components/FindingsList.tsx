"use client";

import { AnimatePresence, motion } from "motion/react";
import { useMemo, useState } from "react";

import { FindingCard } from "@/components/FindingCard";
import { cn } from "@/lib/cn";
import { CATEGORY_LABELS, compareFindings, countBySeverity, SEVERITIES } from "@/lib/format";
import { useMotionPrefs } from "@/lib/motion";
import type { Finding, Severity } from "@/types/scan";

type SeverityFilter = Severity | "all";
type CategoryFilter = Finding["category"] | "all";

function Chip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-full border px-2.5 py-1 text-xs transition-colors",
        active
          ? "border-accent bg-accent/10 text-accent"
          : "border-border text-muted hover:border-border-strong hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [category, setCategory] = useState<CategoryFilter>("all");
  const { reduced } = useMotionPrefs();

  const counts = useMemo(() => countBySeverity(findings), [findings]);

  const categories = useMemo(
    () =>
      (Object.keys(CATEGORY_LABELS) as Finding["category"][]).filter((c) =>
        findings.some((f) => f.category === c),
      ),
    [findings],
  );

  const visible = useMemo(
    () =>
      findings
        .filter((f) => severity === "all" || f.severity === severity)
        .filter((f) => category === "all" || f.category === category)
        .slice()
        .sort(compareFindings),
    [findings, severity, category],
  );

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <Chip active={severity === "all"} onClick={() => setSeverity("all")}>
          All {findings.length}
        </Chip>
        {SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
          <Chip
            key={s}
            active={severity === s}
            onClick={() => setSeverity(severity === s ? "all" : s)}
          >
            {s} {counts[s]}
          </Chip>
        ))}

        {categories.length > 1 && (
          <>
            <span aria-hidden className="mx-1 h-4 w-px bg-border" />
            {categories.map((c) => (
              <Chip
                key={c}
                active={category === c}
                onClick={() => setCategory(category === c ? "all" : c)}
              >
                {CATEGORY_LABELS[c]}
              </Chip>
            ))}
          </>
        )}
      </div>

      {visible.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted">
          No findings match this filter.
        </p>
      ) : (
        <motion.ul layout={!reduced} className="space-y-2">
          <AnimatePresence mode="popLayout" initial={false}>
            {visible.map((finding, index) => (
              <motion.li
                key={`${finding.category}-${finding.title}-${index}`}
                layout={!reduced}
                initial={reduced ? { opacity: 0 } : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={reduced ? { opacity: 0 } : { opacity: 0, scale: 0.98 }}
                transition={reduced ? { duration: 0 } : { duration: 0.2 }}
              >
                <FindingCard finding={finding} />
              </motion.li>
            ))}
          </AnimatePresence>
        </motion.ul>
      )}
    </div>
  );
}
