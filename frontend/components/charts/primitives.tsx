"use client";

import { useId, useState } from "react";

import { cn } from "@/lib/cn";

/**
 * The chart pieces the analytics tabs are built from.
 *
 * Hand-rolled SVG rather than a charting library, for the same reason
 * ScoreRing and ScoreBars are: these are four simple forms, they have to wear
 * the app's own tokens in both themes, and a library would be 500KB plus a
 * theming layer to make it look like this anyway.
 *
 * Colour rules come from the validated palette in globals.css: categorical
 * hues in fixed order and never cycled, status colours reserved for state and
 * never reused as "series 4", and text in text tokens so identity is never
 * carried by colour alone.
 */

/** Categorical slots, in fixed order. A ninth series folds into "Other". */
export const SERIES = [
  "var(--series-1)",
  "var(--series-2)",
  "var(--series-3)",
  "var(--series-4)",
  "var(--series-5)",
  "var(--series-6)",
  "var(--series-7)",
  "var(--series-8)",
] as const;

export function seriesColor(index: number): string {
  return SERIES[index] ?? "var(--muted)";
}

/** Axis labels: integers stay integers, small fractions keep their precision. */
function fmtTick(value: number, top: number): string {
  if (top >= 10) return value.toFixed(0);
  if (top >= 1) return value.toFixed(1);

  return value.toFixed(3);
}

/** A single headline number. Not every question needs a plot. */
export function StatTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "default" | "ok" | "warn" | "critical";
}) {
  const toneClass = {
    default: "text-foreground",
    ok: "text-ok",
    warn: "text-warn",
    critical: "text-critical",
  }[tone];

  return (
    <div className="rounded-lg border border-border bg-surface-raised p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-faint">
        {label}
      </p>
      <p
        className={cn(
          "mt-1.5 font-mono text-2xl tabular-nums leading-none",
          toneClass,
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-1.5 text-xs text-muted">{hint}</p>}
    </div>
  );
}

export interface Series {
  label: string;
  color: string;
  points: [number, number][];
}

/**
 * A multi-series line chart with a crosshair and a tooltip.
 *
 * One y-axis, always. Two measures of different scale get two charts - a
 * second scale makes any two lines cross wherever the author chose.
 */
export function TimeSeries({
  series,
  height = 180,
  unit = "",
  empty = "No data in this window.",
}: {
  series: Series[];
  height?: number;
  unit?: string;
  empty?: string;
}) {
  const clip = useId();
  const [hover, setHover] = useState<number | null>(null);

  // Prometheus serialises a missing value as the STRING "NaN" - histogram_quantile
  // does it for any bucket with no samples, which is every quantile panel before
  // the first scan. Number("NaN") is NaN, one NaN poisons Math.max, and every
  // coordinate downstream becomes NaN: the browser then rejects the whole
  // polyline and the chart silently renders nothing. Drop them here rather than
  // in each caller, because every chart on the page routes through this.
  const clean = series.map((s) => ({
    ...s,
    points: s.points.filter(
      ([x, y]) => Number.isFinite(x) && Number.isFinite(y),
    ),
  }));

  const all = clean.flatMap((s) => s.points);

  if (all.length === 0) {
    return (
      <div
        style={{ height }}
        className="flex items-center justify-center rounded-md border border-dashed border-border text-sm text-faint"
      >
        {empty}
      </div>
    );
  }

  const xs = all.map(([x]) => x);
  const ys = all.map(([, y]) => y);

  const x0 = Math.min(...xs);
  const x1 = Math.max(...xs);
  // Floor the top at a non-zero value so an all-zero series draws along the
  // baseline instead of dividing by zero.
  const y1 = Math.max(...ys, 0.0001);

  const W = 720;
  const H = height;
  const PAD = { top: 8, right: 8, bottom: 20, left: 40 };

  const px = (x: number) =>
    PAD.left + ((x - x0) / Math.max(x1 - x0, 1)) * (W - PAD.left - PAD.right);
  const py = (y: number) =>
    H - PAD.bottom - (y / y1) * (H - PAD.top - PAD.bottom);

  // Deduped: an all-zero series makes y1 the 0.0001 floor, and three ticks
  // rounding to "0.000" is three identical labels stacked up the axis.
  const ticks = [...new Set([0, y1 / 2, y1].map((t) => fmtTick(t, y1)))].map(
    (label) => ({ label, value: Number(label) }),
  );

  const fmt = (n: number) =>
    n >= 100 ? n.toFixed(0) : n >= 1 ? n.toFixed(1) : n.toFixed(3);

  // The hovered column, found on the first series that has points.
  const spine = clean.find((s) => s.points.length > 0)?.points ?? [];
  const at = hover === null ? null : spine[hover];

  return (
    <figure className="m-0">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height }}
        role="img"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect();
          const ratio = (event.clientX - box.left) / box.width;
          const svgX = ratio * W;

          if (spine.length === 0) return;

          let best = 0;
          let bestDist = Infinity;

          spine.forEach(([x], i) => {
            const d = Math.abs(px(x) - svgX);

            if (d < bestDist) {
              bestDist = d;
              best = i;
            }
          });

          setHover(best);
        }}
      >
        <defs>
          <clipPath id={clip}>
            <rect
              x={PAD.left}
              y={PAD.top}
              width={W - PAD.left - PAD.right}
              height={H - PAD.top - PAD.bottom}
            />
          </clipPath>
        </defs>

        {/* Recessive grid: hairlines in the border token, never the ink. */}
        {ticks.map((t) => (
          <g key={t.label}>
            <line
              x1={PAD.left}
              x2={W - PAD.right}
              y1={py(t.value)}
              y2={py(t.value)}
              stroke="var(--border)"
              strokeWidth="1"
            />
            <text
              x={PAD.left - 6}
              y={py(t.value) + 3}
              textAnchor="end"
              className="fill-[var(--faint)] text-[10px] tabular-nums"
            >
              {t.label}
            </text>
          </g>
        ))}

        <g clipPath={`url(#${clip})`}>
          {clean.map((s) => (
            <polyline
              key={s.label}
              fill="none"
              stroke={s.color}
              strokeWidth="2"
              strokeLinejoin="round"
              strokeLinecap="round"
              points={s.points.map(([x, y]) => `${px(x)},${py(y)}`).join(" ")}
            />
          ))}
        </g>

        {at && (
          <line
            x1={px(at[0])}
            x2={px(at[0])}
            y1={PAD.top}
            y2={H - PAD.bottom}
            stroke="var(--border-strong)"
            strokeWidth="1"
          />
        )}

        <line
          x1={PAD.left}
          x2={W - PAD.right}
          y1={H - PAD.bottom}
          y2={H - PAD.bottom}
          stroke="var(--border-strong)"
          strokeWidth="1"
        />
      </svg>

      <figcaption className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        {/* A legend is always present for two or more series, so identity is
            never colour alone - and the hovered value is direct-labelled next
            to it, which is the relief the contrast WARN obliges. */}
        {clean.map((s, i) => {
          const point = hover === null ? null : s.points[hover];

          return (
            <span key={s.label} className="flex items-center gap-1.5 text-xs">
              <span
                aria-hidden
                className="size-2 shrink-0 rounded-full"
                style={{ background: s.color }}
              />
              <span className="text-muted">{s.label}</span>
              {point && (
                <span className="font-mono tabular-nums text-foreground">
                  {fmt(point[1])}
                  {unit}
                </span>
              )}
              {hover === null && i === 0 && (
                <span className="text-faint">· hover for values</span>
              )}
            </span>
          );
        })}
      </figcaption>
    </figure>
  );
}

/**
 * Magnitude by name — a horizontal bar per row.
 *
 * Horizontal because the labels are words (`base_image_strategist`), and
 * rotating type to fit a vertical axis is the most common way a chart becomes
 * unreadable.
 */
export function BarRows({
  rows,
  unit = "",
  format,
  empty = "Nothing recorded yet.",
}: {
  rows: { label: string; value: number; color?: string; note?: string }[];
  unit?: string;
  format?: (value: number) => string;
  empty?: string;
}) {
  if (rows.length === 0) {
    return (
      <p className="rounded-md border border-dashed border-border p-4 text-sm text-faint">
        {empty}
      </p>
    );
  }

  const max = Math.max(...rows.map((r) => r.value), 0.0001);
  const fmt = format ?? ((n: number) => (n >= 10 ? n.toFixed(0) : n.toFixed(2)));

  return (
    <ul className="space-y-2">
      {rows.map((row) => (
        <li key={row.label} className="grid grid-cols-[1fr_auto] gap-x-3">
          <span className="truncate text-sm text-foreground">{row.label}</span>
          <span className="font-mono text-xs tabular-nums text-muted">
            {fmt(row.value)}
            {unit}
          </span>
          <div className="col-span-2 h-1.5 overflow-hidden rounded-full bg-border">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max(1, (row.value / max) * 100)}%`,
                background: row.color ?? "var(--series-1)",
              }}
            />
          </div>
          {row.note && (
            <span className="col-span-2 text-xs text-faint">{row.note}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** A panel frame, so every chart on the page has the same anatomy. */
export function Panel({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-surface-raised p-4">
      <div className="mb-3 flex items-baseline justify-between gap-4">
        <h3 className="text-sm font-medium text-foreground">{title}</h3>
        {hint && <span className="text-xs text-faint">{hint}</span>}
      </div>
      {children}
    </section>
  );
}
