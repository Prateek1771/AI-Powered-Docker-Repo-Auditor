import type { Finding, Severity } from "@/types/scan";

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

export const SEVERITIES = SEVERITY_ORDER;

/** Lower is worse, matching app/processors/vulnerabilities.py SEVERITY_ORDER. */
export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity);

  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** Worst severity first, then highest priority. */
export function compareFindings(a: Finding, b: Finding): number {
  return severityRank(a.severity) - severityRank(b.severity) || b.priority - a.priority;
}

/**
 * Render a byte count as a human size, never as a bare number.
 *
 * Clamps at zero so a missing or negative size shows 0 B rather than
 * NaN or -Infinity in the middle of a report.
 */
export function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const value = bytes / 1024 ** exponent;

  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

/** Render a duration in milliseconds or seconds, whichever reads better. */
export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;

  return `${seconds.toFixed(1)} s`;
}

/** Only real CVE ids resolve on NVD; Trivy also emits GHSA and vendor ids. */
export function nvdUrl(vulnerabilityId: string): string | null {
  return /^CVE-\d{4}-\d{4,}$/i.test(vulnerabilityId)
    ? `https://nvd.nist.gov/vuln/detail/${vulnerabilityId.toUpperCase()}`
    : null;
}

/**
 * Count findings per severity, reporting zero for absent ones.
 *
 * Every severity is present in the result so a chart can render a real
 * zero instead of a gap.
 */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(
    SEVERITY_ORDER.map((s) => [s, 0]),
  ) as Record<Severity, number>;

  for (const finding of findings) counts[finding.severity] += 1;

  return counts;
}

export const CATEGORY_LABELS: Record<Finding["category"], string> = {
  cve: "Vulnerability",
  bloat: "Image size",
  base_image: "Base image",
  compliance: "Compliance",
};

export const AGENT_LABELS: Record<string, string> = {
  cve_analyst: "Vulnerability analysis",
  bloat_detective: "Image size analysis",
  base_image_strategist: "Base image review",
  compliance_checker: "Compliance checks",
  dockerfile_optimizer: "Dockerfile rewrite",
  risk_scorer: "Risk scoring",
};
