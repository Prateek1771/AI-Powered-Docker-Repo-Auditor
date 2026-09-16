import type { AgentOutcome, AgentStatus, Finding, Severity } from "@/types/scan";

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
  secret: "Secret",
};

/**
 * The colour band for a score out of 100, or null for "not assessed".
 *
 * null is NOT zero. The backend returns null where an axis had no
 * trustworthy evidence, and zero is a real score meaning "as bad as it gets" -
 * so every `value >= 80` comparison fell through to critical red and a score
 * nobody could compute rendered as the worst possible news, in red, at 0/100.
 *
 * One copy, because this was duplicated identically in ScoreRing and
 * ScoreBars and two copies of the null handling would diverge immediately.
 */
export function bandColor(value: number | null): string {
  if (value === null) return "var(--faint)";
  if (value >= 80) return "var(--ok)";
  if (value >= 50) return "var(--sev-medium)";
  if (value >= 25) return "var(--sev-high)";

  return "var(--sev-critical)";
}

/** What to show in place of a score that could not be computed. */
export const NOT_ASSESSED = "Not assessed";

export function formatScore(value: number | null): string {
  return value === null ? NOT_ASSESSED : String(Math.round(value));
}

/**
 * Lifted out of AgentTimings, which held the only copy while DegradedNotice
 * and the scan page each re-derived the same judgement inline.
 */
export const STATUS_TEXT: Record<AgentStatus, string> = {
  analysed: "text-ok",
  skipped_no_input: "text-faint",
  skipped_missing_input: "text-warn",
  skipped_degraded_input: "text-warn",
  failed: "text-critical",
  timed_out: "text-critical",
};

export const STATUS_LABEL: Record<AgentStatus, string> = {
  analysed: "analysed",
  skipped_no_input: "nothing to analyse",
  // Deliberately not "skipped". The evidence never arrived - this agent has
  // found nothing in the sense that a closed eye has seen nothing.
  skipped_missing_input: "input never arrived",
  skipped_degraded_input: "skipped",
  failed: "failed",
  timed_out: "timed out",
};

/**
 * Whether an outcome is an absence of evidence rather than evidence.
 *
 * Mirrors AgentOutcome.is_trustworthy on the backend: analysed and
 * skipped_no_input are real answers, everything else is not. The predicate was
 * written inline in two places and both omitted skipped_missing_input, so an
 * agent that never saw its input did not count as degradation.
 */
export function isDegraded(outcome: AgentOutcome): boolean {
  return !(
    outcome.status === "analysed" || outcome.status === "skipped_no_input"
  );
}

export const AGENT_LABELS: Record<string, string> = {
  // The three scanners. They emit node frames during a scan and appear in no
  // report outcome, so they were missing here and rendered raw.
  trivy: "Vulnerability scan",
  docker_history: "Layer history",
  image_inspect: "Image config",

  // Deterministic, decided before any model runs - which is why they survive
  // every agent failing, and why they belong in the same list.
  cis_controls: "CIS controls",
  secret_scan: "Secret scan",

  cve_analyst: "Vulnerability analysis",
  bloat_detective: "Image size analysis",
  base_image_strategist: "Base image review",
  compliance_checker: "Compliance checks",
  dockerfile_optimizer: "Dockerfile rewrite",
  risk_scorer: "Risk scoring",
};
