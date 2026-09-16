export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type Effort = "trivial" | "moderate" | "involved";

export type Exploitability =
  | "actively_exploited"
  | "likely"
  | "unlikely"
  | "theoretical";

// All six. If the type cannot express a failure, no component can render one.
//
// skipped_missing_input is the one that matters and was missing here for five
// backend phases: it means the evidence never arrived, where skipped_no_input
// means the agent looked and there was genuinely nothing. Conflating them is
// how an unreadable image scored as confidently clean - the exact bug the
// backend added this member to remove, which the UI then re-introduced by not
// knowing about it.
export type AgentStatus =
  | "analysed"
  | "skipped_no_input"
  | "skipped_missing_input"
  | "skipped_degraded_input"
  | "failed"
  | "timed_out";

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface ProgressEvent {
  job_id: string;
  status: ScanStatus;
  progress: number;
  step: string;
  at: string;

  // Present only on per-agent frames, absent on the four stage frames. A frame
  // that names a node is not a stage change - see ScanProgress, which rendered
  // `step` unfiltered and so flickered "cve_analyst: running" at the user.
  node?: string | null;
  node_state?: string | null;
}

/** GET /api/v1/scans/jobs/{job_id}. */
export interface JobStatusResponse {
  job_id: string;
  status: ScanStatus;
  progress: number;
  current_step: string;
  started_at: string;
  updated_at: string;

  // The job says running but no worker holds its lease. There is no reaper, so
  // without this a dead scan reads as in-progress for the full 30-day TTL.
  stale: boolean;
}

export interface ScanSummary {
  job_id: string;
  tenant_id: string;
  repo_id: string;
  tenant_repo: string;
  target: string;
  scan_date: string;
  degraded: boolean;
  confidence: number;

  // Nullable, and the distinction is load-bearing. null means the axis had no
  // trustworthy evidence; 0 is a real score meaning "as bad as it gets".
  // Typed `number` here, null fell through every `>=` comparison and rendered
  // as a red 0/100 - "we could not tell" displayed as the worst possible news.
  overall: number | null;
  security: number | null;
  efficiency: number | null;
  compliance: number | null;

  finding_count: number;
  critical_count: number;
  high_count: number;
  report_key: string;
  expires_at: number;
}

interface BaseFinding {
  severity: Severity;
  title: string;
  impact: string;
  fix: string;
  effort: Effort;
  priority: number;

  // Stable identity across scans of the same repo. The join key the diff
  // rests on; empty on reports written before it existed.
  fingerprint?: string;

  // Stamped at read time by the policy layer, which MARKS rather than deletes -
  // so an accepted risk stays visible and reviewable. Absent on live findings.
  suppressed?: boolean;
  suppressed_reason?: string;
  suppressed_until?: string;
}

// Discriminated on category, mirroring the backend union in
// app/models/outcomes.py. A flat interface with optional fields would drop the
// per-category evidence the agents actually produce.
export interface CVEFinding extends BaseFinding {
  category: "cve";
  vulnerability_id: string;
  exploitability: Exploitability;

  // Copied from the scanner after the model replies, never asked of it - the
  // scanner is the authority on these and asking a model to repeat them only
  // invents a chance to get them wrong. All optional: reports predating the
  // enrichment carry none of them.
  package?: string;
  installed_version?: string;
  fixed_version?: string;
  cvss_score?: number;
  cvss_vector?: string;
  cwe_ids?: string[];
  references?: string[];

  // The authoritative advisory link. The UI used to guess an NVD URL from a
  // regex, which cannot work for GHSA ids.
  primary_url?: string;
  layer_digest?: string;

  // The scanner's own severity, kept beside the model's so a disagreement is
  // visible rather than silently resolved.
  scanner_severity?: Severity | null;

  // Measured exploitability, as opposed to `exploitability` above which is the
  // model's judgement. null means the feed was unavailable - which is not the
  // same as "not listed", and must not render as a reassuring absence.
  kev_listed?: boolean | null;
  epss_score?: number | null;
}

export interface BloatFinding extends BaseFinding {
  category: "bloat";
  layer_index: number;
  wasted_bytes: number;
  root_cause_command: string;
}

export interface BaseImageFinding extends BaseFinding {
  category: "base_image";
  recommended_base: string;
  estimated_savings_bytes: number;
  breaking_risk: string;
}

export interface ComplianceFinding extends BaseFinding {
  category: "compliance";
  control_id: string;
  evidence: string;
}

/**
 * Produced on every scan by the deterministic secret_scan pass - Trivy has
 * always been asked for these and the report has always carried them.
 *
 * `redacted_match` is a redaction, never the credential: the backend stores a
 * prefix and asterisks, so this type cannot be used to leak one.
 */
export interface SecretFinding extends BaseFinding {
  category: "secret";
  rule_id: string;
  category_name: string;
  file_path: string;
  line: number;
  redacted_match: string;
}

export type Finding =
  | CVEFinding
  | BloatFinding
  | BaseImageFinding
  | ComplianceFinding
  | SecretFinding;

export interface AgentOutcome {
  agent: string;
  status: AgentStatus;
  findings: Finding[];
  error: string | null;
  duration_seconds: number;
}

/**
 * What the scan actually looked at, beside what got written up.
 *
 * Only the worst N vulnerabilities ever reach a model; the rest are counted
 * and dropped. Without this the report implied completeness - a handful of
 * findings over an image with eleven thousand vulnerabilities.
 */
export interface ScanCoverage {
  total_vulnerabilities: number;
  counts_by_severity: Partial<Record<Severity, number>>;
  dedup_removed: number;
  sent_to_model: number;

  /** Above zero means the report is a sample, and the UI has to say so. */
  dropped: number;

  total_secrets: number;
  kev_available: boolean;
  epss_available: boolean;
  image_id: string;
  repo_digests: string[];
  scanner_image: string;
  trivy_schema_version: number;
  scanned_at: string;
}

/** What changed since the previous scan of the same repo. */
export interface ScanDiff {
  previous_job_id: string;
  previous_scan_date: string;
  new: string[];
  fixed: string[];
  persisting: string[];
}

/**
 * What the image is, read from its own config before any agent runs.
 *
 * Stored on every report since the scanner layer and never once rendered.
 * It is the only content in a report that no injected text can influence and
 * that survives every agent failing. See docs/audits/audit-02-frontend-worker-observability.md F13.
 */
export interface ImageProfile {
  target: string;
  os_family: string;
  os_name: string;
  base_reference: string;
  user: string;
  exposed_ports: number[];
  env_keys: string[];
  entrypoint: string[];
  cmd: string[];
  has_healthcheck: boolean;
  layer_count: number;
  total_size_bytes: number;
}

/** One component of the image's bill of materials. */
export interface Package {
  name: string;
  version: string;
  purl: string;
  licenses: string[];
  source: string;
}

export interface RiskScore {
  overall: number | null;
  security: number | null;
  efficiency: number | null;
  compliance: number | null;
  summary: string;
  top_priorities: string[];
}

export interface FullReport {
  job_id: string;

  /** The image this report is about. Lived only on the summary row before. */
  target?: string;

  outcomes: AgentOutcome[];
  risk: {
    score: RiskScore;
    confidence: number;
    inputs_used: string[];
    inputs_missing: string[];
  } | null;
  dockerfile: {
    status: AgentStatus;
    optimization: {
      reconstructed: string;
      optimized: string;
      reconstruction_notes: string;
    } | null;
    skipped_because: string[];
  } | null;

  // All four are optional because a report stored before the phase that
  // added them has none. `profile` is the oldest of them and was the last to
  // be typed here, which is how it stayed invisible for so long.
  profile?: ImageProfile | null;
  coverage?: ScanCoverage | null;
  diff?: ScanDiff | null;
  packages?: Package[];
}

/** The export formats GET /report can serve besides JSON. */
export type ExportFormat = "sarif" | "cyclonedx" | "csv" | "junit";

/** One image on the Docker daemon the API can reach. */
export interface LocalImage {
  reference: string;
  image_id: string;
  size: string;
  created: string;
}
