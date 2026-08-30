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

// All five, including skipped_degraded_input. If the type cannot express a
// failure, no component can render one.
export type AgentStatus =
  | "analysed"
  | "skipped_no_input"
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
  overall: number;
  security: number;
  efficiency: number;
  compliance: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  report_key: string;
}

interface BaseFinding {
  severity: Severity;
  title: string;
  impact: string;
  fix: string;
  effort: Effort;
  priority: number;
}

// Discriminated on category, mirroring the backend union in
// app/models/outcomes.py. A flat interface with optional fields would drop the
// per-category evidence the agents actually produce.
export interface CVEFinding extends BaseFinding {
  category: "cve";
  vulnerability_id: string;
  exploitability: Exploitability;
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

export type Finding =
  | CVEFinding
  | BloatFinding
  | BaseImageFinding
  | ComplianceFinding;

export interface AgentOutcome {
  agent: string;
  status: AgentStatus;
  findings: Finding[];
  error: string | null;
  duration_seconds: number;
}

export interface FullReport {
  job_id: string;
  outcomes: AgentOutcome[];
  risk: {
    score: {
      overall: number;
      security: number;
      efficiency: number;
      compliance: number;
      summary: string;
      top_priorities: string[];
    };
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
}

/** One image on the Docker daemon the API can reach. */
export interface LocalImage {
  reference: string;
  image_id: string;
  size: string;
  created: string;
}
