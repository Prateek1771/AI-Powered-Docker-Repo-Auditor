import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CoverageNotice } from "@/components/CoverageNotice";
import { DegradedNotice } from "@/components/DegradedNotice";
import { FindingCard } from "@/components/FindingCard";
import { ScanDiffSummary } from "@/components/ScanDiffSummary";
import { ScoreBars } from "@/components/ScoreBars";
import { ScoreRing } from "@/components/ScoreRing";
import { bandColor, formatScore, isDegraded } from "@/lib/format";
import type {
  AgentOutcome,
  Finding,
  FullReport,
  ScanCoverage,
} from "@/types/scan";

function outcome(status: AgentOutcome["status"]): AgentOutcome {
  return {
    agent: "bloat_detective",
    status,
    findings: [],
    error: null,
    duration_seconds: 0.4,
  };
}

function report(outcomes: AgentOutcome[]): FullReport {
  return { job_id: "j1", outcomes, risk: null, dockerfile: null };
}

/**
 * A null score means the axis had no trustworthy evidence. Zero is a real
 * score meaning "as bad as it gets". Rendering the first as the second is the
 * exact class of lie the backend scoring work exists to remove, and the UI
 * did it for five phases because it typed the scores as `number`.
 */
describe("a score that could not be computed", () => {
  it("is not coloured as though it were zero", () => {
    expect(bandColor(null)).not.toBe(bandColor(0));
    expect(bandColor(0)).toBe("var(--sev-critical)");
  });

  it("formats as words, not as a number", () => {
    expect(formatScore(null)).toBe("Not assessed");
    expect(formatScore(0)).toBe("0");
    expect(formatScore(72.4)).toBe("72");
  });

  it("renders no numeral in the ring", () => {
    render(<ScoreRing value={null} confidence={1} label="Overall" />);

    expect(screen.getByText("Not assessed")).toBeInTheDocument();
    expect(screen.queryByText("/100")).not.toBeInTheDocument();
  });

  it("renders a dash rather than a bar value", () => {
    render(
      <ScoreBars confidence={1} scores={[{ label: "Security", value: null }]} />,
    );

    expect(screen.getByText("--")).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
});

/**
 * skipped_missing_input means the evidence never arrived. skipped_no_input
 * means the agent looked and there was nothing. Conflating them is how an
 * unreadable image scores as confidently clean - P1-2 on the backend, and
 * re-introduced here by a type that could not express the difference.
 */
describe("an agent that never saw its input", () => {
  it("counts as degradation", () => {
    expect(isDegraded(outcome("skipped_missing_input"))).toBe(true);
    expect(isDegraded(outcome("failed"))).toBe(true);
    expect(isDegraded(outcome("timed_out"))).toBe(true);
    expect(isDegraded(outcome("skipped_degraded_input"))).toBe(true);
  });

  it("does not drag a genuinely clean scan into a warning", () => {
    expect(isDegraded(outcome("analysed"))).toBe(false);
    expect(isDegraded(outcome("skipped_no_input"))).toBe(false);
  });

  it("raises the banner", () => {
    render(
      <DegradedNotice
        report={report([outcome("skipped_missing_input")])}
        onRescan={() => {}}
      />,
    );

    expect(screen.getByRole("status")).toBeInTheDocument();
  });
});

/**
 * Only the worst N vulnerabilities reach a model. Without saying so the report
 * shows a handful of findings over an image with thousands and implies that is
 * all of them.
 */
describe("coverage", () => {
  const coverage: ScanCoverage = {
    total_vulnerabilities: 11028,
    counts_by_severity: { critical: 224, high: 2472 },
    dedup_removed: 0,
    sent_to_model: 150,
    dropped: 10878,
    total_secrets: 0,
    kev_available: true,
    epss_available: true,
    image_id: "sha256:abc",
    repo_digests: [],
    scanner_image: "trivy:0.74.0",
    trivy_schema_version: 2,
    scanned_at: "2026-09-15T00:00:00Z",
  };

  it("says how much of the image was not analysed", () => {
    render(<CoverageNotice coverage={coverage} />);

    expect(screen.getByText("11,028")).toBeInTheDocument();
    expect(screen.getByText(/10,878 were not/)).toBeInTheDocument();
  });

  it("says so plainly when the report IS complete", () => {
    render(
      <CoverageNotice
        coverage={{ ...coverage, dropped: 0, sent_to_model: 11028 }}
      />,
    );

    expect(screen.getByText(/This report is complete/)).toBeInTheDocument();
  });

  it("renders nothing for an image with no vulnerabilities", () => {
    const { container } = render(
      <CoverageNotice
        coverage={{ ...coverage, total_vulnerabilities: 0, dropped: 0 }}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});

/**
 * The policy layer MARKS rather than deletes, so an accepted risk stays in the
 * report and stays reviewable. The UI knowing nothing about it meant a
 * suppressed finding was counted in every total - which defeats the point of
 * marking rather than deleting.
 */
describe("a suppressed finding", () => {
  const suppressed = {
    severity: "high",
    title: "Accepted zlib issue",
    impact: "Not reachable in our usage",
    fix: "None available",
    effort: "involved",
    priority: 40,
    category: "cve",
    vulnerability_id: "CVE-2018-25032",
    exploitability: "unlikely",
    suppressed: true,
    suppressed_reason: "Not reachable, reviewed 2026-09-01",
  } as unknown as Finding;

  it("is still shown, and shown as accepted", () => {
    render(<FindingCard finding={suppressed} />);

    expect(screen.getByText("Accepted zlib issue")).toBeInTheDocument();
    expect(screen.getByText("suppressed")).toBeInTheDocument();
    expect(
      screen.getByText(/Not reachable, reviewed 2026-09-01/),
    ).toBeInTheDocument();
  });
});

describe("the scan-to-scan diff", () => {
  it("answers whether the last fix worked", () => {
    render(
      <ScanDiffSummary
        diff={{
          previous_job_id: "j0",
          previous_scan_date: "2026-09-01T00:00:00Z",
          new: ["a"],
          fixed: ["b", "c"],
          persisting: ["d", "e", "f"],
        }}
      />,
    );

    expect(screen.getByText("New").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Fixed").previousSibling).toHaveTextContent("2");
    expect(screen.getByText("Still there").previousSibling).toHaveTextContent(
      "3",
    );
  });
});
