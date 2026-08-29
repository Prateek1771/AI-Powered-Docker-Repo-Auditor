import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DegradedNotice } from "@/components/DegradedNotice";
import { FindingsEmpty } from "@/components/FindingsEmpty";
import type { AgentStatus, FullReport } from "@/types/scan";

function report(statuses: AgentStatus[]): FullReport {
  return {
    job_id: "j1",
    outcomes: statuses.map((status, i) => ({
      agent: ["cve_analyst", "bloat_detective", "risk_scorer"][i],
      status,
      findings: [],
      error: status === "failed" ? "timeout after 120s" : null,
      duration_seconds: 1,
    })),
    risk: null,
    dockerfile: null,
  };
}

describe("DegradedNotice", () => {
  it("renders nothing when every check completed", () => {
    const { container } = render(
      <DegradedNotice
        report={report(["analysed", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("names the check that failed in plain language", () => {
    render(
      <DegradedNotice
        report={report(["failed", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(screen.getByText(/Vulnerability analysis/)).toBeDefined();
    expect(screen.getByText(/incomplete/i)).toBeDefined();
  });

  it("counts a skipped dependent check as incomplete", () => {
    render(
      <DegradedNotice
        report={report(["analysed", "skipped_degraded_input", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(screen.getByText(/depends on a check that failed/)).toBeDefined();
  });

  it("does not flag a clean image that was skipped for having no input", () => {
    const { container } = render(
      <DegradedNotice
        report={report(["skipped_no_input", "analysed", "analysed"])}
        onRescan={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});

describe("FindingsEmpty", () => {
  it("says the image is clean when nothing failed", () => {
    render(<FindingsEmpty degraded={false} />);

    expect(screen.getByText("Nothing to fix")).toBeDefined();
  });

  it("says the review is incomplete when something failed", () => {
    render(<FindingsEmpty degraded />);

    expect(screen.getByText(/not been fully reviewed/)).toBeDefined();
  });
});
