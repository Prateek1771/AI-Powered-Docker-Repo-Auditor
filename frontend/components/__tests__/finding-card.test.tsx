import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingCard } from "@/components/FindingCard";
import type { Finding } from "@/types/scan";

const BASE = {
  severity: "high",
  title: "A finding",
  impact: "It is bad",
  fix: "Make it good",
  effort: "moderate",
  priority: 70,
} as const;

/**
 * Each agent produces evidence only its own category carries. A card that
 * silently drops those fields still looks correct on screen, which is exactly
 * why types/scan.ts models Finding as a union discriminated on `category` -
 * these assertions are what makes the narrowing load-bearing.
 */
describe("FindingCard renders the evidence for each category", () => {
  it("links a CVE to NVD and names its exploitability", () => {
    const finding: Finding = {
      ...BASE,
      category: "cve",
      vulnerability_id: "CVE-2023-45322",
      exploitability: "actively_exploited",
    };

    render(<FindingCard finding={finding} />);

    const link = screen.getByRole("link", { name: /CVE-2023-45322/ });

    expect(link).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2023-45322",
    );
    expect(screen.getAllByText(/actively exploited/).length).toBeGreaterThan(0);
  });

  it("shows a bloat finding's wasted bytes, layer and root cause", () => {
    const finding: Finding = {
      ...BASE,
      category: "bloat",
      layer_index: 7,
      wasted_bytes: 412_000_000,
      root_cause_command: "apt-get install -y build-essential",
    };

    render(<FindingCard finding={finding} />);

    expect(screen.getByText("393 MB")).toBeInTheDocument();
    expect(screen.getByText("#7")).toBeInTheDocument();
    expect(screen.getByText(/build-essential/)).toBeInTheDocument();
  });

  it("shows the recommended base image and what it saves", () => {
    const finding: Finding = {
      ...BASE,
      category: "base_image",
      recommended_base: "python:3.12-slim",
      estimated_savings_bytes: 700_000_000,
      breaking_risk: "Low - no compiled extensions in use",
    };

    render(<FindingCard finding={finding} />);

    expect(screen.getByText("python:3.12-slim")).toBeInTheDocument();
    expect(screen.getByText("668 MB")).toBeInTheDocument();
    expect(screen.getByText(/no compiled extensions/)).toBeInTheDocument();
  });

  it("shows the CIS control id and the evidence for it", () => {
    const finding: Finding = {
      ...BASE,
      category: "compliance",
      control_id: "CIS-4.1",
      evidence: "No USER instruction in the image config",
    };

    render(<FindingCard finding={finding} />);

    // Twice by design: once in the collapsed row, once under "Control".
    expect(screen.getAllByText("CIS-4.1")).toHaveLength(2);
    expect(screen.getByText(/No USER instruction/)).toBeInTheDocument();
  });

  it("does not fabricate a link for an id NVD cannot resolve", () => {
    const finding: Finding = {
      ...BASE,
      category: "cve",
      vulnerability_id: "GHSA-abcd-1234-wxyz",
      exploitability: "theoretical",
    };

    render(<FindingCard finding={finding} />);

    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getAllByText(/GHSA-abcd-1234-wxyz/).length).toBeGreaterThan(0);
  });

  it("always states the severity as a word, never colour alone", () => {
    render(<FindingCard finding={{ ...BASE, category: "cve", vulnerability_id: "CVE-2024-0001", exploitability: "likely" }} />);

    expect(screen.getByText("high")).toBeInTheDocument();
  });
});
