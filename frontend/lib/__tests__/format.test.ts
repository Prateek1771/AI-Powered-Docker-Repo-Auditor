import { describe, expect, it } from "vitest";

import {
  compareFindings,
  countBySeverity,
  formatBytes,
  formatDuration,
  nvdUrl,
  severityRank,
} from "@/lib/format";
import type { Finding } from "@/types/scan";

function cve(severity: Finding["severity"], priority: number): Finding {
  return {
    category: "cve",
    severity,
    title: "t",
    impact: "i",
    fix: "f",
    effort: "trivial",
    priority,
    vulnerability_id: "CVE-2024-0001",
    exploitability: "likely",
  };
}

describe("formatBytes", () => {
  it("does not render a bare byte count for large layers", () => {
    expect(formatBytes(412_000_000)).toBe("393 MB");
  });

  it("keeps one decimal below 100 and drops it above", () => {
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(200 * 1024)).toBe("200 KB");
  });

  it("handles zero and negatives rather than printing NaN or -Infinity", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(-1)).toBe("0 B");
  });
});

describe("formatDuration", () => {
  it("uses milliseconds under a second", () => {
    expect(formatDuration(0.42)).toBe("420 ms");
  });

  it("uses seconds above one", () => {
    expect(formatDuration(12.34)).toBe("12.3 s");
  });
});

describe("nvdUrl", () => {
  it("links a real CVE id", () => {
    expect(nvdUrl("CVE-2023-45322")).toContain("nvd.nist.gov");
  });

  it("refuses ids NVD cannot resolve, rather than making a dead link", () => {
    // Trivy also emits GHSA and vendor identifiers.
    expect(nvdUrl("GHSA-xxxx-yyyy-zzzz")).toBeNull();
    expect(nvdUrl("DSA-5432-1")).toBeNull();
  });
});

describe("severityRank", () => {
  it("orders worst first, matching the backend", () => {
    expect(severityRank("critical")).toBeLessThan(severityRank("high"));
    expect(severityRank("low")).toBeLessThan(severityRank("informational"));
  });
});

describe("compareFindings", () => {
  it("sorts by severity before priority", () => {
    // A high/99 must not outrank a critical/10 - priority is only a
    // tie-breaker within a severity band.
    const sorted = [cve("high", 99), cve("critical", 10)].sort(compareFindings);

    expect(sorted[0].severity).toBe("critical");
  });

  it("falls back to priority within one severity", () => {
    const sorted = [cve("high", 10), cve("high", 90)].sort(compareFindings);

    expect(sorted[0].priority).toBe(90);
  });
});

describe("countBySeverity", () => {
  it("reports zero for absent severities instead of undefined", () => {
    expect(countBySeverity([cve("high", 1)])).toEqual({
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      informational: 0,
    });
  });
});
