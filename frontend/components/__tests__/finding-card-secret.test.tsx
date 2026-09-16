import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingCard } from "@/components/FindingCard";
import type { Finding } from "@/types/scan";

const BASE = {
  severity: "critical",
  title: "AWS key in a layer",
  impact: "Credential exposure",
  fix: "Rotate and rebuild",
  effort: "moderate",
  priority: 95,
} as const;

/**
 * The regression test for the outage. secret_scan runs on every scan, the page
 * flatMaps every outcome's findings, and the default filter passes them
 * through - so before this, one detected secret replaced the whole report with
 * Next's error page. See docs/AUDIT.md.
 */
describe("FindingCard survives categories it was not built for", () => {
  it("renders a secret finding's evidence without the credential", () => {
    const finding: Finding = {
      ...BASE,
      category: "secret",
      rule_id: "aws-access-key-id",
      category_name: "AWS",
      file_path: "app/settings.py",
      line: 12,
      redacted_match: "AKIA****************",
    };

    render(<FindingCard finding={finding} />);

    expect(screen.getByText("app/settings.py:12")).toBeInTheDocument();
    expect(screen.getByText(/AKIA\*+/)).toBeInTheDocument();
  });

  it("degrades rather than throwing on a category it has never seen", () => {
    // Not hypothetical: `secret` WAS this case until the line above. The next
    // category the backend adds must be a missing label, not an outage.
    const finding = {
      ...BASE,
      category: "quantum",
    } as unknown as Finding;

    expect(() => render(<FindingCard finding={finding} />)).not.toThrow();

    expect(screen.getByText("AWS key in a layer")).toBeInTheDocument();
  });
});
