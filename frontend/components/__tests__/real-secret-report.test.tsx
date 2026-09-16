import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingsList } from "@/components/FindingsList";
import type { Finding } from "@/types/scan";

/**
 * Captured verbatim from a real scan of an image with two planted credentials
 * — a synthetic AWS key and a synthetic GitHub PAT — fetched from the live API.
 *
 * Not hand-written, because a hand-written fixture is a guess at the payload
 * and the guess is exactly what was wrong here for five backend phases. This
 * payload replaced the entire scan report with Next's error page before the
 * `secret` category existed in types/scan.ts.
 *
 * Note what is NOT in it: the credentials. The backend keeps a prefix and a
 * length, so a report can warn about a secret without carrying one.
 */
const REAL_SECRET_FINDINGS = [
  {
    "severity": "critical",
    "title": "Hardcoded secret: AWS Access Key ID",
    "impact": "A credential baked into an image layer is readable by anyone who can pull the image, and deleting it in a later layer does not remove it from the earlier one.",
    "fix": "Remove the credential, rotate it - assume it is compromised - and inject it at runtime instead.",
    "effort": "moderate",
    "priority": 95,
    "fingerprint": "9baefdc440d25e98",
    "category": "secret",
    "rule_id": "aws-access-key-id",
    "category_name": "AWS",
    "file_path": "/app/settings.py",
    "line": 2,
    "redacted_match": "AWS_ACCESS_K... <redacted, 42 chars>"
  },
  {
    "severity": "critical",
    "title": "Hardcoded secret: GitHub Personal Access Token",
    "impact": "A credential baked into an image layer is readable by anyone who can pull the image, and deleting it in a later layer does not remove it from the earlier one.",
    "fix": "Remove the credential, rotate it - assume it is compromised - and inject it at runtime instead.",
    "effort": "moderate",
    "priority": 95,
    "fingerprint": "223edbd093618407",
    "category": "secret",
    "rule_id": "github-pat",
    "category_name": "GitHub",
    "file_path": "/app/settings.py",
    "line": 3,
    "redacted_match": "GITHUB_TOKEN... <redacted, 57 chars>"
  }
] as unknown as Finding[];

describe("a real report containing secrets", () => {
  it("renders instead of taking the page down", () => {
    expect(() =>
      render(<FindingsList findings={REAL_SECRET_FINDINGS} />),
    ).not.toThrow();

    expect(
      screen.getByText(/Hardcoded secret: AWS Access Key ID/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Hardcoded secret: GitHub Personal Access Token/),
    ).toBeInTheDocument();
  });

  it("shows where each secret is, so it can be removed", () => {
    render(<FindingsList findings={REAL_SECRET_FINDINGS} />);

    expect(screen.getByText("/app/settings.py:2")).toBeInTheDocument();
    expect(screen.getByText("/app/settings.py:3")).toBeInTheDocument();
  });

  it("never renders the credential itself", () => {
    const { container } = render(
      <FindingsList findings={REAL_SECRET_FINDINGS} />,
    );

    // The shapes Trivy matched on. If either ever reaches the DOM, the report
    // has become a way to exfiltrate the thing it is warning about.
    expect(container.textContent).not.toMatch(/AKIA[A-Z0-9]{16}/);
    expect(container.textContent).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
    expect(container.textContent).toMatch(/redacted/);
  });
});
