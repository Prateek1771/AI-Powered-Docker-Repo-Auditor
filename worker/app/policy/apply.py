"""Apply suppressions to findings - by marking them, never by deleting them.

The distinction is the whole design. A suppressed finding stays in the report,
carrying the reason it was accepted, and is excluded from the gate and the
score. Dropping it instead would mean:

  - nobody can review what was accepted,
  - an expiry has nothing to un-hide,
  - and the report quietly disagrees with the scanner about what is in the
    image.

Applied late, at read time, for the same reason: the stored report is evidence
and should not depend on what the policy happened to say the day it was
written.
"""

from datetime import datetime

from app.policy.store import Policy, Suppression


def _first_match(
    finding: dict,
    suppressions: list[Suppression],
) -> Suppression | None:
    for suppression in suppressions:
        if suppression.matches(finding):
            return suppression

    return None


def apply_policy(
    report: dict,
    policy: Policy,
    now: datetime | None = None,
) -> dict:
    """Return the report with suppressed findings marked.

    The input is not mutated: callers hold the stored report and may reuse
    it for another export.
    """
    active = policy.active(now)

    if not active:
        return report

    outcomes = []

    for outcome in report.get("outcomes") or []:
        findings = []

        for finding in outcome.get("findings") or []:
            match = _first_match(finding, active)

            if match is None:
                findings.append(finding)
                continue

            findings.append(
                {
                    **finding,
                    "suppressed": True,
                    "suppressed_reason": match.reason,
                    "suppressed_until": match.expires_at,
                }
            )

        outcomes.append({**outcome, "findings": findings})

    return {**report, "outcomes": outcomes}


def unsuppressed_findings(report: dict) -> list[dict]:
    """Every finding the report still stands behind.

    What the gate counts and what the score is computed from.
    """
    return [
        finding
        for outcome in report.get("outcomes") or []
        for finding in outcome.get("findings") or []
        if not finding.get("suppressed")
    ]


def all_findings(report: dict) -> list[dict]:
    """Every finding, suppressed or not. What an export shows."""
    return [
        finding
        for outcome in report.get("outcomes") or []
        for finding in outcome.get("findings") or []
    ]
