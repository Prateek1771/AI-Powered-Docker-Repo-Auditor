from typing import Any

from app.models.outcomes import AgentOutcome

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _text_of(finding: Any) -> str:
    parts = [
        getattr(finding, "title", ""),
        getattr(finding, "fix", ""),
        getattr(finding, "impact", ""),
        getattr(finding, "root_cause_command", ""),
        getattr(finding, "recommended_base", ""),
        getattr(finding, "evidence", ""),
    ]

    return " ".join(str(p) for p in parts).lower()


def finding_matches(finding: Any, match: dict) -> bool:
    if (
        "control_id" in match
        and getattr(finding, "control_id", None) != match["control_id"]
    ):
        return False

    if (
        "vulnerability_id" in match
        and getattr(finding, "vulnerability_id", None) != match["vulnerability_id"]
    ):
        return False

    if "keywords_any" in match:
        text = _text_of(finding)

        if not any(keyword.lower() in text for keyword in match["keywords_any"]):
            return False

    return True


def evaluate_expectation(
    expectation: dict,
    outcomes: dict[str, AgentOutcome],
) -> tuple[bool, str]:
    agent = expectation["agent"]

    if agent not in outcomes:
        return False, "agent did not run"

    outcome = outcomes[agent]

    if not outcome.is_trustworthy:
        return False, f"agent {outcome.status}"

    match = expectation.get("match", {})

    if "min_count" in match:
        found = len(outcome.findings) >= match["min_count"]

        return found, f"{len(outcome.findings)} findings"

    hits = [finding for finding in outcome.findings if finding_matches(finding, match)]

    if not hits:
        return False, "no matching finding"

    minimum = expectation.get("min_severity")

    if minimum:
        best = max(SEVERITY_RANK[h.severity] for h in hits)

        if best < SEVERITY_RANK[minimum]:
            return False, "found but severity too low"

    return True, f"{len(hits)} matching"
