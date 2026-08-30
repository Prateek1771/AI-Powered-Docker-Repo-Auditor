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
    """Flatten the prose fields of any finding into one lowercase string.

    Every finding type is searched the same way, so an expectation does
    not have to know which agent produced the finding it matches.
    """
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
    """Test one finding against an expectation's match rules.

    Identifiers must be exact; keywords_any is a substring test, which is
    brittle by design - it is honest about being keyword matching rather
    than pretending to understand the text.
    """
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
    """Decide whether one expectation was met, and say why if not.

    An agent that did not run, or ran untrustworthily, fails the
    expectation rather than silently counting as 'found nothing'. The
    reason string is what makes a failing eval diagnosable.
    """
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
