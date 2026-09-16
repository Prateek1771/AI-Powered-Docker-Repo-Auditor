"""The risk score, computed rather than asked for.

The four 0-100 scores were whatever a model returned, guided only by prose
("security carries the heaviest weight", "be willing to give low scores").
There was no formula, no seed, and temperature=0 on gpt-4o is not
deterministic - so the number users treat as authoritative was not
reproducible and could not be diffed across scans.

Worse, "degraded" did nothing to it. With two of four agents failed the model
was handed "findings from 2 of 4 agents" and would return compliance: 85 on
zero compliance evidence, because absence of findings reads as absence of
problems.

Here, an axis whose evidence is missing scores None - not a number. See
docs/audits/audit-01-backend.md P2-6.
"""

from app.models.findings import Severity
from app.models.outcomes import AgentOutcome

# What one finding of each severity costs its axis. Roughly geometric: a
# critical is worth about four highs, which matches how people actually
# triage. These are a policy choice, and being able to point at the choice is
# the entire advantage over asking a model.
SEVERITY_COST: dict[Severity, int] = {
    "critical": 40,
    "high": 18,
    "medium": 7,
    "low": 2,
    "informational": 0,
}

# Which agents feed which axis. An axis with no trustworthy input scores None.
AXIS_INPUTS = {
    "security": ("cve_analyst", "cis_controls", "secret_scan"),
    "efficiency": ("bloat_detective", "base_image_strategist"),
    "compliance": ("compliance_checker", "cis_controls"),
}

# Security dominates: this is a security scanner, and an efficient image full
# of critical CVEs is not a good image.
AXIS_WEIGHT = {
    "security": 0.6,
    "efficiency": 0.15,
    "compliance": 0.25,
}


def _score_from(findings: list) -> int:
    """Turn a list of findings into 0-100, where 100 is clean.

    Saturating rather than linear: the difference between zero and one
    critical matters enormously, the difference between twenty and
    twenty-one does not.
    """
    penalty = sum(SEVERITY_COST.get(f.severity, 0) for f in findings)

    return max(0, 100 - min(penalty, 100))


def axis_scores(
    outcomes: list[AgentOutcome],
) -> dict[str, int | None]:
    """Score each axis, or None where the evidence never arrived.

    None is the point. A number computed from an agent that failed is a
    number about nothing, and rendering it beside a confidence footnote
    invites exactly the misreading this is meant to prevent.
    """
    by_agent = {o.agent: o for o in outcomes}

    scores: dict[str, int | None] = {}

    for axis, agents in AXIS_INPUTS.items():
        contributing = [
            by_agent[name]
            for name in agents
            if name in by_agent and by_agent[name].is_trustworthy
        ]

        if not contributing:
            scores[axis] = None
            continue

        scores[axis] = _score_from(
            [finding for outcome in contributing for finding in outcome.findings]
        )

    return scores


def overall_score(scores: dict[str, int | None]) -> int | None:
    """Blend the axes, over whatever evidence exists.

    Re-normalised across the axes that scored, so a missing axis lowers
    confidence rather than silently contributing a zero - and the result is
    clamped to the worst axis, because an image cannot be in better shape
    overall than it is at its weakest.
    """
    present = {k: v for k, v in scores.items() if v is not None}

    if not present:
        return None

    weight = sum(AXIS_WEIGHT[k] for k in present)

    blended = sum(AXIS_WEIGHT[k] * v for k, v in present.items()) / weight

    return min(round(blended), min(present.values()))
