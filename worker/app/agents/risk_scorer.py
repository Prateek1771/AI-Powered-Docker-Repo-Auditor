import json
import logging

from app.agents.prompts import RISK_SCORER_PROMPT
from app.agents.runner import run_structured_agent, untrusted_block
from app.agents.trust import input_confidence, missing_inputs
from app.models.findings import RiskNarrative, RiskScore, ScoredRisk
from app.models.outcomes import AgentOutcome
from app.processors.scoring import axis_scores, overall_score

logger = logging.getLogger(__name__)

SCORER_INPUTS = [
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
    "compliance_checker",
]


async def run_risk_scorer(
    prior: dict[str, AgentOutcome],
) -> ScoredRisk:
    """Score the image, and ask a model only for the words.

    The four numbers are computed in processors/scoring.py from finding
    counts and severities. They used to be whatever the model returned,
    which meant two runs over identical cached scanner output produced
    different scores - and the eval harness was comparing against a moving
    target.

    Runs last because it reads every other outcome, and carries the
    confidence computed from which inputs were actually sound. That number
    is derived from the pipeline, never asked of the model.
    """
    confidence = input_confidence(prior, SCORER_INPUTS)

    missing = missing_inputs(prior, SCORER_INPUTS)

    used = [name for name in SCORER_INPUTS if name not in missing]

    scores = axis_scores(list(prior.values()))

    overall = overall_score(scores)

    findings = [
        finding.model_dump() for name in used for finding in prior[name].findings
    ]

    narrative = await run_structured_agent(
        agent_name="risk_scorer",
        system_prompt=RISK_SCORER_PROMPT,
        user_content=(
            f"Computed scores: {json.dumps(scores)} (overall {overall}).\n\n"
            f"Findings from {len(used)} of {len(SCORER_INPUTS)} agents:\n\n"
            f"{untrusted_block(json.dumps(findings, indent=2))}\n\n"
            "Return the JSON object."
        ),
        response_model=RiskNarrative,
    )

    return ScoredRisk(
        score=RiskScore(
            overall=overall,
            security=scores.get("security"),
            efficiency=scores.get("efficiency"),
            compliance=scores.get("compliance"),
            summary=narrative.summary,
            top_priorities=narrative.top_priorities,
        ),
        confidence=confidence,
        inputs_used=used,
        inputs_missing=missing,
    )
