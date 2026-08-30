import json

from app.agents.prompts import RISK_SCORER_PROMPT
from app.agents.runner import run_structured_agent
from app.agents.trust import input_confidence, missing_inputs
from app.models.findings import RiskScore, ScoredRisk
from app.models.outcomes import AgentOutcome

SCORER_INPUTS = [
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
    "compliance_checker",
]


async def run_risk_scorer(
    prior: dict[str, AgentOutcome],
) -> ScoredRisk:
    """Turn every agent's findings into scores and a priority order.

    Runs last because it reads all of them, and carries the confidence
    computed from which inputs were actually sound - the number is derived
    from the pipeline, never asked of the model.
    """
    confidence = input_confidence(prior, SCORER_INPUTS)

    missing = missing_inputs(prior, SCORER_INPUTS)

    used = [name for name in SCORER_INPUTS if name not in missing]

    findings = [
        finding.model_dump() for name in used for finding in prior[name].findings
    ]

    score = await run_structured_agent(
        agent_name="risk_scorer",
        system_prompt=RISK_SCORER_PROMPT,
        user_content=(
            f"Findings from {len(used)} of {len(SCORER_INPUTS)} agents:\n\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Return the JSON object."
        ),
        response_model=RiskScore,
    )

    return ScoredRisk(
        score=score,
        confidence=confidence,
        inputs_used=used,
        inputs_missing=missing,
    )
