import json
import logging

from app.agents.prompts import DOCKERFILE_OPTIMIZER_PROMPT
from app.agents.runner import run_structured_agent
from app.agents.trust import missing_inputs, required_inputs_sound
from app.models.findings import DockerfileOptimization, DockerfileResult
from app.models.outcomes import AgentOutcome
from app.processors.layers import ImageLayer

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = [
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
]


async def run_dockerfile_optimizer(
    layers: list[ImageLayer],
    prior: dict[str, AgentOutcome],
) -> DockerfileResult:
    """Reconstruct a Dockerfile from the layers and rewrite it.

    Depends on the earlier agents, so it refuses to run on partial input:
    a rewrite built from half the findings could drop a fix the reader
    needed, and a plausible wrong Dockerfile is worse than none.
    """
    if not required_inputs_sound(prior, REQUIRED_INPUTS):
        unsound = missing_inputs(prior, REQUIRED_INPUTS)

        logger.warning(
            "Skipping dockerfile optimizer, unsound inputs: %s",
            unsound,
        )

        return DockerfileResult(
            status="skipped_degraded_input",
            optimization=None,
            skipped_because=unsound,
        )

    findings = [
        finding.model_dump()
        for name in REQUIRED_INPUTS
        for finding in prior[name].findings
    ]

    optimization = await run_structured_agent(
        agent_name="dockerfile_optimizer",
        system_prompt=DOCKERFILE_OPTIMIZER_PROMPT,
        user_content=(
            "Layer history:\n\n"
            f"{json.dumps([l.model_dump() for l in layers], indent=2)}\n\n"
            "Findings from prior agents:\n\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Return the JSON object."
        ),
        response_model=DockerfileOptimization,
    )

    return DockerfileResult(
        status="analysed",
        optimization=optimization,
        skipped_because=[],
    )
