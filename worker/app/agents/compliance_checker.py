import json
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import COMPLIANCE_PROMPT
from app.agents.runner import AgentError, run_structured_agent, untrusted_block
from app.models.findings import ComplianceAnalysis, ComplianceFinding
from app.processors.compliance import DETERMINISTIC_CONTROLS
from app.processors.layers import ImageLayer
from app.processors.profile import ImageProfile

# What the model is still asked to judge. 4.1, 4.6 and 5.8 are decided in
# app/processors/compliance.py because they are comparisons, not judgements -
# and a comparison a human wrote cannot be talked out of its answer by content
# in the image being scanned.
JUDGEMENT_CONTROLS = {
    "4.3",
    "4.7",
    "4.9",
    "4.10",
}

KNOWN_CONTROLS = JUDGEMENT_CONTROLS | DETERMINISTIC_CONTROLS


class ComplianceResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[ComplianceFinding]


def _guard(analysis: ComplianceAnalysis) -> None:
    """Reject controls that are not in the known CIS set.

    Without this the model can cite an authoritative-looking control
    number that does not exist, which is unfalsifiable to a reader.
    """
    unknown = {f.control_id for f in analysis.findings} - KNOWN_CONTROLS

    if unknown:
        raise AgentError(f"compliance_checker: invented control IDs {sorted(unknown)}")


async def run_compliance_checker(
    profile: ImageProfile,
    layers: list[ImageLayer],
) -> ComplianceResult:
    """Check an image profile and its layers against the judgement controls.

    4.1, 4.6 and 5.8 are NOT here. The orchestrator evaluates them from
    the profile before any agent runs, so they reach the report even when
    this agent times out or fails - which is the whole point of moving
    them out of a prompt.
    """
    analysis = await run_structured_agent(
        agent_name="compliance_checker",
        system_prompt=COMPLIANCE_PROMPT,
        user_content=(
            f"Image profile:\n\n{untrusted_block(json.dumps(profile.model_dump(), indent=2))}\n\n"
            "Layer history:\n\n"
            f"{untrusted_block(json.dumps([layer.model_dump() for layer in layers], indent=2))}\n\n"
            "Report failing controls. Return the JSON object."
        ),
        response_model=ComplianceAnalysis,
        guard=_guard,
    )

    # Drop any deterministic control the model reported anyway. Two sources
    # for one control would double-count it in the risk score, and the
    # Python answer is the one that cannot be influenced.
    return ComplianceResult(
        status="analysed",
        findings=[
            finding
            for finding in analysis.findings
            if finding.control_id not in DETERMINISTIC_CONTROLS
        ],
    )
