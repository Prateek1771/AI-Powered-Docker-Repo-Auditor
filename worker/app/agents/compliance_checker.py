import json
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import COMPLIANCE_PROMPT
from app.agents.runner import AgentError, run_structured_agent
from app.models.findings import ComplianceAnalysis, ComplianceFinding
from app.processors.layers import ImageLayer
from app.processors.profile import ImageProfile

KNOWN_CONTROLS = {
    "4.1",
    "4.3",
    "4.6",
    "4.7",
    "4.9",
    "4.10",
    "5.8",
}


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
    """Check an image profile and its layers against the CIS controls."""
    analysis = await run_structured_agent(
        agent_name="compliance_checker",
        system_prompt=COMPLIANCE_PROMPT,
        user_content=(
            "Image profile:\n\n"
            f"{json.dumps(profile.model_dump(), indent=2)}\n\n"
            "Layer history:\n\n"
            f"{json.dumps([l.model_dump() for l in layers], indent=2)}\n\n"
            "Report failing controls. Return the JSON object."
        ),
        response_model=ComplianceAnalysis,
        guard=_guard,
    )

    return ComplianceResult(
        status="analysed",
        findings=analysis.findings,
    )
