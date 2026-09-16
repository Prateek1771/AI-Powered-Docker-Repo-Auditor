import json
import logging
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import BLOAT_DETECTIVE_PROMPT
from app.agents.runner import AgentError, run_structured_agent, untrusted_block
from app.models.findings import BloatAnalysis, BloatFinding
from app.processors.layers import ImageLayer

logger = logging.getLogger(__name__)


class BloatAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_missing_input"]
    findings: list[BloatFinding]
    layers_examined: int


async def run_bloat_detective(
    layers: list[ImageLayer],
) -> BloatAnalysisResult:
    """Find wasted space in an image's layers and name the instruction.

    No layers is `skipped_missing_input`, not `skipped_no_input`: an image
    whose history could not be read has not been shown to be lean. The
    distinction is what stops a squashed image scoring as confidently
    clean - see docs/audits/audit-01-backend.md P1-2.
    """
    if not layers:
        return BloatAnalysisResult(
            status="skipped_missing_input",
            findings=[],
            layers_examined=0,
        )

    allowed = {layer.index for layer in layers}

    def guard(analysis: BloatAnalysis) -> None:
        """Reject layer indexes that were not in the input.

        Same contract as the CVE analyst's id check: a finding pinned to
        a layer that does not exist is worse than no finding.
        """
        unknown = {f.layer_index for f in analysis.findings} - allowed

        if unknown:
            raise AgentError(
                f"bloat_detective: invented layer indexes {sorted(unknown)[:5]}"
            )

    payload = json.dumps(
        [layer.model_dump() for layer in layers],
        indent=2,
    )

    # Through run_structured_agent, not build_client directly. This agent used
    # to hand-roll its own call and its own parser, which meant every fix to
    # the shared path - the injection delimiters, the suppression guard, the
    # re-ask on malformed output - silently skipped it.
    analysis = await run_structured_agent(
        agent_name="bloat_detective",
        system_prompt=BLOAT_DETECTIVE_PROMPT,
        user_content=(
            f"Image layer history:\n\n{untrusted_block(payload)}\n\n"
            "Identify bloat and return the JSON object."
        ),
        response_model=BloatAnalysis,
        guard=guard,
        # A layer history that produced no bloat finding at all is possible
        # but unusual, and it is also exactly what a successful prompt
        # injection looks like. Above this many layers, demand an answer.
        expect_findings_above=12,
        input_size=len(layers),
    )

    return BloatAnalysisResult(
        status="analysed",
        findings=analysis.findings,
        layers_examined=len(layers),
    )
