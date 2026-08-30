import json
import logging
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

from app.agents.prompts import BLOAT_DETECTIVE_PROMPT
from app.agents.runner import build_client
from app.models.findings import BloatAnalysis, BloatFinding
from app.processors.layers import ImageLayer

logger = logging.getLogger(__name__)


class BloatAnalysisError(RuntimeError):
    pass


class BloatAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[BloatFinding]
    layers_examined: int


def parse_bloat_analysis(
    raw_content: str,
    allowed_indexes: set[int],
) -> list[BloatFinding]:
    """Parse a bloat analysis and reject layer indexes not in the input.

    Same contract as the CVE analyst's id check: a finding pinned to a
    layer that does not exist is worse than no finding.
    """
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise BloatAnalysisError(f"Model returned non-JSON content: {exc}") from exc

    try:
        analysis = BloatAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise BloatAnalysisError(
            f"Model response failed schema validation: {exc.error_count()} errors"
        ) from exc

    returned = {finding.layer_index for finding in analysis.findings}

    unknown = returned - allowed_indexes

    if unknown:
        raise BloatAnalysisError(
            f"Model returned layer indexes absent from input: {sorted(unknown)[:5]}"
        )

    return analysis.findings


async def run_bloat_detective(
    layers: list[ImageLayer],
) -> BloatAnalysisResult:
    """Find wasted space in an image's layers and name the instruction.

    No layers is skipped_no_input rather than a clean result - an image
    whose history could not be read has not been shown to be lean.
    """
    if not layers:
        return BloatAnalysisResult(
            status="skipped_no_input",
            findings=[],
            layers_examined=0,
        )

    payload = json.dumps(
        [layer.model_dump() for layer in layers],
        indent=2,
    )

    response = await build_client().ainvoke(
        [
            SystemMessage(content=BLOAT_DETECTIVE_PROMPT),
            HumanMessage(
                content=(
                    "Image layer history as JSON:\n\n"
                    f"{payload}\n\n"
                    "Identify bloat and return the JSON object."
                )
            ),
        ]
    )

    findings = parse_bloat_analysis(
        response.text,
        {layer.index for layer in layers},
    )

    return BloatAnalysisResult(
        status="analysed",
        findings=findings,
        layers_examined=len(layers),
    )
