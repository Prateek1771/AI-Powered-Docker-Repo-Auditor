import json
import logging
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from app.agents.prompts import BLOAT_DETECTIVE_PROMPT
from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
)
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

    client = ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )

    response = await client.ainvoke(
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
