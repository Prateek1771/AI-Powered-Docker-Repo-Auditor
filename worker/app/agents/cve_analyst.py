import json
import logging
from typing import Literal

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from app.agents.prompts import CVE_ANALYST_PROMPT
from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
)
from app.models.findings import CVEAnalysis, CVEFinding
from app.processors.vulnerabilities import RawVulnerability, prioritise

logger = logging.getLogger(__name__)


class CVEAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[CVEFinding]
    vulnerabilities_examined: int


class CVEAnalysisError(RuntimeError):
    pass


def _build_client() -> ChatOpenAI:
    return ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )


def parse_analysis(
    raw_content: str,
    allowed_ids: set[str],
) -> list[CVEFinding]:
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise CVEAnalysisError(f"Model returned non-JSON content: {exc}") from exc

    try:
        analysis = CVEAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise CVEAnalysisError(
            f"Model response failed schema validation: {exc.error_count()} errors"
        ) from exc

    returned_ids = {finding.vulnerability_id for finding in analysis.findings}

    hallucinated = returned_ids - allowed_ids

    if hallucinated:
        raise CVEAnalysisError(
            "Model returned vulnerability IDs absent from scan input: "
            f"{sorted(hallucinated)[:5]}"
        )

    return analysis.findings


def _build_messages(
    vulnerabilities: list[RawVulnerability],
) -> list[BaseMessage]:
    payload = json.dumps(
        [item.model_dump() for item in vulnerabilities],
        indent=2,
    )

    return [
        SystemMessage(content=CVE_ANALYST_PROMPT),
        HumanMessage(
            content=(
                "Trivy scan results as JSON:\n\n"
                f"{payload}\n\n"
                "Analyse these and return the JSON object."
            )
        ),
    ]


async def run_cve_analyst(
    vulnerabilities: list[RawVulnerability],
) -> CVEAnalysisResult:
    if not vulnerabilities:
        logger.info("No vulnerabilities found, skipping model call")

        return CVEAnalysisResult(
            status="skipped_no_input",
            findings=[],
            vulnerabilities_examined=0,
        )

    prioritised = prioritise(vulnerabilities)

    allowed_ids = {item.id for item in prioritised}

    response = await _build_client().ainvoke(_build_messages(prioritised))

    findings = parse_analysis(
        response.text,
        allowed_ids,
    )

    logger.info(
        "CVE analyst produced %d findings from %d vulnerabilities",
        len(findings),
        len(prioritised),
    )

    return CVEAnalysisResult(
        status="analysed",
        findings=findings,
        vulnerabilities_examined=len(prioritised),
    )
