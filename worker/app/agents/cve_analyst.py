import json
import logging
from typing import Literal

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

from app.agents.prompts import CVE_ANALYST_PROMPT
from app.agents.runner import AgentError, run_structured_agent
from app.models.findings import CVEAnalysis, CVEFinding
from app.processors.vulnerabilities import RawVulnerability, prioritise

logger = logging.getLogger(__name__)


class CVEAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[CVEFinding]
    vulnerabilities_examined: int


class CVEAnalysisError(RuntimeError):
    pass


def parse_analysis(
    raw_content: str,
    allowed_ids: set[str],
) -> list[CVEFinding]:
    """Parse a CVE analysis and reject any id that was not in the input.

    The hallucination check is the point. A plausible CVE id the scanner
    never reported would send someone chasing a vulnerability that is not
    in their image, so the whole response is refused rather than filtered.
    """
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
    """Build the prompt pair for a batch of vulnerabilities."""
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
    """Triage scanner vulnerabilities into ranked, explained findings.

    No vulnerabilities is skipped_no_input, not an empty success: the
    difference is what stops a clean scan and a failed one scoring alike.
    Only the worst MAX_VULNERABILITIES_TO_MODEL are sent.
    """
    if not vulnerabilities:
        return CVEAnalysisResult(
            status="skipped_no_input",
            findings=[],
            vulnerabilities_examined=0,
        )

    prioritised = prioritise(vulnerabilities)
    allowed = {item.id for item in prioritised}

    def guard(analysis: CVEAnalysis) -> None:
        unknown = {f.vulnerability_id for f in analysis.findings} - allowed

        if unknown:
            raise AgentError(
                f"cve_analyst: invented vulnerability IDs {sorted(unknown)[:5]}"
            )

    payload = json.dumps(
        [v.model_dump() for v in prioritised],
        indent=2,
    )

    analysis = await run_structured_agent(
        agent_name="cve_analyst",
        system_prompt=CVE_ANALYST_PROMPT,
        user_content=(
            f"Trivy scan results as JSON:\n\n{payload}\n\n"
            "Analyse these and return the JSON object."
        ),
        response_model=CVEAnalysis,
        guard=guard,
    )

    return CVEAnalysisResult(
        status="analysed",
        findings=analysis.findings,
        vulnerabilities_examined=len(prioritised),
    )
