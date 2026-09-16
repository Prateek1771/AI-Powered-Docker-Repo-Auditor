import json
import logging
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import CVE_ANALYST_PROMPT
from app.agents.runner import AgentError, run_structured_agent, untrusted_block
from app.models.findings import CVEAnalysis, CVEFinding
from app.processors.vulnerabilities import (
    SEVERITY_ORDER,
    RawVulnerability,
    prioritise,
)

logger = logging.getLogger(__name__)


class CVEAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[CVEFinding]
    vulnerabilities_examined: int


def reconcile_severities(
    findings: list[CVEFinding],
    scanner: dict[str, RawVulnerability],
) -> list[CVEFinding]:
    """Stop the model reporting a CVE as less severe than the scanner did.

    The hallucination guard checks that a vulnerability_id was in the
    input. It says nothing about the severity attached to it, so a model
    could take a CRITICAL the scanner found and write it up as `low` -
    and nothing noticed, even though RawVulnerability.severity holds the
    scanner's answer for that exact CVE, in memory, at that moment.

    Raising the severity is allowed and left alone: the model sees
    context the scanner does not, and escalation is the direction that
    cannot hide a problem. Lowering it is overwritten and logged.

    See docs/audits/audit-01-backend.md P1-3.
    """
    reconciled = []

    for finding in findings:
        truth = scanner.get(finding.vulnerability_id)

        if truth is None:
            reconciled.append(finding)
            continue

        # Lower rank is worse: critical is 0, informational is 4.
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[truth.severity]:
            logger.warning(
                "cve_analyst: %s reported as %s, scanner says %s - using the scanner",
                finding.vulnerability_id,
                finding.severity,
                truth.severity,
            )

            finding = finding.model_copy(update={"severity": truth.severity})

        reconciled.append(finding)

    return reconciled


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

    by_id = {item.id: item for item in prioritised}

    def guard(analysis: CVEAnalysis) -> None:
        """Refuse any id the scanner did not report.

        The whole response is rejected rather than filtered: a plausible
        CVE id the scanner never saw would send someone chasing a
        vulnerability that is not in their image.
        """
        unknown = {f.vulnerability_id for f in analysis.findings} - set(by_id)

        if unknown:
            raise AgentError(
                f"cve_analyst: invented vulnerability IDs {sorted(unknown)[:5]}"
            )

    # for_prompt(), not model_dump(): the enrichment fields are added after
    # the model replies, so sending them is pure token cost.
    payload = json.dumps(
        [v.for_prompt() for v in prioritised],
        indent=2,
    )

    analysis = await run_structured_agent(
        agent_name="cve_analyst",
        system_prompt=CVE_ANALYST_PROMPT,
        user_content=(
            f"Trivy scan results:\n\n{untrusted_block(payload)}\n\n"
            "Analyse these and return the JSON object."
        ),
        response_model=CVEAnalysis,
        guard=guard,
        # Handed this many real vulnerabilities, "nothing worth reporting"
        # is not a credible answer - it is what a suppressed agent returns.
        expect_findings_above=5,
        input_size=len(prioritised),
    )

    return CVEAnalysisResult(
        status="analysed",
        findings=reconcile_severities(analysis.findings, by_id),
        vulnerabilities_examined=len(prioritised),
    )
