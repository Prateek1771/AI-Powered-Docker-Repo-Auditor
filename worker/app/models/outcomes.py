from typing import Literal

from pydantic import BaseModel

from app.models.coverage import ScanCoverage
from app.models.findings import (
    BaseImageFinding,
    BloatFinding,
    ComplianceFinding,
    CVEFinding,
    DockerfileResult,
    ScoredRisk,
    SecretFinding,
)
from app.processors.packages import Package
from app.processors.profile import ImageProfile

AgentStatus = Literal[
    "analysed",
    "skipped_no_input",
    # New, and the distinction is the point. `skipped_no_input` means the
    # agent looked and there was genuinely nothing - zero vulnerabilities is
    # a real, trustworthy answer. `skipped_missing_input` means the evidence
    # never arrived: a squashed image whose history could not be read has not
    # been shown to be lean, it has not been examined at all.
    #
    # Both used to be `skipped_no_input`, so an unreadable image scored as
    # confidently clean. See docs/AUDIT.md P1-2.
    "skipped_missing_input",
    "skipped_degraded_input",
    "failed",
    "timed_out",
]

Finding = (
    CVEFinding | BloatFinding | BaseImageFinding | ComplianceFinding | SecretFinding
)


class AgentOutcome(BaseModel):
    agent: str
    status: AgentStatus
    findings: list[Finding] = []
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def is_trustworthy(self) -> bool:
        """Whether this outcome is evidence, rather than an absence of it.

        skipped_missing_input is deliberately NOT here: an agent that
        never saw its input has found nothing in the same sense that a
        closed eye has seen nothing.
        """
        return self.status in ("analysed", "skipped_no_input")


class ScanOutcome(BaseModel):
    target: str
    outcomes: list[AgentOutcome]
    profile: ImageProfile | None = None
    dockerfile: DockerfileResult | None = None
    risk: ScoredRisk | None = None

    # What the scanner actually saw, beside what the model wrote up. The
    # report used to carry only the latter and imply it was the former.
    coverage: ScanCoverage | None = None

    # The full bill of materials, not just the vulnerable part of it. Trivy
    # reported it on every scan and nothing read it.
    packages: list[Package] = []

    @property
    def all_findings(self) -> list[Finding]:
        return [finding for outcome in self.outcomes for finding in outcome.findings]

    @property
    def degraded(self) -> bool:
        return any(not outcome.is_trustworthy for outcome in self.outcomes)
