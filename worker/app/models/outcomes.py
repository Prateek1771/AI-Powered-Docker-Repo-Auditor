from typing import Literal

from pydantic import BaseModel

from app.models.findings import (
    BaseImageFinding,
    BloatFinding,
    ComplianceFinding,
    CVEFinding,
    DockerfileResult,
    ScoredRisk,
)
from app.processors.profile import ImageProfile

AgentStatus = Literal[
    "analysed",
    "skipped_no_input",
    "skipped_degraded_input",
    "failed",
    "timed_out",
]

Finding = CVEFinding | BloatFinding | BaseImageFinding | ComplianceFinding


class AgentOutcome(BaseModel):
    agent: str
    status: AgentStatus
    findings: list[Finding] = []
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def is_trustworthy(self) -> bool:
        return self.status in ("analysed", "skipped_no_input")


class ScanOutcome(BaseModel):
    target: str
    outcomes: list[AgentOutcome]
    profile: ImageProfile | None = None
    dockerfile: DockerfileResult | None = None
    risk: ScoredRisk | None = None

    @property
    def all_findings(self) -> list[Finding]:
        return [finding for outcome in self.outcomes for finding in outcome.findings]

    @property
    def degraded(self) -> bool:
        return any(not outcome.is_trustworthy for outcome in self.outcomes)
