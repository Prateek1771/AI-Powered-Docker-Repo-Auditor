from typing import Literal

from pydantic import BaseModel

from app.models.findings import BloatFinding, CVEFinding

AgentStatus = Literal[
    "analysed",
    "skipped_no_input",
    "failed",
    "timed_out",
]


class AgentOutcome(BaseModel):
    agent: str
    status: AgentStatus
    findings: list[CVEFinding | BloatFinding] = []
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def is_trustworthy(self) -> bool:
        return self.status in ("analysed", "skipped_no_input")


class ScanOutcome(BaseModel):
    target: str
    outcomes: list[AgentOutcome]

    @property
    def all_findings(self) -> list[CVEFinding | BloatFinding]:
        return [finding for outcome in self.outcomes for finding in outcome.findings]

    @property
    def degraded(self) -> bool:
        return any(not outcome.is_trustworthy for outcome in self.outcomes)
