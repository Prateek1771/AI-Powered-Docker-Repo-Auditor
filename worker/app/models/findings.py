from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.processors.vulnerabilities import Severity

Effort = Literal[
    "trivial",
    "moderate",
    "involved",
]

Exploitability = Literal[
    "actively_exploited",
    "likely",
    "unlikely",
    "theoretical",
]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1, max_length=140)
    impact: str = Field(min_length=1)
    fix: str = Field(min_length=1)
    effort: Effort
    exploitability: Exploitability
    priority: int = Field(ge=1, le=100)


class CVEAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]
