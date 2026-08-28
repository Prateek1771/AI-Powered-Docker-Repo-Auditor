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


class BaseFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    title: str = Field(min_length=1, max_length=140)
    impact: str = Field(min_length=1)
    fix: str = Field(min_length=1)
    effort: Effort
    priority: int = Field(ge=1, le=100)


class CVEFinding(BaseFinding):
    category: Literal["cve"] = "cve"
    vulnerability_id: str = Field(min_length=1)
    exploitability: Exploitability


class BloatFinding(BaseFinding):
    category: Literal["bloat"] = "bloat"
    layer_index: int = Field(ge=0)
    wasted_bytes: int = Field(ge=0)
    root_cause_command: str = Field(min_length=1)


class CVEAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[CVEFinding]


class BloatAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[BloatFinding]
