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


class BaseImageFinding(BaseFinding):
    category: Literal["base_image"] = "base_image"
    recommended_base: str = Field(min_length=1)
    estimated_savings_bytes: int = Field(ge=0)
    breaking_risk: str = Field(min_length=1)


class ComplianceFinding(BaseFinding):
    category: Literal["compliance"] = "compliance"
    control_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)


class BaseImageAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_base: str
    findings: list[BaseImageFinding]


class ComplianceAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[ComplianceFinding]


class DockerfileChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    instruction: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    addresses: list[str] = []


class DockerfileOptimization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reconstructed: str
    optimized: str
    reconstruction_notes: str
    changes: list[DockerfileChange]


class DockerfileResult(BaseModel):
    status: Literal["analysed", "skipped_degraded_input"]
    optimization: DockerfileOptimization | None = None
    skipped_because: list[str] = []


class RiskScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overall: int = Field(ge=0, le=100)
    security: int = Field(ge=0, le=100)
    efficiency: int = Field(ge=0, le=100)
    compliance: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1)
    top_priorities: list[str]


class ScoredRisk(BaseModel):
    score: RiskScore
    confidence: float = Field(ge=0.0, le=1.0)
    inputs_used: list[str]
    inputs_missing: list[str]
