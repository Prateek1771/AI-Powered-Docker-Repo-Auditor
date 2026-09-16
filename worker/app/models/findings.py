import hashlib
from collections.abc import Sequence
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

    # Stable identity for this finding across scans of the same repo.
    #
    # Optional and defaulted because this model is ALSO the schema the model
    # answers in, and extra="forbid" means a required field here becomes a
    # required key the model must emit. Everything below is computed after the
    # model replies - see fingerprint_findings() - and never asked for.
    #
    # Without it a diff is impossible: the prose varies run to run, so there
    # was nothing to join two scans on. See docs/audits/audit-01-backend.md P2-5.
    fingerprint: str = ""


class CVEFinding(BaseFinding):
    category: Literal["cve"] = "cve"
    vulnerability_id: str = Field(min_length=1)

    # The model's judgement, and labelled as such. `kev_listed` and
    # `epss_score` below are the measured versions of the same question.
    exploitability: Exploitability

    # Copied from the scanner entry after the model replies, never requested.
    # The scanner knows these; asking a model to repeat them invents a chance
    # to get them wrong. See docs/audits/audit-01-backend.md P2-1.
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    primary_url: str = ""
    layer_digest: str = ""

    # What the scanner said, kept beside what the model said. They differ only
    # when the model tried to lower it, which reconcile_severities overrides -
    # keeping both makes the disagreement visible rather than silent.
    scanner_severity: Severity | None = None

    # Measured exploitability. `kev_listed` is CISA's known-exploited catalog:
    # a plain fact, not a prediction. `epss_score` is FIRST's probability of
    # exploitation in the next 30 days. None means enrichment was unavailable,
    # which is NOT the same as "not exploited" - see models/coverage.py.
    kev_listed: bool | None = None
    epss_score: float | None = None


class SecretFinding(BaseFinding):
    """A credential Trivy found baked into a layer.

    Produced deterministically from the scan; no model is involved, so it
    cannot be argued away by content in the image.
    """

    category: Literal["secret"] = "secret"
    rule_id: str = ""
    category_name: str = ""
    file_path: str = ""
    line: int = 0
    # Never the secret itself - see processors/secrets.py _redact.
    redacted_match: str = ""


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


class RiskNarrative(BaseModel):
    """The only part of the score a model is asked for any more.

    Prose and prioritisation genuinely need language. The numbers do not,
    and asking for them produced a figure nobody could reproduce or
    explain. See processors/scoring.py.
    """

    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1)
    top_priorities: list[str]


class RiskScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # None where the evidence never arrived, rather than a number computed
    # from an agent that failed. See docs/audits/audit-01-backend.md P2-6.
    overall: int | None = Field(default=None, ge=0, le=100)
    security: int | None = Field(default=None, ge=0, le=100)
    efficiency: int | None = Field(default=None, ge=0, le=100)
    compliance: int | None = Field(default=None, ge=0, le=100)
    summary: str = ""
    top_priorities: list[str] = Field(default_factory=list)


class ScoredRisk(BaseModel):
    score: RiskScore
    confidence: float = Field(ge=0.0, le=1.0)
    inputs_used: list[str]
    inputs_missing: list[str]


def fingerprint_of(finding: BaseFinding) -> str:
    """Return a stable identity for a finding, across scans and wording.

    Built only from facts: the category, the identifier, the package and
    the layer. Deliberately NOT from title/impact/fix - those are written
    by a model and vary between runs of the same scan, which is exactly
    why two scans of one image could not be joined before.

    Truncated to 16 bytes of hex. This is a join key, not a security
    primitive; collisions cost a mislabelled diff entry.
    """
    parts = [
        # getattr: `category` lives on the subclasses, not BaseFinding.
        getattr(finding, "category", ""),
        getattr(finding, "vulnerability_id", ""),
        getattr(finding, "control_id", ""),
        getattr(finding, "rule_id", ""),
        getattr(finding, "package", ""),
        str(getattr(finding, "layer_index", "")),
        getattr(finding, "file_path", ""),
    ]

    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def fingerprint_findings[T: BaseFinding](findings: Sequence[T]) -> list[T]:
    """Stamp every finding with its fingerprint."""
    return [
        finding.model_copy(update={"fingerprint": fingerprint_of(finding)})
        for finding in findings
    ]
