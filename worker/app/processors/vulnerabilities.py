from typing import Literal

from pydantic import BaseModel, Field

from app.config.scanning import DESCRIPTION_TRUNCATE_CHARS, MAX_VULNERABILITIES_TO_MODEL

Severity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "informational",
    "NEGLIGIBLE": "informational",
}


class RawVulnerability(BaseModel):
    id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: Severity
    cvss_score: float = Field(default=0.0)
    description: str
    target: str


def normalise_severity(value: str) -> Severity:
    """Map a Trivy severity string onto our own five-level scale.

    Anything unrecognised becomes informational rather than raising: a new
    severity name from a scanner upgrade must not fail the whole scan.
    """
    return _SEVERITY_MAP.get(
        value.upper(),
        "informational",
    )


def _extract_cvss(entry: dict) -> float:
    """Pull a V3 score out of a Trivy entry, preferring NVD over GHSA.

    Returns 0.0 when neither source scored it, which sorts the entry last
    within its severity band rather than dropping it.
    """
    cvss = entry.get("CVSS") or {}

    nvd_score = cvss.get("nvd", {}).get("V3Score")

    if nvd_score is not None:
        return float(nvd_score)

    ghsa_score = cvss.get("ghsa", {}).get("V3Score")

    if ghsa_score is not None:
        return float(ghsa_score)

    return 0.0


def extract_vulnerabilities(
    trivy_data: dict,
) -> list[RawVulnerability]:
    """Flatten a Trivy report into a list of vulnerabilities we control.

    This is the deterministic reduction the whole pipeline rests on: a raw
    report is megabytes of nested JSON, and the model only ever sees what
    comes out of here, truncated to DESCRIPTION_TRUNCATE_CHARS.
    """
    vulnerabilities: list[RawVulnerability] = []

    for result in trivy_data.get("Results") or []:
        target = result.get("Target", "")

        for entry in result.get("Vulnerabilities") or []:
            vulnerabilities.append(
                RawVulnerability(
                    id=entry.get("VulnerabilityID", ""),
                    package=entry.get("PkgName", ""),
                    installed_version=entry.get("InstalledVersion", ""),
                    fixed_version=entry.get("FixedVersion", ""),
                    severity=normalise_severity(entry.get("Severity", "UNKNOWN")),
                    cvss_score=_extract_cvss(entry),
                    description=entry.get("Description", "")[
                        :DESCRIPTION_TRUNCATE_CHARS
                    ],
                    target=target,
                )
            )

    return vulnerabilities


def prioritise(
    vulnerabilities: list[RawVulnerability],
    limit: int = MAX_VULNERABILITIES_TO_MODEL,
) -> list[RawVulnerability]:
    """Take the worst `limit` vulnerabilities, severity first then CVSS.

    The id is the final tie-break so the same input always produces the
    same slice - an unstable sort here would make eval runs unrepeatable.
    """
    ordered = sorted(
        vulnerabilities,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -item.cvss_score,
            item.id,
        ),
    )

    return ordered[:limit]
