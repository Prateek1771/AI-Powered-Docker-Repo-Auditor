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

# Stored findings are plain dicts, so their severity arrives as a str that
# has lost the Literal. One str-keyed view of the same table, rather than a
# cast at every call site or - worse - a second ordering.
_SEVERITY_RANK: dict[str, int] = {k: v for k, v in SEVERITY_ORDER.items()}

# Unknown sorts last: a severity we do not recognise must not outrank a
# critical, and must not fail a gate on its own.
UNRANKED = len(SEVERITY_ORDER)


def severity_rank(value: str) -> int:
    """Where a severity sits in SEVERITY_ORDER. Lower is worse."""
    return _SEVERITY_RANK.get(value, UNRANKED)


_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    # UNKNOWN means Trivy has no severity for this CVE, not that the CVE is
    # harmless - an advisory can be real and unscored, and frequently is for
    # the first days after publication. Mapped to `informational` it sorted
    # below `low`, which made it the first thing dropped by the
    # MAX_VULNERABILITIES_TO_MODEL cap: the vulnerabilities nobody has
    # assessed yet were the ones nobody assessed. See docs/audits/audit-01-backend.md P3-10.
    #
    # `low` is the honest floor: it survives the cap on a normal image while
    # not inflating the critical and high counts anyone reports on.
    "UNKNOWN": "low",
    # NEGLIGIBLE is a real assessment, and the assessment is "this does not
    # matter". That one stays where it was.
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

    # Everything below is read from the Trivy entry and was previously
    # discarded here, which is why a stored finding carried a CVE id and four
    # fields of prose and nothing a tool could act on. See docs/audits/audit-01-backend.md P2-1.
    cvss_vector: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    primary_url: str = ""
    layer_digest: str = ""

    def for_prompt(self) -> dict:
        """The subset the model actually needs to triage.

        NOT model_dump(). The enrichment fields above are stapled onto the
        finding after the model replies, so sending them costs tokens and
        buys nothing - five reference URLs and a CVSS vector per entry,
        times the 150-vulnerability budget, pushed one request from 20k to
        44k tokens and straight past the account's per-minute limit.

        Same principle as the rest of this phase: never ask a model for a
        fact the scanner knows. Not showing it those facts is the other
        half of that.
        """
        return self.model_dump(
            include={
                "id",
                "package",
                "installed_version",
                "fixed_version",
                "severity",
                "cvss_score",
                "description",
            }
        )


def normalise_severity(value: str) -> Severity:
    """Map a  severity string onto our own five-level scale.

    Anything unrecognised becomes informational rather than raising: a new
    severity name from a scanner upgrade must not fail the whole scan.
    """
    return _SEVERITY_MAP.get(
        value.upper(),
        "informational",
    )


def _extract_cvss_vector(entry: dict) -> str:
    """Pull the V3 vector string, preferring the same source as the score.

    The vector is what lets a reader see WHY a score is what it is -
    network vs local, whether privileges are needed. `_extract_cvss` was
    already reading this block and taking only the number out of it.
    """
    cvss = entry.get("CVSS") or {}

    for source in ("nvd", "ghsa", "redhat"):
        vector = (cvss.get(source) or {}).get("V3Vector")

        if vector:
            return str(vector)

    return ""


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
                    cvss_vector=_extract_cvss_vector(entry),
                    cwe_ids=list(entry.get("CweIDs") or []),
                    # Capped: some entries carry dozens of vendor advisory
                    # links and the report does not need all of them.
                    references=list(entry.get("References") or [])[:5],
                    primary_url=entry.get("PrimaryURL", ""),
                    layer_digest=(entry.get("Layer") or {}).get("DiffID", ""),
                )
            )

    return vulnerabilities


def deduplicate(
    vulnerabilities: list[RawVulnerability],
) -> list[RawVulnerability]:
    """Collapse the same vulnerability reported against the same package.

    Trivy reports per (Result, entry), so one CVE affecting a package
    vendored into forty jars arrives forty times. Undeduplicated, that CVE
    consumed forty of the 150 slots the model ever sees - forty copies of
    one issue crowding out thirty-nine others.

    Keyed on (id, package, installed_version) rather than id alone: the
    same CVE against two different installed versions really is two things
    to fix.
    """
    seen: dict[tuple[str, str, str], RawVulnerability] = {}

    for item in vulnerabilities:
        seen.setdefault((item.id, item.package, item.installed_version), item)

    return list(seen.values())


def prioritise(
    vulnerabilities: list[RawVulnerability],
    limit: int = MAX_VULNERABILITIES_TO_MODEL,
) -> list[RawVulnerability]:
    """Take the worst `limit` vulnerabilities, worst and fixable first.

    Severity leads, then whether a fix EXISTS, then CVSS. Without the
    fixable term, a wall of unfixable criticals fills the budget and
    crowds out the actionable highs underneath them - the reader is shown
    the scariest list rather than the most useful one.

    The id is the final tie-break so the same input always produces the
    same slice - an unstable sort here would make eval runs unrepeatable.
    """
    ordered = sorted(
        vulnerabilities,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            # False sorts before True, so "has a fix" comes first.
            not bool(item.fixed_version),
            -item.cvss_score,
            item.id,
        ),
    )

    return ordered[:limit]


def counts_by_severity(
    vulnerabilities: list[RawVulnerability],
) -> dict[str, int]:
    """Count every vulnerability by severity, including the zeros.

    The scanner's own tally, which is what the report should quote.
    finding_count and critical_count were computed from whatever the model
    chose to write up, using the model's severities - displayed as scan
    metrics while being nothing of the kind. See docs/audits/audit-01-backend.md P2-4.
    """
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)

    for item in vulnerabilities:
        counts[item.severity] += 1

    return counts
