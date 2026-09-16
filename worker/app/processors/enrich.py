"""Attach measured exploitability to the findings a model wrote up.

Runs after the CVE agent, never before: the model is asked about the
vulnerabilities, and then the facts are stapled on. Asking a model to report a
KEV listing or an EPSS score would just be inviting it to guess at something
already known.

See docs/AUDIT.md P2-1, P2-3.
"""

import logging

from app.config.enrichment import ENRICHMENT_ENABLED
from app.enrichment.epss import load_epss_scores
from app.enrichment.kev import load_kev_ids
from app.models.findings import CVEFinding
from app.processors.vulnerabilities import RawVulnerability

logger = logging.getLogger(__name__)


class Enrichment:
    """The feeds, fetched once per scan.

    `kev`/`epss` are None when the feed could not be reached, which the
    coverage record surfaces. None is not an empty answer: "we could not
    check" and "nothing is exploited" must never render the same.
    """

    def __init__(self, kev: set[str] | None, epss: dict[str, float] | None) -> None:
        self.kev = kev
        self.epss = epss

    @property
    def kev_available(self) -> bool:
        return self.kev is not None

    @property
    def epss_available(self) -> bool:
        return self.epss is not None


def fetch_enrichment(cve_ids: list[str]) -> Enrichment:
    """Load both feeds. Never raises - a scan is worth more than a score."""
    if not ENRICHMENT_ENABLED:
        logger.info("Enrichment disabled by configuration")

        return Enrichment(kev=None, epss=None)

    return Enrichment(kev=load_kev_ids(), epss=load_epss_scores(cve_ids))


def enrich_cve_findings(
    findings: list[CVEFinding],
    scanner: dict[str, RawVulnerability],
    enrichment: Enrichment | None = None,
) -> list[CVEFinding]:
    """Copy the scanner's facts, and the feeds', onto each finding.

    Everything here is overwritten unconditionally from the scanner entry.
    If a model volunteered a package name or a CVSS score, it is replaced -
    the scanner is the authority and a second opinion on a measured value
    is only a chance to be wrong.
    """
    enriched = []

    for finding in findings:
        truth = scanner.get(finding.vulnerability_id)

        update: dict = {}

        if truth is not None:
            update.update(
                package=truth.package,
                installed_version=truth.installed_version,
                fixed_version=truth.fixed_version,
                cvss_score=truth.cvss_score,
                cvss_vector=truth.cvss_vector,
                cwe_ids=truth.cwe_ids,
                references=truth.references,
                primary_url=truth.primary_url,
                layer_digest=truth.layer_digest,
                scanner_severity=truth.severity,
            )

        if enrichment is not None:
            if enrichment.kev is not None:
                update["kev_listed"] = finding.vulnerability_id in enrichment.kev

            if enrichment.epss is not None:
                update["epss_score"] = enrichment.epss.get(finding.vulnerability_id)

        enriched.append(finding.model_copy(update=update) if update else finding)

    return enriched
