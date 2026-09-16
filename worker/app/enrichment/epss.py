"""EPSS scores from FIRST: the probability a CVE is exploited in 30 days.

CVSS says how bad a vulnerability would be if exploited. It says nothing about
whether anyone is going to. EPSS is the missing half, and on a list of 150
findings it is the difference between "sorted by theoretical severity" and
"sorted by what will actually happen to you".

See docs/AUDIT.md P2-3.
"""

import logging

import httpx

from app.config.enrichment import (
    ENRICHMENT_TIMEOUT_SECONDS,
    EPSS_API_URL,
    EPSS_BATCH_SIZE,
)

logger = logging.getLogger(__name__)


def _batch(ids: list[str], size: int):
    for start in range(0, len(ids), size):
        yield ids[start : start + size]


def load_epss_scores(cve_ids: list[str]) -> dict[str, float] | None:
    """Return EPSS scores for the ids that have one.

    None means the API could not be reached at all. A CVE simply absent
    from the response has no published score, which is ordinary - EPSS
    covers CVEs, not GHSA or vendor advisories, and Trivy emits all three.

    Batched because the API takes a comma-separated list, and one request
    per CVE for a 150-finding scan would be 150 round trips.
    """
    wanted = [i for i in cve_ids if i.upper().startswith("CVE-")]

    if not wanted:
        return {}

    scores: dict[str, float] = {}

    try:
        with httpx.Client(timeout=ENRICHMENT_TIMEOUT_SECONDS) as client:
            for chunk in _batch(wanted, EPSS_BATCH_SIZE):
                response = client.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(chunk)},
                )
                response.raise_for_status()

                for row in response.json().get("data") or []:
                    cve = row.get("cve")
                    epss = row.get("epss")

                    if cve and epss is not None:
                        scores[cve] = float(epss)
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail a scan
        logger.warning("EPSS unavailable: %s", exc)

        # Partial results are worse than none here: a half-filled map looks
        # identical to "these CVEs have no score", and the caller would
        # record enrichment as available when it was not.
        return None

    logger.info("EPSS scores loaded for %d of %d CVEs", len(scores), len(wanted))

    return scores
