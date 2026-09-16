"""CISA's Known Exploited Vulnerabilities catalog.

`CVEFinding.exploitability` was a four-value enum the MODEL chose, on a
question it cannot actually answer - whether a vulnerability is being exploited
in the wild is a fact about the world, not something inferable from a package
name and a CVE id.

CISA publishes the answer as one JSON file. A CVE is on the list or it is not.
See docs/audits/audit-01-backend.md P2-3.
"""

import json
import logging
import time
from pathlib import Path

import httpx

from app.config.enrichment import (
    ENRICHMENT_CACHE_DIR,
    ENRICHMENT_TIMEOUT_SECONDS,
    KEV_CATALOG_URL,
    KEV_REFRESH_SECONDS,
)

logger = logging.getLogger(__name__)


def _cache_path() -> Path:
    return Path(ENRICHMENT_CACHE_DIR) / "kev.json"


def _fresh(path: Path) -> bool:
    """Whether the cached catalog is young enough to use.

    CISA adds to the catalog a few times a week, so a day-old copy is not
    meaningfully wrong and re-downloading a megabyte per scan would be.
    """
    if not path.exists():
        return False

    return (time.time() - path.stat().st_mtime) < KEV_REFRESH_SECONDS


def _download() -> list[str]:
    with httpx.Client(timeout=ENRICHMENT_TIMEOUT_SECONDS) as client:
        response = client.get(KEV_CATALOG_URL)
        response.raise_for_status()

        payload = response.json()

    return [
        entry["cveID"]
        for entry in payload.get("vulnerabilities") or []
        if entry.get("cveID")
    ]


def load_kev_ids() -> set[str] | None:
    """Return every CVE id CISA lists as known-exploited.

    None means the catalog could not be obtained. That is deliberately
    distinct from an empty set: "we do not know" must never be recorded as
    "nothing here is exploited", which is the failure mode that would make
    this enrichment worse than not having it.

    A stale cache is preferred over no answer - an old catalog is a subset
    of the current one, so it can only under-report, never invent.
    """
    path = _cache_path()

    if _fresh(path):
        try:
            return set(json.loads(path.read_text()))
        except (OSError, ValueError):
            logger.warning("KEV cache unreadable, refetching")

    try:
        ids = _download()
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail a scan
        logger.warning("KEV catalog unavailable: %s", exc)

        if path.exists():
            try:
                logger.info("Falling back to the stale KEV cache")

                return set(json.loads(path.read_text()))
            except (OSError, ValueError):
                pass

        return None

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(ids))
    except OSError as exc:
        logger.warning("Could not cache the KEV catalog: %s", exc)

    logger.info("KEV catalog loaded: %d known-exploited CVEs", len(ids))

    return set(ids)
