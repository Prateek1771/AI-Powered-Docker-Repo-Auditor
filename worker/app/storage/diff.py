"""What changed since the last scan of this repo.

`previous_scan()` has been implemented and tested since persistence landed and
was called by nothing, so a report could never answer the first question
anybody asks of a second scan: is this better or worse than last time?

It could not have worked before either. Findings had no stable identity - the
title, impact and fix are model prose and vary between runs of the same scan -
so two reports could not be joined. `fingerprint` fixed that; this uses it.

See docs/audits/audit-01-backend.md P2-5.
"""

import logging

from pydantic import BaseModel, Field

from app.models.outcomes import ScanOutcome
from app.storage.blobs import get_blob

logger = logging.getLogger(__name__)


class ScanDiff(BaseModel):
    previous_job_id: str
    previous_scan_date: str

    # Fingerprints, not whole findings: the findings themselves are already
    # in this report, and copying them would double the blob.
    new: list[str] = Field(default_factory=list)
    fixed: list[str] = Field(default_factory=list)
    persisting: list[str] = Field(default_factory=list)

    @property
    def regressed(self) -> bool:
        """Whether this scan found something the last one did not."""
        return bool(self.new)


def _fingerprints(findings) -> set[str]:
    return {f.fingerprint for f in findings if getattr(f, "fingerprint", "")}


def _previous_fingerprints(report_key: str) -> set[str] | None:
    """Read the prior report's fingerprints, or None if it is unusable.

    None rather than an empty set, because they are not the same: an empty
    set means the last scan was clean, and would make every current
    finding "new". A missing blob means we cannot say - and the S3
    lifecycle expires bodies while summary rows live on, so a missing blob
    beside a live summary is routine rather than exceptional.
    """
    blob = get_blob(report_key)

    if not blob:
        return None

    prints = {
        finding["fingerprint"]
        for outcome in blob.get("outcomes") or []
        for finding in outcome.get("findings") or []
        if finding.get("fingerprint")
    }

    # A report written before fingerprints existed has none, and treating
    # that as "the last scan found nothing" would mark every finding new.
    return prints or None


def diff_against_previous(
    tenant_id: str,
    repo_id: str,
    job_id: str,
    scan: ScanOutcome,
) -> ScanDiff | None:
    """Classify this scan's findings against the previous one.

    Returns None when there is no comparable predecessor - a first scan,
    or one whose body has aged out. Never raises: a diff is a nice-to-have
    and the scan result is not.
    """
    # Imported here rather than at module scope: results.py imports this
    # module, so a top-level import would be a cycle.
    from app.storage.results import previous_scan

    try:
        previous = previous_scan(tenant_id, repo_id, before_job_id=job_id)

        if previous is None:
            return None

        before = _previous_fingerprints(previous.report_key)

        if before is None:
            return None

        now = _fingerprints(scan.all_findings)

        return ScanDiff(
            previous_job_id=previous.job_id,
            previous_scan_date=previous.scan_date,
            new=sorted(now - before),
            fixed=sorted(before - now),
            persisting=sorted(now & before),
        )
    except Exception:
        logger.warning("Could not diff against the previous scan", exc_info=True)

        return None
