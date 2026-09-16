"""What the scan actually looked at, as opposed to what the model wrote up.

A report used to say nothing about its own completeness. Only the worst 150
vulnerabilities ever reach a model, and the raw report was discarded straight
after reduction - so a 900-CVE image produced a report on 150 of them, the
other 750 were unrecoverable, and nothing on the page said so.

Worse, `finding_count` and `critical_count` were counted from the findings the
MODEL chose to write up, using the MODEL's severities, and displayed as scan
metrics. This record is the scanner's own tally, which is what those numbers
should have been all along.

See docs/audits/audit-01-backend.md P2-3 and P2-4.
"""

from pydantic import BaseModel, Field


class ScanCoverage(BaseModel):
    # --- what the scanner found, before any reduction -------------------
    total_vulnerabilities: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)

    # --- what survived reduction ----------------------------------------
    dedup_removed: int = 0
    sent_to_model: int = 0

    # The headline honesty number. Anything above zero means the report is a
    # sample, and the UI should say so rather than implying completeness.
    dropped: int = 0

    total_secrets: int = 0

    # --- enrichment -----------------------------------------------------
    #
    # False means the feed was unreachable, so `kev_listed` and `epss_score`
    # on every finding are None. That is NOT "nothing is exploited", and a
    # reader has to be able to tell the two apart.
    kev_available: bool = False
    epss_available: bool = False

    # --- provenance: which bytes were actually scanned ------------------
    image_id: str = ""
    repo_digests: list[str] = Field(default_factory=list)
    scanner_image: str = ""
    trivy_schema_version: int = 0
    scanned_at: str = ""

    @property
    def is_complete(self) -> bool:
        """Whether every vulnerability found was actually analysed."""
        return self.dropped == 0
