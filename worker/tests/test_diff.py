"""Cover the scan-to-scan diff.

`previous_scan()` was implemented, tested, and called by nothing, so a report
could never answer the first question anyone asks of a second scan: is this
better or worse than last time? It could not have worked anyway - findings had
no stable identity until Phase 2 added the fingerprint.

See docs/audits/audit-01-backend.md P2-5.
"""

import uuid

import pytest

from app.models.findings import CVEFinding, fingerprint_findings
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.storage.diff import diff_against_previous
from app.storage.results import previous_scan, store_result

pytestmark = pytest.mark.integration


def _finding(vuln_id: str) -> CVEFinding:
    return CVEFinding(
        vulnerability_id=vuln_id,
        severity="high",
        title=f"finding for {vuln_id}",
        impact="i",
        fix="f",
        effort="trivial",
        exploitability="likely",
        priority=50,
    )


def _scan(*vuln_ids: str) -> ScanOutcome:
    return ScanOutcome(
        target="alpine:3.20",
        outcomes=[
            AgentOutcome(
                agent="cve_analyst",
                status="analysed",
                findings=fingerprint_findings([_finding(v) for v in vuln_ids]),
            )
        ],
    )


def _store(tenant: str, repo: str, *vuln_ids: str) -> str:
    job_id = str(uuid.uuid4())

    store_result(job_id, tenant, repo, _scan(*vuln_ids))

    return job_id


def test_a_first_scan_has_nothing_to_compare_against(tenant: str) -> None:
    job_id = _store(tenant, "repo-diff", "CVE-2024-0001")

    assert diff_against_previous(tenant, "repo-diff", job_id, _scan()) is None


def test_previous_scan_resolves_for_a_real_second_scan(tenant: str) -> None:
    """The Limit=2 bug meant this could return None even with a prior scan."""
    first = _store(tenant, "repo-two", "CVE-2024-0001")
    second = _store(tenant, "repo-two", "CVE-2024-0001")

    found = previous_scan(tenant, "repo-two", before_job_id=second)

    assert found is not None
    assert found.job_id == first


def test_new_fixed_and_persisting_are_classified(tenant: str) -> None:
    _store(tenant, "repo-three", "CVE-2024-0001", "CVE-2024-0002")

    # 0001 persists, 0002 is fixed, 0003 is new.
    current = _scan("CVE-2024-0001", "CVE-2024-0003")

    job_id = str(uuid.uuid4())

    diff = diff_against_previous(tenant, "repo-three", job_id, current)

    assert diff is not None

    prints = {f.vulnerability_id: f.fingerprint for f in current.all_findings}

    assert prints["CVE-2024-0003"] in diff.new
    assert prints["CVE-2024-0001"] in diff.persisting
    assert len(diff.fixed) == 1
    assert diff.regressed is True


def test_a_clean_follow_up_is_not_a_regression(tenant: str) -> None:
    _store(tenant, "repo-four", "CVE-2024-0001")

    diff = diff_against_previous(tenant, "repo-four", str(uuid.uuid4()), _scan())

    assert diff is not None
    assert diff.new == []
    assert len(diff.fixed) == 1
    assert diff.regressed is False


def test_the_diff_is_stored_on_the_report(tenant: str) -> None:
    from app.storage.results import get_full_report

    _store(tenant, "repo-five", "CVE-2024-0001")

    second = _store(tenant, "repo-five", "CVE-2024-0002")

    report = get_full_report(second)

    assert report is not None
    assert report["diff"] is not None
    assert len(report["diff"]["new"]) == 1
    assert len(report["diff"]["fixed"]) == 1


def test_the_summary_row_now_expires(tenant: str) -> None:
    """The S3 lifecycle expired report bodies at 30 days while the Dynamo
    row lived forever, so /report 404'd on scans the UI still listed."""
    from app.storage.results import get_summary

    job_id = _store(tenant, "repo-ttl", "CVE-2024-0001")

    summary = get_summary(job_id)

    assert summary is not None
    assert summary.expires_at > 0
