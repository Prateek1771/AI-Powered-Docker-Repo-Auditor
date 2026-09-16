"""Suppression: marks, never deletes; expires; and never fails a scan."""

from datetime import UTC, datetime, timedelta

import pytest

from app.policy.apply import apply_policy, unsuppressed_findings
from app.policy.store import Policy, Suppression, load_policy, save_policy


def _report() -> dict:
    return {
        "target": "nginx:latest",
        "outcomes": [
            {
                "agent": "cve_analyst",
                "status": "analysed",
                "findings": [
                    {
                        "category": "cve",
                        "severity": "critical",
                        "title": "A",
                        "fingerprint": "fp-a",
                        "vulnerability_id": "CVE-1",
                        "package": "openssl",
                    },
                    {
                        "category": "cve",
                        "severity": "high",
                        "title": "B",
                        "fingerprint": "fp-b",
                        "vulnerability_id": "CVE-2",
                        "package": "zlib",
                    },
                ],
            }
        ],
    }


def test_suppression_marks_rather_than_deletes():
    policy = Policy(
        suppressions=[Suppression(fingerprint="fp-a", reason="Accepted for now")]
    )

    applied = apply_policy(_report(), policy)

    findings = applied["outcomes"][0]["findings"]

    # Still two findings. The report and the scanner do not disagree about
    # what is in the image - that is the entire design.
    assert len(findings) == 2

    assert findings[0]["suppressed"] is True
    assert findings[0]["suppressed_reason"] == "Accepted for now"

    # But the gate only counts one.
    assert [f["title"] for f in unsuppressed_findings(applied)] == ["B"]


def test_apply_policy_does_not_mutate_the_stored_report():
    report = _report()

    apply_policy(report, Policy(suppressions=[Suppression(package="zlib", reason="x")]))

    assert "suppressed" not in report["outcomes"][0]["findings"][1]


def test_targets_match_at_three_granularities():
    for suppression, expected in (
        (Suppression(fingerprint="fp-a", reason="r"), ["B"]),
        (Suppression(vulnerability_id="CVE-2", reason="r"), ["A"]),
        (Suppression(package="openssl", reason="r"), ["B"]),
    ):
        applied = apply_policy(_report(), Policy(suppressions=[suppression]))

        assert [f["title"] for f in unsuppressed_findings(applied)] == expected


def test_expired_suppression_stops_applying():
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()

    expired = Policy(
        suppressions=[Suppression(fingerprint="fp-a", reason="r", expires_at=past)]
    )
    live = Policy(
        suppressions=[Suppression(fingerprint="fp-a", reason="r", expires_at=future)]
    )

    assert len(unsuppressed_findings(apply_policy(_report(), expired))) == 2
    assert len(unsuppressed_findings(apply_policy(_report(), live))) == 1


def test_unparseable_expiry_expires():
    """A typo must bring the finding back, not hide it forever."""
    assert Suppression(fingerprint="x", reason="r", expires_at="soon").is_expired()


def test_reason_is_required():
    with pytest.raises(ValueError):
        Suppression(fingerprint="fp-a", reason="")


def test_policy_round_trips_through_blob_storage(tmp_path, monkeypatch):
    from app.storage import blobs

    monkeypatch.setattr(blobs, "BLOB_DIR", str(tmp_path))
    monkeypatch.setattr(blobs, "REPORTS_BUCKET", "")

    save_policy(
        "tenant-a",
        Policy(suppressions=[Suppression(vulnerability_id="CVE-1", reason="r")]),
    )

    assert load_policy("tenant-a").suppressions[0].vulnerability_id == "CVE-1"

    # A tenant id guessed from elsewhere resolves to a key that is not there.
    assert load_policy("tenant-b").suppressions == []


def test_missing_policy_never_raises(monkeypatch):
    from app.policy import store

    def boom(_key):
        raise RuntimeError("storage down")

    monkeypatch.setattr(store, "get_blob", boom)

    # Failing open is the right direction: report a finding they had
    # accepted, rather than report nothing.
    assert load_policy("tenant-a").suppressions == []
