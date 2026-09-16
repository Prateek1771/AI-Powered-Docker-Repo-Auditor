"""Cover Phase 2: the data the report used to compute and then discard.

Every test here fails against the code as it was. See docs/AUDIT.md §4.
"""

import pytest

from app.models.coverage import ScanCoverage
from app.models.findings import (
    CVEFinding,
    fingerprint_findings,
    fingerprint_of,
)
from app.models.outcomes import AgentOutcome
from app.processors.enrich import Enrichment, enrich_cve_findings
from app.processors.scoring import axis_scores, overall_score
from app.processors.secrets import _redact, extract_secrets
from app.processors.vulnerabilities import (
    RawVulnerability,
    counts_by_severity,
    deduplicate,
    extract_vulnerabilities,
    prioritise,
)


def _raw(
    vuln_id="CVE-2024-0001", severity="critical", fixed="1.2.3", package="openssl"
):
    return RawVulnerability(
        id=vuln_id,
        package=package,
        installed_version="1.0.0",
        fixed_version=fixed,
        severity=severity,
        cvss_score=9.8,
        description="",
        target="alpine",
        cvss_vector="CVSS:3.1/AV:N/AC:L",
        cwe_ids=["CWE-787"],
        references=["https://example.test/advisory"],
        primary_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        layer_digest="sha256:abc",
    )


def _finding(vuln_id="CVE-2024-0001", severity="critical"):
    return CVEFinding(
        vulnerability_id=vuln_id,
        severity=severity,
        title="t",
        impact="i",
        fix="f",
        effort="trivial",
        exploitability="likely",
        priority=90,
    )


# ------------------------------------------------- the Trivy fields we dropped


def test_the_trivy_entry_is_read_in_full() -> None:
    report = {
        "Results": [
            {
                "Target": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.2.3",
                        "Severity": "CRITICAL",
                        "PrimaryURL": "https://nvd.example/CVE-2024-0001",
                        "CweIDs": ["CWE-787"],
                        "References": ["https://a.test", "https://b.test"],
                        "Layer": {"DiffID": "sha256:deadbeef"},
                        "CVSS": {
                            "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N"},
                        },
                    }
                ],
            }
        ]
    }

    [vuln] = extract_vulnerabilities(report)

    assert vuln.cvss_score == 9.8
    assert vuln.cvss_vector == "CVSS:3.1/AV:N"
    assert vuln.cwe_ids == ["CWE-787"]
    assert vuln.references == ["https://a.test", "https://b.test"]
    assert vuln.primary_url == "https://nvd.example/CVE-2024-0001"
    assert vuln.layer_digest == "sha256:deadbeef"


def test_scanner_facts_are_copied_onto_the_finding() -> None:
    [enriched] = enrich_cve_findings([_finding()], {"CVE-2024-0001": _raw()})

    assert enriched.package == "openssl"
    assert enriched.installed_version == "1.0.0"
    assert enriched.fixed_version == "1.2.3"
    assert enriched.cvss_score == 9.8
    assert enriched.cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert enriched.cwe_ids == ["CWE-787"]
    assert enriched.scanner_severity == "critical"


def test_a_finding_the_scanner_does_not_know_is_left_alone() -> None:
    [out] = enrich_cve_findings([_finding("CVE-9999-0000")], {})

    assert out.package == ""


# -------------------------------------------------------------- deduplication


def test_the_same_cve_in_many_jars_collapses() -> None:
    """One CVE vendored into forty jars used to eat forty of the 150 slots."""
    vulns = [_raw(package="log4j") for _ in range(40)]

    assert len(deduplicate(vulns)) == 1


def test_the_same_cve_at_different_versions_is_kept_apart() -> None:
    a = _raw(package="openssl")
    b = _raw(package="openssl").model_copy(update={"installed_version": "2.0.0"})

    assert len(deduplicate([a, b])) == 2


# ---------------------------------------------------------- prioritisation


def test_fixable_outranks_unfixable_at_the_same_severity() -> None:
    """A wall of unfixable criticals used to crowd out actionable ones."""
    unfixable = _raw("CVE-2024-0001", fixed="")
    fixable = _raw("CVE-2024-0002", fixed="9.9.9")

    ordered = prioritise([unfixable, fixable], limit=2)

    assert ordered[0].id == "CVE-2024-0002"


def test_severity_still_leads() -> None:
    low_fixable = _raw("CVE-2024-0003", severity="low", fixed="1.0")
    critical_unfixable = _raw("CVE-2024-0004", severity="critical", fixed="")

    ordered = prioritise([low_fixable, critical_unfixable], limit=2)

    assert ordered[0].id == "CVE-2024-0004"


def test_counts_include_the_zeros() -> None:
    counts = counts_by_severity([_raw(severity="critical")])

    assert counts["critical"] == 1
    assert counts["low"] == 0
    assert set(counts) == {"critical", "high", "medium", "low", "informational"}


# ----------------------------------------------------------------- secrets


def test_trivy_secret_results_are_read() -> None:
    """They were fetched on every scan and dropped on the floor."""
    report = {
        "Results": [
            {
                "Target": "app/settings.py",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "StartLine": 12,
                        "Match": "AWS_KEY = AKIAIOSFODNN7EXAMPLE",
                    }
                ],
            }
        ]
    }

    [finding] = extract_secrets(report)

    assert finding.category == "secret"
    assert finding.severity == "critical"
    assert finding.rule_id == "aws-access-key-id"
    assert finding.line == 12
    assert finding.file_path == "app/settings.py"


def test_the_secret_itself_is_never_stored() -> None:
    """The matched line CONTAINS a live credential. A vulnerability report
    is exactly the document an attacker would like a copy of."""
    secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"

    redacted = _redact(secret)

    assert "wJalrXUtnFEMI" not in redacted
    assert "EXAMPLEKEY" not in redacted
    assert "redacted" in redacted


def test_a_report_with_no_secrets_yields_none() -> None:
    assert extract_secrets({"Results": [{"Target": "x"}]}) == []


# ------------------------------------------------------------- enrichment


def test_kev_marks_a_listed_cve() -> None:
    enrichment = Enrichment(kev={"CVE-2024-0001"}, epss={"CVE-2024-0001": 0.97})

    [out] = enrich_cve_findings([_finding()], {"CVE-2024-0001": _raw()}, enrichment)

    assert out.kev_listed is True
    assert out.epss_score == pytest.approx(0.97)


def test_an_unlisted_cve_is_marked_false_not_unknown() -> None:
    enrichment = Enrichment(kev=set(), epss={})

    [out] = enrich_cve_findings([_finding()], {"CVE-2024-0001": _raw()}, enrichment)

    assert out.kev_listed is False


def test_unavailable_enrichment_stays_none_not_false() -> None:
    """'We could not check' and 'not exploited' must never render alike."""
    enrichment = Enrichment(kev=None, epss=None)

    [out] = enrich_cve_findings([_finding()], {"CVE-2024-0001": _raw()}, enrichment)

    assert out.kev_listed is None
    assert out.epss_score is None
    assert enrichment.kev_available is False


# ---------------------------------------------------------------- scoring


def _outcome(agent, findings, status="analysed"):
    return AgentOutcome(agent=agent, status=status, findings=findings)


def test_the_score_is_reproducible() -> None:
    """Two runs over the same findings must agree. The model's version did
    not, which made the eval gate measure a moving target."""
    outcomes = [_outcome("cve_analyst", [_finding()])]

    assert axis_scores(outcomes) == axis_scores(outcomes)


def test_criticals_drive_the_security_score_down() -> None:
    clean = axis_scores([_outcome("cve_analyst", [])])
    bad = axis_scores([_outcome("cve_analyst", [_finding() for _ in range(3)])])

    assert clean["security"] == 100
    assert bad["security"] is not None
    assert bad["security"] < clean["security"]


def test_a_failed_agent_scores_none_not_a_number() -> None:
    """The model would happily return compliance: 85 on zero evidence."""
    scores = axis_scores([_outcome("compliance_checker", [], status="failed")])

    assert scores["compliance"] is None


def test_overall_is_clamped_to_the_worst_axis() -> None:
    scores = {"security": 10, "efficiency": 100, "compliance": 100}

    assert overall_score(scores) <= 10


def test_overall_is_none_when_nothing_scored() -> None:
    assert overall_score({"security": None, "efficiency": None}) is None


# ------------------------------------------------------------ fingerprints


def test_the_fingerprint_ignores_model_prose() -> None:
    """The whole point: two scans word findings differently, and a diff
    joined on wording would call every finding new."""
    a = _finding()
    b = a.model_copy(update={"title": "completely different wording"})

    assert fingerprint_of(a) == fingerprint_of(b)


def test_a_different_cve_fingerprints_differently() -> None:
    assert fingerprint_of(_finding("CVE-2024-0001")) != fingerprint_of(
        _finding("CVE-2024-0002")
    )


def test_the_package_is_part_of_the_identity() -> None:
    a = _finding().model_copy(update={"package": "openssl"})
    b = _finding().model_copy(update={"package": "zlib"})

    assert fingerprint_of(a) != fingerprint_of(b)


def test_fingerprints_are_stamped_on() -> None:
    [stamped] = fingerprint_findings([_finding()])

    assert stamped.fingerprint
    assert stamped.fingerprint == fingerprint_of(stamped)


# ---------------------------------------------------------------- coverage


def test_coverage_knows_when_a_report_is_a_sample() -> None:
    assert ScanCoverage(total_vulnerabilities=900, dropped=750).is_complete is False
    assert ScanCoverage(total_vulnerabilities=12, dropped=0).is_complete is True


# ------------------------------------------------------------ prompt payload


def test_the_prompt_payload_excludes_the_enrichment_fields() -> None:
    """Sending them cost tokens and bought nothing - they are stapled on
    after the model replies. 150 entries' worth pushed one request from
    20k to 44k tokens and past the account's per-minute limit."""
    payload = _raw().for_prompt()

    assert set(payload) == {
        "id",
        "package",
        "installed_version",
        "fixed_version",
        "severity",
        "cvss_score",
        "description",
    }


def test_the_prompt_payload_keeps_what_triage_needs() -> None:
    payload = _raw().for_prompt()

    assert payload["id"] == "CVE-2024-0001"
    assert payload["fixed_version"] == "1.2.3"
    assert payload["severity"] == "critical"
