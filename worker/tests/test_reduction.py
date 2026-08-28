from app.processors.vulnerabilities import (
    extract_vulnerabilities,
    normalise_severity,
    prioritise,
)


def _vulnerability(
    vuln_id: str,
    severity: str,
    score: float,
) -> dict:
    return {
        "VulnerabilityID": vuln_id,
        "PkgName": "openssl",
        "InstalledVersion": "1.1.1",
        "FixedVersion": "1.1.1w",
        "Severity": severity,
        "CVSS": {"nvd": {"V3Score": score}},
        "Description": "x" * 500,
    }


def test_extracts_and_truncates_description() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [_vulnerability("CVE-1", "HIGH", 7.5)],
            }
        ]
    }

    result = extract_vulnerabilities(data)

    assert len(result) == 1
    assert result[0].id == "CVE-1"
    assert result[0].severity == "high"
    assert len(result[0].description) == 200


def test_handles_null_vulnerabilities() -> None:
    data = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": None,
            }
        ]
    }

    assert extract_vulnerabilities(data) == []


def test_handles_missing_results() -> None:
    assert extract_vulnerabilities({}) == []


def test_unknown_severity_becomes_informational() -> None:
    assert normalise_severity("BOGUS") == "informational"
    assert normalise_severity("NEGLIGIBLE") == "informational"


def test_prioritise_keeps_worst_findings() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    _vulnerability("CVE-LOW", "LOW", 2.0),
                    _vulnerability("CVE-CRIT", "CRITICAL", 9.8),
                    _vulnerability("CVE-MED", "MEDIUM", 5.0),
                ],
            }
        ]
    }

    result = prioritise(
        extract_vulnerabilities(data),
        limit=2,
    )

    assert [item.id for item in result] == [
        "CVE-CRIT",
        "CVE-MED",
    ]


def test_prioritise_breaks_ties_by_cvss() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    _vulnerability("CVE-A", "HIGH", 7.1),
                    _vulnerability("CVE-B", "HIGH", 8.9),
                ],
            }
        ]
    }

    result = prioritise(extract_vulnerabilities(data))

    assert result[0].id == "CVE-B"
