"""Every export, against a real parser.

Eyeballing a SARIF file is how a malformed one ships: GitHub rejects it
silently, so the failure mode is a security feature that appears to work
and reports nothing.
"""

import csv
import io
import json
from xml.etree import ElementTree as ET

import pytest

from app.processors.packages import extract_packages
from app.reporting import FORMATS
from app.reporting.cyclonedx import to_cyclonedx
from app.reporting.sarif import to_sarif
from app.reporting.tabular import to_csv, to_junit


@pytest.fixture
def report() -> dict:
    """One of each finding category, one suppressed, plus packages."""
    return {
        "target": "nginx:latest",
        "coverage": {
            "image_id": "sha256:abc",
            "total_vulnerabilities": 11028,
            "sent_to_model": 150,
            "dropped": 10878,
            "scanned_at": "2026-09-15T00:00:00Z",
        },
        "packages": [
            {
                "name": "openssl",
                "version": "3.0.2",
                "purl": "pkg:deb/debian/openssl@3.0.2",
                "licenses": ["Apache-2.0"],
            },
            {"name": "zlib", "version": "1.2.11", "purl": ""},
        ],
        "outcomes": [
            {
                "agent": "cve_analyst",
                "status": "analysed",
                "findings": [
                    {
                        "category": "cve",
                        "severity": "critical",
                        "title": "OpenSSL RCE",
                        "impact": 'Remote code execution, with a comma, "quotes"',
                        "fix": "Upgrade to 3.0.7",
                        "effort": "trivial",
                        "priority": 99,
                        "fingerprint": "fp-cve-1",
                        "vulnerability_id": "CVE-2022-3602",
                        "package": "openssl",
                        "installed_version": "3.0.2",
                        "fixed_version": "3.0.7",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L",
                        "cwe_ids": ["CWE-787"],
                        "primary_url": "https://nvd.nist.gov/vuln/CVE-2022-3602",
                        "references": ["https://example.test/a"],
                    },
                    {
                        "category": "cve",
                        "severity": "high",
                        "title": "Accepted zlib issue",
                        "impact": "Not reachable in our usage",
                        "fix": "None available",
                        "effort": "involved",
                        "priority": 40,
                        "fingerprint": "fp-cve-2",
                        "vulnerability_id": "CVE-2018-25032",
                        "package": "zlib",
                        "suppressed": True,
                        "suppressed_reason": "Not reachable, reviewed 2026-09-01",
                    },
                ],
            },
            {
                "agent": "secret_scan",
                "status": "analysed",
                "findings": [
                    {
                        "category": "secret",
                        "severity": "critical",
                        "title": "AWS key in layer",
                        "impact": "Credential exposure",
                        "fix": "Rotate and rebuild",
                        "effort": "moderate",
                        "priority": 95,
                        "fingerprint": "fp-secret-1",
                        "rule_id": "aws-access-key-id",
                        "file_path": "app/settings.py",
                        "line": 12,
                    }
                ],
            },
            {
                "agent": "cis_controls",
                "status": "analysed",
                "findings": [
                    {
                        "category": "compliance",
                        "severity": "medium",
                        "title": "Container runs as root",
                        "impact": "No privilege boundary",
                        "fix": "Add a USER directive",
                        "effort": "trivial",
                        "priority": 60,
                        "fingerprint": "fp-cis-1",
                        "control_id": "4.1",
                    }
                ],
            },
        ],
    }


def test_sarif_parses_and_keeps_shape(report):
    doc = json.loads(to_sarif(report))

    assert doc["version"] == "2.1.0"

    run = doc["runs"][0]

    # One result per finding - suppressed ones included, as suppressed.
    assert len(run["results"]) == 4

    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}

    # The categories Trivy's own SARIF would have dropped.
    assert "cis/4.1" in rule_ids
    assert "secret/aws-access-key-id" in rule_ids

    by_rule = {r["ruleId"]: r for r in run["results"]}

    assert by_rule["cve/CVE-2022-3602"]["level"] == "error"
    assert by_rule["cve/CVE-2022-3602"]["partialFingerprints"] == {
        "auditorFingerprint/v1": "fp-cve-1"
    }

    # A secret points at its real file and line; nothing else invents one.
    secret = by_rule["secret/aws-access-key-id"]["locations"][0]["physicalLocation"]

    assert secret["artifactLocation"]["uri"] == "app/settings.py"
    assert secret["region"]["startLine"] == 12

    cis = by_rule["cis/4.1"]["locations"][0]["physicalLocation"]

    assert cis["artifactLocation"]["uri"] == "Dockerfile"
    assert "region" not in cis

    # What the scan could not look at, stated rather than implied.
    assert run["properties"]["notAnalysed"] == 10878


def test_sarif_reports_suppression_rather_than_hiding_it(report):
    doc = json.loads(to_sarif(report))

    suppressed = [
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "cve/CVE-2018-25032"
    ]

    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["justification"].startswith("Not reachable")


def test_cyclonedx_cross_references_components(report):
    doc = json.loads(to_cyclonedx(report))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")

    assert [c["name"] for c in doc["components"]] == ["openssl", "zlib"]

    # Only CVEs become vulnerabilities; the CIS control is not one.
    assert len(doc["vulnerabilities"]) == 2

    openssl = doc["vulnerabilities"][0]

    assert openssl["id"] == "CVE-2022-3602"
    assert openssl["affects"] == [{"ref": "pkg:deb/debian/openssl@3.0.2"}]
    assert openssl["cwes"] == [787]
    assert openssl["ratings"][0]["score"] == 9.8

    accepted = doc["vulnerabilities"][1]

    assert accepted["analysis"]["state"] == "not_affected"


def test_cyclonedx_component_count_matches_trivy_packages():
    """The SBOM is exactly what the scanner listed, not a subset of it."""
    trivy = {
        "Results": [
            {
                "Target": "debian",
                "Packages": [
                    {
                        "Name": "a",
                        "Version": "1",
                        "Identifier": {"PURL": "pkg:deb/a@1"},
                    },
                    {"Name": "b", "Version": "2", "PURL": "pkg:deb/b@2"},
                    # The same component seen twice is one line in a BOM.
                    {
                        "Name": "a",
                        "Version": "1",
                        "Identifier": {"PURL": "pkg:deb/a@1"},
                    },
                ],
            }
        ]
    }

    packages = extract_packages(trivy)

    doc = json.loads(
        to_cyclonedx(
            {
                "target": "x",
                "outcomes": [],
                "packages": [p.model_dump() for p in packages],
            }
        )
    )

    assert len(doc["components"]) == len(packages) == 2


def test_csv_survives_prose_with_commas_and_quotes(report):
    rows = list(csv.DictReader(io.StringIO(to_csv(report))))

    assert len(rows) == 4

    # Worst first.
    assert rows[0]["severity"] == "critical"

    openssl = next(r for r in rows if r["vulnerability_id"] == "CVE-2022-3602")

    assert openssl["fixed_version"] == "3.0.7"
    assert openssl["cvss_score"] == "9.8"

    accepted = next(r for r in rows if r["vulnerability_id"] == "CVE-2018-25032")

    assert accepted["suppressed"] == "True"
    assert accepted["suppressed_reason"].startswith("Not reachable")


def test_junit_fails_only_unsuppressed_findings_at_or_above_threshold(report):
    suite = ET.fromstring(to_junit(report, fail_at="high"))

    assert suite.get("tests") == "4"

    # critical CVE + critical secret. The high one is suppressed, the
    # medium one is below the line.
    assert suite.get("failures") == "2"

    skipped = suite.findall("./testcase/skipped")

    assert len(skipped) == 1
    assert "Not reachable" in (skipped[0].get("message") or "")


def test_junit_threshold_moves(report):
    assert ET.fromstring(to_junit(report, fail_at="medium")).get("failures") == "3"
    assert ET.fromstring(to_junit(report, fail_at="critical")).get("failures") == "2"


def test_every_format_renders_an_empty_report():
    """A clean scan must not crash the exporter that reports it clean."""
    empty: dict = {
        "target": "scratch",
        "outcomes": [],
        "packages": [],
        "coverage": None,
    }

    for name, export in FORMATS.items():
        rendered = export.render(empty)

        assert isinstance(rendered, str) and rendered, name
