"""CycloneDX 1.5, from the package inventory the scan already collected.

Trivy reports every package it finds under `Results[].Packages`, not just the
vulnerable ones. Nothing read that key, so a full bill of materials arrived on
every scan and was discarded - and producing an SBOM looked like it needed a
second, doubled scan.

Components and vulnerabilities in one document, cross-referenced by bom-ref,
so a consumer can go from "this CVE" to "this exact component" without joining
two files.
"""

import json
import uuid
from typing import Any

from app.policy.apply import all_findings

SPEC_VERSION = "1.5"

# CycloneDX's own vocabulary, which is not ours.
_RATING_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def _bom_ref(package: dict) -> str:
    """Prefer the purl: it identifies a component globally, a name does not."""
    return (
        package.get("purl") or f"{package.get('name', '')}@{package.get('version', '')}"
    )


def _component(package: dict) -> dict:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": _bom_ref(package),
        "name": package.get("name", ""),
        "version": package.get("version", ""),
    }

    if package.get("purl"):
        component["purl"] = package["purl"]

    if package.get("licenses"):
        # CycloneDX wants either a licence id or a name; `name` accepts the
        # free-text strings Trivy reports without pretending they are SPDX ids.
        component["licenses"] = [
            {"license": {"name": name}} for name in package["licenses"]
        ]

    return component


def _vulnerability(finding: dict, by_name: dict[str, str]) -> dict:
    severity = finding.get("severity", "informational")

    vulnerability: dict[str, Any] = {
        "bom-ref": finding.get("fingerprint") or finding.get("vulnerability_id", ""),
        "id": finding.get("vulnerability_id", ""),
        "ratings": [
            {
                "severity": _RATING_SEVERITY.get(severity, "unknown"),
                "method": "CVSSv31" if finding.get("cvss_vector") else "other",
            }
        ],
        "description": finding.get("impact", ""),
        "recommendation": finding.get("fix", ""),
    }

    if finding.get("cvss_score"):
        vulnerability["ratings"][0]["score"] = finding["cvss_score"]

    if finding.get("cvss_vector"):
        vulnerability["ratings"][0]["vector"] = finding["cvss_vector"]

    if finding.get("cwe_ids"):
        # CycloneDX wants integers; Trivy gives "CWE-787".
        cwes = []

        for cwe in finding["cwe_ids"]:
            digits = str(cwe).removeprefix("CWE-")

            if digits.isdigit():
                cwes.append(int(digits))

        if cwes:
            vulnerability["cwes"] = cwes

    if finding.get("references") or finding.get("primary_url"):
        urls = list(finding.get("references") or [])

        if finding.get("primary_url"):
            urls.insert(0, finding["primary_url"])

        vulnerability["advisories"] = [{"url": url} for url in urls[:5]]

    # The cross-reference that makes this worth having as one document.
    ref = by_name.get(finding.get("package", ""))

    if ref:
        vulnerability["affects"] = [{"ref": ref}]

    # An accepted risk is stated, not hidden. CycloneDX has a first-class
    # analysis block for exactly this.
    if finding.get("suppressed"):
        vulnerability["analysis"] = {
            "state": "not_affected",
            "detail": finding.get("suppressed_reason", ""),
        }

    return vulnerability


def to_cyclonedx(report: dict) -> str:
    """Render a stored report as a CycloneDX 1.5 BOM."""
    packages = report.get("packages") or []

    components = [_component(p) for p in packages]

    by_name = {p.get("name", ""): _bom_ref(p) for p in packages}

    vulnerabilities = [
        _vulnerability(f, by_name)
        for f in all_findings(report)
        if f.get("category") == "cve"
    ]

    coverage = report.get("coverage") or {}

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": coverage.get("scanned_at", ""),
            "tools": [
                {
                    "vendor": "AI-Powered Docker Repo Auditor",
                    "name": "auditor",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "container",
                "bom-ref": coverage.get("image_id", "") or report.get("target", ""),
                "name": report.get("target", ""),
                "version": coverage.get("image_id", ""),
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    return json.dumps(document, indent=2)
