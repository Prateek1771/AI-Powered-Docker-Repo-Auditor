"""SARIF 2.1.0, built from our findings rather than passed through from Trivy.

Trivy can emit SARIF itself, and it would have been three lines. It also only
knows about vulnerabilities - so it would throw away the CIS controls, the
secret findings, the bloat analysis and the base-image work, which is to say
everything the product adds on top of Trivy.

GitHub code scanning ingests this natively, which is what turns a report
nobody opens into PR annotations on the line that caused them.

See docs/audits/audit-01-backend.md P2-5.
"""

import json
from typing import Any

from app.policy.apply import all_findings

SARIF_VERSION = "2.1.0"

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has three levels and we have five. Mapping medium to "warning" rather
# than "error" is the difference between a PR that can be merged and one that
# cannot, so it is a policy decision, not a detail.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

# GitHub sorts and filters on this, and reads it from the rule properties.
# Without it every finding lands as undifferentiated "warning".
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "informational": "1.0",
}

# Findings that are not about a file get attributed here. Inventing line
# numbers for them would put annotations on unrelated code, which is worse
# than pointing at the thing that actually produced them.
_SYNTHETIC_ARTIFACT = "Dockerfile"


def _rule_id(finding: dict) -> str:
    """A stable rule id per finding class, not per finding.

    SARIF rules are the catalogue; results are the occurrences. Giving
    every finding its own rule would make the catalogue useless and stop
    GitHub grouping recurrences.
    """
    category = finding.get("category", "unknown")

    if category == "cve":
        return f"cve/{finding.get('vulnerability_id', 'unknown')}"

    if category == "compliance":
        return f"cis/{finding.get('control_id', 'unknown')}"

    if category == "secret":
        return f"secret/{finding.get('rule_id', 'unknown')}"

    return category


def _rule(finding: dict) -> dict:
    severity = finding.get("severity", "informational")

    properties: dict[str, Any] = {
        "security-severity": _SECURITY_SEVERITY.get(severity, "1.0"),
        "tags": ["security", finding.get("category", "unknown")],
    }

    if finding.get("cwe_ids"):
        properties["tags"] = [*properties["tags"], *finding["cwe_ids"]]

    rule = {
        "id": _rule_id(finding),
        "name": _rule_id(finding).replace("/", "_"),
        "shortDescription": {"text": finding.get("title", "")[:140]},
        "fullDescription": {"text": finding.get("impact", "")},
        "help": {
            "text": finding.get("fix", ""),
            "markdown": f"**Impact**\n\n{finding.get('impact', '')}\n\n"
            f"**Fix**\n\n{finding.get('fix', '')}",
        },
        "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
        "properties": properties,
    }

    if finding.get("primary_url"):
        rule["helpUri"] = finding["primary_url"]

    return rule


def _location(finding: dict) -> dict:
    """Where to point the annotation.

    Only a secret finding knows a real file and line. Everything else is a
    property of the image as a whole, so it is attributed to the Dockerfile
    with no region rather than to a fabricated line.
    """
    if finding.get("category") == "secret" and finding.get("file_path"):
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding["file_path"]},
            }
        }

        if finding.get("line"):
            location["physicalLocation"]["region"] = {"startLine": int(finding["line"])}

        return location

    return {
        "physicalLocation": {"artifactLocation": {"uri": _SYNTHETIC_ARTIFACT}},
    }


def _result(finding: dict) -> dict:
    severity = finding.get("severity", "informational")

    properties: dict[str, Any] = {}

    for key in (
        "package",
        "installed_version",
        "fixed_version",
        "cvss_score",
        "cvss_vector",
        "layer_index",
        "control_id",
        "wasted_bytes",
        "recommended_base",
        "kev_listed",
        "epss_score",
        "effort",
        "priority",
    ):
        if finding.get(key) not in (None, "", []):
            properties[key] = finding[key]

    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _LEVEL.get(severity, "note"),
        "message": {"text": f"{finding.get('title', '')}. {finding.get('fix', '')}"},
        "locations": [_location(finding)],
    }

    if properties:
        result["properties"] = properties

    # The 2A fingerprint, which is exactly what this field is for: GitHub
    # uses it to recognise a finding across scans instead of closing and
    # reopening it every run.
    if finding.get("fingerprint"):
        result["partialFingerprints"] = {
            "auditorFingerprint/v1": finding["fingerprint"]
        }

    # Suppressed findings are REPORTED as suppressed, not omitted. SARIF has
    # a first-class notion of this and GitHub honours it, so an accepted risk
    # stays visible and reviewable instead of silently vanishing.
    if finding.get("suppressed"):
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": finding.get("suppressed_reason", ""),
            }
        ]

    return result


def to_sarif(report: dict) -> str:
    """Render a stored report as SARIF 2.1.0."""
    findings = all_findings(report)

    rules: dict[str, dict] = {}

    for finding in findings:
        rules.setdefault(_rule_id(finding), _rule(finding))

    coverage = report.get("coverage") or {}

    document = {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Powered Docker Repo Auditor",
                        "informationUri": (
                            "https://github.com/prateek1771/"
                            "AI-Powered-Docker-Repo-Auditor"
                        ),
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
                "properties": {
                    "target": report.get("target", ""),
                    "imageId": coverage.get("image_id", ""),
                    # Surfaced deliberately: a SARIF upload that silently
                    # covered 150 of 11,000 vulnerabilities would read as a
                    # clean-ish bill of health.
                    "totalVulnerabilities": coverage.get("total_vulnerabilities", 0),
                    "analysed": coverage.get("sent_to_model", 0),
                    "notAnalysed": coverage.get("dropped", 0),
                },
            }
        ],
    }

    return json.dumps(document, indent=2)
