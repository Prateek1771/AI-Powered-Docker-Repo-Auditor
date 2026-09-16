"""CSV and JUnit, the two formats people actually paste into other tools.

CSV goes into a spreadsheet and gets sorted by whoever has to do the work.
JUnit goes into the test-report pane every CI system already renders, which
means findings show up where people already look instead of in a tab they have
to remember to open.

Both stdlib. `csv` and `xml.etree.ElementTree` are enough, and a dependency
for either would be hard to justify.
"""

import csv
import io
from xml.etree import ElementTree as ET

from app.policy.apply import all_findings
from app.processors.vulnerabilities import severity_rank

CSV_COLUMNS = [
    "severity",
    "category",
    "title",
    "package",
    "installed_version",
    "fixed_version",
    "vulnerability_id",
    "control_id",
    "cvss_score",
    "kev_listed",
    "epss_score",
    "effort",
    "priority",
    "suppressed",
    "suppressed_reason",
    "fix",
    "fingerprint",
]


def _sorted_findings(report: dict) -> list[dict]:
    """Worst first, then highest priority - the order work gets done in."""
    return sorted(
        all_findings(report),
        key=lambda f: (
            severity_rank(f.get("severity", "informational")),
            -int(f.get("priority", 0)),
        ),
    )


def to_csv(report: dict) -> str:
    buffer = io.StringIO()

    # QUOTE_ALL: findings carry prose with commas, quotes and newlines in it,
    # and a CSV that needs a human to repair it is not an export.
    writer = csv.DictWriter(
        buffer,
        fieldnames=CSV_COLUMNS,
        extrasaction="ignore",
        quoting=csv.QUOTE_ALL,
        lineterminator="\n",
    )

    writer.writeheader()

    for finding in _sorted_findings(report):
        writer.writerow({column: finding.get(column, "") for column in CSV_COLUMNS})

    return buffer.getvalue()


def to_junit(report: dict, fail_at: str = "high") -> str:
    """Render findings as a JUnit suite.

    Anything at or above `fail_at` is a failure; everything else is a
    passing test that still carries its detail, so the report shows the
    whole picture rather than only the bad news.
    """
    threshold = severity_rank(fail_at)

    findings = _sorted_findings(report)

    failures = 0

    suite = ET.Element(
        "testsuite",
        name="docker-repo-auditor",
        tests=str(len(findings)),
        errors="0",
    )

    for finding in findings:
        severity = finding.get("severity", "informational")

        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"{finding.get('category', 'unknown')}.{severity}",
            name=finding.get("title", "")[:140],
        )

        if finding.get("suppressed"):
            skipped = ET.SubElement(case, "skipped")
            skipped.set("message", finding.get("suppressed_reason", "suppressed"))

            continue

        if severity_rank(severity) <= threshold:
            failures += 1

            failure = ET.SubElement(
                case,
                "failure",
                message=finding.get("title", "")[:140],
                type=severity,
            )
            failure.text = (
                f"{finding.get('impact', '')}\n\nFix: {finding.get('fix', '')}"
            )

    suite.set("failures", str(failures))

    return ET.tostring(suite, encoding="unicode", xml_declaration=True)
