"""Scan an image from a pipeline and fail the build on what it finds.

    python -m app.cli scan nginx:latest --fail-on-severity high

The exit code is the whole point: a report nothing acts on is a report
nobody reads. 0 clean, 1 threshold breached, 2 the scan itself failed -
and the distinction between 1 and 2 matters, because "we found criticals"
and "we never looked" must not look the same to CI.

`python -m`, not a console script: worker/Dockerfile passes
--no-install-project, so nothing declared in [project.scripts] exists in
the image. Every other entrypoint here is `python -m app.scripts.X`.
"""

import argparse
import asyncio
import json
import logging
import sys

from app.orchestrator import run_scan
from app.policy.apply import apply_policy, unsuppressed_findings
from app.policy.store import load_policy
from app.processors.vulnerabilities import SEVERITY_ORDER, severity_rank
from app.reporting import FORMATS
from app.telemetry import setup

logger = logging.getLogger(__name__)

EXIT_CLEAN = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


def _report_dict(scan) -> dict:
    """The same shape store_result writes, so exporters see one format.

    Exporters take the stored report dict rather than the live object,
    which is what lets them run against a historical scan - the CLI has a
    live object, so it produces the same dict here.
    """
    return {
        "target": scan.target,
        "outcomes": [o.model_dump() for o in scan.outcomes],
        "dockerfile": scan.dockerfile.model_dump() if scan.dockerfile else None,
        "risk": scan.risk.model_dump() if scan.risk else None,
        "profile": scan.profile.model_dump() if scan.profile else None,
        "coverage": scan.coverage.model_dump() if scan.coverage else None,
        "packages": [p.model_dump() for p in scan.packages],
        "diff": None,
    }


def breaches(report: dict, threshold: str) -> list[dict]:
    """Unsuppressed findings at or above the threshold.

    Ordered by SEVERITY_ORDER rather than a second severity ranking
    defined here, because two rankings is how they drift apart.
    """
    limit = severity_rank(threshold)

    return [
        finding
        for finding in unsuppressed_findings(report)
        if severity_rank(finding.get("severity", "informational")) <= limit
    ]


def _scan(args: argparse.Namespace) -> int:
    # asyncio only wraps the scan itself. Everything after it is ordinary
    # blocking work - writing a file, printing - and belongs outside a
    # loop rather than inside one it would block.
    scan = asyncio.run(run_scan(args.target))

    report = apply_policy(_report_dict(scan), load_policy(args.tenant))

    if args.format == "json":
        rendered = json.dumps(report, indent=2)
    else:
        rendered = FORMATS[args.format].render(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)

        print(f"Wrote {args.format} to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    if not args.fail_on_severity:
        return EXIT_CLEAN

    failing = breaches(report, args.fail_on_severity)

    if not failing:
        print(
            f"PASS: nothing at or above {args.fail_on_severity}",
            file=sys.stderr,
        )

        return EXIT_CLEAN

    print(
        f"FAIL: {len(failing)} finding(s) at or above {args.fail_on_severity}",
        file=sys.stderr,
    )

    # The worst ten, not all of them: a gate message that scrolls off the
    # CI pane is the same as no message.
    for finding in sorted(
        failing,
        key=lambda f: severity_rank(f.get("severity", "informational")),
    )[:10]:
        print(
            f"  [{finding.get('severity')}] {finding.get('title')}",
            file=sys.stderr,
        )

    return EXIT_THRESHOLD


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an image and optionally gate on it")
    scan.add_argument("target")
    scan.add_argument(
        "--fail-on-severity",
        choices=list(SEVERITY_ORDER),
        help="Exit 1 if any unsuppressed finding is at or above this",
    )
    scan.add_argument("--format", choices=["json", *FORMATS], default="json")
    scan.add_argument("--output", help="Write the report here instead of stdout")
    scan.add_argument(
        "--tenant",
        default="default",
        help="Whose suppression policy to apply",
    )

    return parser


def main() -> int:
    # Before any logger is used. The CI gate is the third entrypoint and was
    # the one left on plain-text logging with no metrics, so a scan run from a
    # pipeline was the only scan nobody could see. JSON goes to stderr, which
    # is what keeps --format json on stdout machine-readable, and metrics push
    # only when OTEL_EXPORTER_OTLP_ENDPOINT is set.
    setup("cli")

    args = build_parser().parse_args()

    try:
        return _scan(args)
    except Exception:
        # Exit 2, never 1: a scan that could not run has not proved the
        # image clean, and must not be mistaken for a passing gate.
        logger.exception("Scan failed")

        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
