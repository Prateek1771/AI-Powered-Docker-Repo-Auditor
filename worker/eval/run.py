import argparse
import asyncio
from pathlib import Path

import yaml

from app.agents.trust import outcomes_by_agent
from app.models.outcomes import ScanOutcome
from app.orchestrator import run_scan_from_raw
from eval.cache import cached_scanners
from eval.matcher import evaluate_expectation, finding_matches
from eval.metrics import (
    ExpectationResult,
    PrecisionReport,
    RecallReport,
    StabilityReport,
)

EXPECTATIONS = Path(__file__).parent / "expectations"


def _load(name: str) -> dict:
    """Read one expectations file from eval/expectations."""
    return yaml.safe_load((EXPECTATIONS / name).read_text())


async def _scan(target: str) -> ScanOutcome:
    """Run every agent over cached scanner output for a target."""
    trivy, history, inspect = await cached_scanners(target)

    return await run_scan_from_raw(target, trivy, history, inspect)


async def measure_recall(spec: dict) -> RecallReport:
    """Report how many known problems the agents actually found.

    Run against the deliberately bad fixture, where the answers are known
    in advance. This is the number that must not go down when a prompt
    changes, which is what makes it a gate rather than a report.
    """
    scan = await _scan(spec["image"])
    outcomes = outcomes_by_agent(scan.outcomes)

    report = RecallReport()

    for expectation in spec["expectations"]:
        passed, note = evaluate_expectation(expectation, outcomes)

        report.results.append(
            ExpectationResult(
                expectation_id=expectation["id"],
                agent=expectation["agent"],
                passed=passed,
                note=note,
                why=expectation["why"],
            )
        )

    limits = spec.get("scores", {})

    if scan.risk:
        score = scan.risk.score

        for key, cap in limits.items():
            if key.endswith("_at_most"):
                name = key.replace("_at_most", "")
                actual = getattr(score, name)

                report.results.append(
                    ExpectationResult(
                        expectation_id=f"score-{name}",
                        agent="risk_scorer",
                        passed=actual <= cap,
                        note=f"{actual} (cap {cap})",
                        why=f"{name} should be at most {cap} on a bad image",
                    )
                )

    return report


async def measure_precision(spec: dict) -> PrecisionReport:
    """Report whether the agents invent problems on a clean image.

    The other half of recall: a prompt tuned only for recall learns to
    flag everything, and this is what catches that.
    """
    scan = await _scan(spec["image"])
    outcomes = outcomes_by_agent(scan.outcomes)

    report = PrecisionReport()

    for rule in spec.get("forbidden", []):
        agent = rule["agent"]

        if agent not in outcomes:
            continue

        hits = [
            f for f in outcomes[agent].findings if finding_matches(f, rule["match"])
        ]

        if hits:
            report.violations.append(
                ExpectationResult(
                    expectation_id=rule["id"],
                    agent=agent,
                    passed=False,
                    note=f"{len(hits)} false positives",
                    why=rule["why"],
                )
            )

    limits = spec.get("limits", {})

    for key, cap in limits.items():
        agent = key.replace("_findings_at_most", "")

        agent_key = {
            "compliance": "compliance_checker",
            "bloat": "bloat_detective",
            "cve": "cve_analyst",
        }.get(agent)

        if agent_key and agent_key in outcomes:
            count = len(outcomes[agent_key].findings)

            if count > cap:
                report.limit_breaches.append(
                    f"{agent_key}: {count} findings, limit {cap}"
                )

    return report


async def measure_stability(target: str, runs: int) -> StabilityReport:
    """Run the same scan repeatedly and measure how much the answers move.

    Temperature is zero, but the same input can still produce different
    findings. Score spread and Jaccard overlap say how much a single run
    can be trusted.
    """
    scores: list[int] = []
    id_sets: list[set[str]] = []

    for _ in range(runs):
        scan = await _scan(target)

        if scan.risk:
            scores.append(scan.risk.score.overall)

        ids = set()

        for outcome in scan.outcomes:
            for finding in outcome.findings:
                ids.add(
                    getattr(finding, "vulnerability_id", None)
                    or getattr(finding, "control_id", None)
                    or finding.title[:60]
                )

        id_sets.append(ids)

    return StabilityReport(
        overall_scores=scores,
        finding_id_sets=id_sets,
    )


async def main() -> None:
    """Run the eval suite and print a report."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--skip-stability", action="store_true")
    args = parser.parse_args()

    bad = _load("bad.yaml")
    clean = _load("clean.yaml")

    print("=" * 62)
    print("RECALL  - did it find the planted problems")
    print("=" * 62)

    recall = await measure_recall(bad)

    for result in recall.results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"  [{mark}] {result.expectation_id:32} {result.note}")

    print(f"\n  recall: {recall.recall:.0%} ({recall.found}/{recall.total})\n")

    print("=" * 62)
    print("PRECISION - did it invent problems on a clean image")
    print("=" * 62)

    precision = await measure_precision(clean)

    if precision.clean:
        print("  no false positives\n")
    else:
        for violation in precision.violations:
            print(f"  [FAIL] {violation.expectation_id:30} {violation.why}")

        for breach in precision.limit_breaches:
            print(f"  [FAIL] {breach}")

        print()

    if not args.skip_stability:
        print("=" * 62)
        print(f"STABILITY - {args.runs} runs of the same input")
        print("=" * 62)

        stability = await measure_stability(bad["image"], args.runs)

        print(f"  scores:        {stability.overall_scores}")
        print(f"  stdev:         {stability.score_stdev}")
        print(f"  range:         {stability.score_range}")
        print(f"  mean jaccard:  {stability.mean_jaccard}")


if __name__ == "__main__":
    asyncio.run(main())
