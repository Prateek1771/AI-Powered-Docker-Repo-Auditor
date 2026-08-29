import pytest

from eval.run import _load, measure_precision, measure_recall

pytestmark = pytest.mark.eval

MIN_RECALL = 0.90


async def test_recall_meets_threshold() -> None:
    report = await measure_recall(_load("bad.yaml"))

    missed = ", ".join(r.expectation_id for r in report.missed)

    assert report.recall >= MIN_RECALL, (
        f"recall {report.recall:.0%} below {MIN_RECALL:.0%}. Missed: {missed}"
    )


async def test_no_false_positives_on_clean_image() -> None:
    report = await measure_precision(_load("clean.yaml"))

    problems = [v.expectation_id for v in report.violations]
    problems += report.limit_breaches

    assert report.clean, f"false positives: {problems}"
