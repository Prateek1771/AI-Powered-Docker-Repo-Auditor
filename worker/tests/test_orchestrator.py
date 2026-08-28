import asyncio

from app.models.outcomes import AgentOutcome, ScanOutcome


def _outcome(name: str, status: str, count: int = 0) -> AgentOutcome:
    return AgentOutcome(
        agent=name,
        status=status,
        findings=[],
        error=None if status == "analysed" else "boom",
    )


def test_scan_is_degraded_when_an_agent_fails() -> None:
    scan = ScanOutcome(
        target="python:3.8",
        outcomes=[
            _outcome("cve_analyst", "analysed"),
            _outcome("bloat_detective", "failed"),
        ],
    )

    assert scan.degraded is True


def test_clean_scan_is_not_degraded() -> None:
    scan = ScanOutcome(
        target="alpine:3.20",
        outcomes=[
            _outcome("cve_analyst", "skipped_no_input"),
            _outcome("bloat_detective", "analysed"),
        ],
    )

    assert scan.degraded is False


def test_empty_findings_alone_does_not_mean_clean() -> None:
    degraded = ScanOutcome(
        target="python:3.8",
        outcomes=[_outcome("cve_analyst", "failed")],
    )

    clean = ScanOutcome(
        target="alpine:3.20",
        outcomes=[_outcome("cve_analyst", "skipped_no_input")],
    )

    assert degraded.all_findings == clean.all_findings == []
    assert degraded.degraded != clean.degraded


async def test_gather_isolates_failure() -> None:
    async def good() -> str:
        await asyncio.sleep(0.01)
        return "ok"

    async def bad() -> str:
        raise RuntimeError("boom")

    results = await asyncio.gather(
        good(),
        bad(),
        return_exceptions=True,
    )

    assert results[0] == "ok"
    assert isinstance(results[1], BaseException)


async def test_wait_for_produces_timeout_error() -> None:
    async def slow() -> str:
        await asyncio.sleep(5)
        return "never"

    results = await asyncio.gather(
        asyncio.wait_for(slow(), timeout=0.05),
        return_exceptions=True,
    )

    assert isinstance(results[0], asyncio.TimeoutError)
