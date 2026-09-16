"""Cover the per-node progress frames the pipeline graph is built on.

The interesting property is not that frames are emitted - it is that the
sequence a client sees never goes backwards. The first version of this
spread all nine nodes over one 10->90 band, which put the third settled
scanner at 37% immediately before the stage frame that says 40%.
"""

import pytest

from app.orchestrator import (
    _AGENT_NODES,
    _AGENTS_AT,
    _FETCHING_AT,
    _SCANNER_NODES,
    _STORING_AT,
    _node_reporter,
    _report_node,
)
from app.progress.bus import ProgressEvent


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    async def publish(self, event: ProgressEvent) -> None:
        self.events.append(event)


async def _run_a_whole_scan(bus: RecordingBus) -> None:
    report = _node_reporter(bus, "job-1")

    for node in _SCANNER_NODES:
        await report(node, "running")

    for node in _SCANNER_NODES:
        await report(node, "analysed")

    for node in _AGENT_NODES:
        await report(node, "running")
        await report(node, "analysed")


async def test_progress_never_goes_backwards() -> None:
    bus = RecordingBus()

    await _run_a_whole_scan(bus)

    values = [e.progress for e in bus.events]

    assert values == sorted(values), f"progress went backwards: {values}"


async def test_the_bands_line_up_with_the_stage_frames() -> None:
    """Scanners must finish exactly where "Running agents" starts, and
    agents exactly where "Storing results" does. Any other arithmetic puts
    a node frame on the wrong side of a stage frame."""
    bus = RecordingBus()

    await _run_a_whole_scan(bus)

    by_node = {(e.node, e.node_state): e.progress for e in bus.events}

    assert by_node[(_SCANNER_NODES[-1], "analysed")] == _AGENTS_AT
    assert by_node[(_AGENT_NODES[-1], "analysed")] == _STORING_AT

    assert bus.events[0].progress == _FETCHING_AT


async def test_every_frame_carries_the_fields_a_client_filters_on() -> None:
    """hooks/useScanProgress.ts drops any frame without a numeric progress
    and a status, so a node frame missing either is invisible."""
    bus = RecordingBus()

    await _run_a_whole_scan(bus)

    for event in bus.events:
        assert isinstance(event.progress, int)
        assert event.status == "running"
        assert event.node
        assert event.node_state


async def test_running_does_not_advance_the_bar() -> None:
    """Only a settled node is progress. Otherwise starting four agents at
    once would jump the bar most of the way before any work landed."""
    bus = RecordingBus()

    report = _node_reporter(bus, "job-1")

    for node in _SCANNER_NODES:
        await report(node, "running")

    assert {e.progress for e in bus.events} == {_FETCHING_AT}


async def test_a_reporter_failure_never_reaches_the_scan() -> None:
    """A progress frame is a nice-to-have; the scan result is not."""

    async def broken(node: str, state: str) -> None:
        raise RuntimeError("redis is down")

    await _report_node(broken, "cve_analyst", "running")


async def test_no_reporter_is_the_eval_harness_path() -> None:
    """run_scan_from_raw(..., on_node=None) must behave exactly as before."""
    await _report_node(None, "cve_analyst", "running")


@pytest.mark.parametrize("node", [*_SCANNER_NODES, *_AGENT_NODES])
async def test_every_node_stays_inside_the_bar(node: str) -> None:
    bus = RecordingBus()

    report = _node_reporter(bus, "job-1")

    for _ in range(20):
        await report(node, "analysed")

    assert all(0 <= e.progress <= _STORING_AT for e in bus.events)
