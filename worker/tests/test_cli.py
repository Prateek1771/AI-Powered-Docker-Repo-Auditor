"""The gate. Exit codes are the whole feature, so they are what is tested."""

import json
from pathlib import Path

import pytest

from app.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_THRESHOLD, breaches, build_parser, main
from app.models.findings import CVEFinding
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.policy.store import Policy, Suppression


def _report(severity: str = "critical") -> dict:
    return {
        "outcomes": [
            {
                "findings": [
                    {
                        "category": "cve",
                        "severity": severity,
                        "title": "Something",
                        "fingerprint": "fp-1",
                    }
                ]
            }
        ]
    }


def test_breaches_counts_at_or_above_the_threshold():
    assert len(breaches(_report("critical"), "high")) == 1
    assert len(breaches(_report("high"), "high")) == 1
    assert len(breaches(_report("medium"), "high")) == 0


def test_breaches_ignores_suppressed_findings():
    report = _report("critical")

    report["outcomes"][0]["findings"][0]["suppressed"] = True

    assert breaches(report, "critical") == []


def _scan(severity: str) -> ScanOutcome:
    return ScanOutcome(
        target="test:latest",
        outcomes=[
            AgentOutcome(
                agent="cve_analyst",
                status="analysed",
                findings=[
                    CVEFinding(
                        severity=severity,
                        title="Planted",
                        impact="i",
                        fix="f",
                        effort="trivial",
                        priority=90,
                        vulnerability_id="CVE-1",
                        exploitability="likely",
                    )
                ],
            )
        ],
    )


@pytest.fixture
def stub_scan(monkeypatch):
    """Swap the scan out. The gate logic is what is under test, not Trivy."""

    def _install(severity: str):
        async def fake(target, on_node=None):
            return _scan(severity)

        from app import cli

        monkeypatch.setattr(cli, "run_scan", fake)
        monkeypatch.setattr(cli, "load_policy", lambda _tenant: Policy())

    return _install


def _run(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr("sys.argv", ["app.cli", *argv])

    return main()


def test_exit_1_when_the_threshold_is_breached(monkeypatch, stub_scan, capsys):
    stub_scan("critical")

    assert (
        _run(monkeypatch, ["scan", "x", "--fail-on-severity", "high"]) is EXIT_THRESHOLD
    )

    assert "FAIL" in capsys.readouterr().err


def test_exit_0_when_it_is_not(monkeypatch, stub_scan, capsys):
    stub_scan("low")

    assert _run(monkeypatch, ["scan", "x", "--fail-on-severity", "high"]) is EXIT_CLEAN

    assert "PASS" in capsys.readouterr().err


def test_exit_0_without_a_threshold(monkeypatch, stub_scan):
    """No --fail-on-severity means report only. Never a surprise failure."""
    stub_scan("critical")

    assert _run(monkeypatch, ["scan", "x"]) is EXIT_CLEAN


def test_a_failed_scan_exits_2_not_1(monkeypatch, capsys):
    """ "We found criticals" and "we never looked" must not look the same."""

    async def boom(target, on_node=None):
        raise RuntimeError("docker is not running")

    monkeypatch.setattr("app.cli.run_scan", boom)

    assert _run(monkeypatch, ["scan", "x", "--fail-on-severity", "high"]) is EXIT_ERROR


def test_suppressed_finding_passes_the_gate_but_stays_in_the_report(
    monkeypatch, stub_scan, tmp_path, capsys
):
    """The distinction the whole policy design rests on."""
    stub_scan("critical")

    monkeypatch.setattr(
        "app.cli.load_policy",
        lambda _tenant: Policy(
            suppressions=[Suppression(vulnerability_id="CVE-1", reason="Accepted")]
        ),
    )

    out = tmp_path / "report.json"

    code = _run(
        monkeypatch,
        ["scan", "x", "--fail-on-severity", "high", "--output", str(out)],
    )

    assert code is EXIT_CLEAN

    finding = json.loads(out.read_text())["outcomes"][0]["findings"][0]

    assert finding["suppressed"] is True
    assert finding["suppressed_reason"] == "Accepted"


def test_output_is_written_in_the_requested_format(monkeypatch, stub_scan, tmp_path):
    stub_scan("critical")

    out = tmp_path / "out.sarif"

    _run(monkeypatch, ["scan", "x", "--format", "sarif", "--output", str(out)])

    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_parser_rejects_an_unknown_format():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "x", "--format", "pdf"])


def test_the_stub_console_script_is_gone():
    """A console script that prints "Hello from worker!" next to a real CLI."""
    assert not Path("src").exists()
