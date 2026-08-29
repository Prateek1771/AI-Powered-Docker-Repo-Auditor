from app.agents.trust import outcomes_by_agent
from app.models.findings import ComplianceFinding
from app.models.outcomes import AgentOutcome
from eval.matcher import evaluate_expectation, finding_matches


def _compliance(control: str, severity: str = "high") -> ComplianceFinding:
    return ComplianceFinding(
        control_id=control,
        severity=severity,
        title="Container runs as root",
        impact="Full host access on escape",
        fix="Add a USER instruction",
        effort="trivial",
        evidence="User field is root",
        priority=90,
    )


def test_control_id_match() -> None:
    assert finding_matches(_compliance("4.1"), {"control_id": "4.1"})
    assert not finding_matches(_compliance("4.3"), {"control_id": "4.1"})


def test_keyword_match_is_case_insensitive() -> None:
    finding = _compliance("4.1")

    assert finding_matches(finding, {"keywords_any": ["ROOT"]})
    assert not finding_matches(finding, {"keywords_any": ["healthcheck"]})


def test_severity_floor_is_enforced() -> None:
    outcomes = outcomes_by_agent(
        [
            AgentOutcome(
                agent="compliance_checker",
                status="analysed",
                findings=[_compliance("4.1", severity="low")],
            )
        ]
    )

    passed, note = evaluate_expectation(
        {
            "agent": "compliance_checker",
            "match": {"control_id": "4.1"},
            "min_severity": "high",
        },
        outcomes,
    )

    assert passed is False
    assert "severity" in note


def test_degraded_agent_fails_the_expectation() -> None:
    outcomes = outcomes_by_agent(
        [
            AgentOutcome(
                agent="compliance_checker",
                status="failed",
                findings=[],
            )
        ]
    )

    passed, note = evaluate_expectation(
        {"agent": "compliance_checker", "match": {"control_id": "4.1"}},
        outcomes,
    )

    assert passed is False
    assert note == "agent failed"
