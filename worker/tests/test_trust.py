from app.agents.trust import (
    input_confidence,
    missing_inputs,
    outcomes_by_agent,
    required_inputs_sound,
)
from app.models.outcomes import AgentOutcome


def _outcome(name: str, status: str) -> AgentOutcome:
    return AgentOutcome(agent=name, status=status, findings=[])


def test_all_sound_inputs_pass_the_gate() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("cve_analyst", "analysed"),
            _outcome("bloat_detective", "skipped_no_input"),
        ]
    )

    assert required_inputs_sound(prior, ["cve_analyst", "bloat_detective"])


def test_failed_input_fails_the_gate() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("cve_analyst", "failed"),
            _outcome("bloat_detective", "analysed"),
        ]
    )

    assert not required_inputs_sound(prior, ["cve_analyst", "bloat_detective"])


def test_missing_input_fails_the_gate() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("cve_analyst", "analysed"),
        ]
    )

    assert not required_inputs_sound(prior, ["cve_analyst", "bloat_detective"])


def test_skipped_no_input_is_trustworthy() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("cve_analyst", "skipped_no_input"),
        ]
    )

    assert required_inputs_sound(prior, ["cve_analyst"])


def test_missing_inputs_are_named() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("a", "analysed"),
            _outcome("b", "timed_out"),
        ]
    )

    assert missing_inputs(prior, ["a", "b", "c"]) == ["b", "c"]


def test_confidence_is_the_sound_fraction() -> None:
    prior = outcomes_by_agent(
        [
            _outcome("a", "analysed"),
            _outcome("b", "analysed"),
            _outcome("c", "failed"),
            _outcome("d", "timed_out"),
        ]
    )

    assert input_confidence(prior, ["a", "b", "c", "d"]) == 0.5


def test_confidence_of_no_inputs_is_zero() -> None:
    assert input_confidence({}, []) == 0.0
