from app.models.outcomes import AgentOutcome


def outcomes_by_agent(
    outcomes: list[AgentOutcome],
) -> dict[str, AgentOutcome]:
    """Index a list of agent outcomes by agent name."""
    return {outcome.agent: outcome for outcome in outcomes}


def required_inputs_sound(
    outcomes: dict[str, AgentOutcome],
    required: list[str],
) -> bool:
    """Report whether every named input agent produced usable output.

    Trustworthy is stricter than 'did not raise': an agent that timed out
    or was skipped returns no findings, and treating that as 'found
    nothing' is how a broken scan scores clean.
    """
    return all(name in outcomes and outcomes[name].is_trustworthy for name in required)


def missing_inputs(
    outcomes: dict[str, AgentOutcome],
    required: list[str],
) -> list[str]:
    """Name the required agents whose output cannot be trusted.

    The list is what the UI shows, so a degraded report can say which
    evidence is absent instead of just claiming lower confidence.
    """
    return [
        name
        for name in required
        if name not in outcomes or not outcomes[name].is_trustworthy
    ]


def input_confidence(
    outcomes: dict[str, AgentOutcome],
    inputs: list[str],
) -> float:
    """Return the fraction of an agent's inputs that were trustworthy.

    Confidence is computed from what actually ran, never asked of the
    model - a model's opinion of its own certainty is not evidence.
    """
    if not inputs:
        return 0.0

    sound = sum(
        1 for name in inputs if name in outcomes and outcomes[name].is_trustworthy
    )

    return round(sound / len(inputs), 2)
