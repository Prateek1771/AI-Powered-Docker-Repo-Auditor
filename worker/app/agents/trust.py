from app.models.outcomes import AgentOutcome


def outcomes_by_agent(
    outcomes: list[AgentOutcome],
) -> dict[str, AgentOutcome]:
    return {outcome.agent: outcome for outcome in outcomes}


def required_inputs_sound(
    outcomes: dict[str, AgentOutcome],
    required: list[str],
) -> bool:
    return all(name in outcomes and outcomes[name].is_trustworthy for name in required)


def missing_inputs(
    outcomes: dict[str, AgentOutcome],
    required: list[str],
) -> list[str]:
    return [
        name
        for name in required
        if name not in outcomes or not outcomes[name].is_trustworthy
    ]


def input_confidence(
    outcomes: dict[str, AgentOutcome],
    inputs: list[str],
) -> float:
    if not inputs:
        return 0.0

    sound = sum(
        1 for name in inputs if name in outcomes and outcomes[name].is_trustworthy
    )

    return round(sound / len(inputs), 2)
