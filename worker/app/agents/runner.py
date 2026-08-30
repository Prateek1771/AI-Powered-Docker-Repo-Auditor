import json
import logging
from collections.abc import Callable

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
    MODEL_MAX_RETRIES,
)

logger = logging.getLogger(__name__)


class AgentError(RuntimeError):
    pass


def build_client() -> ChatOpenAI:
    """Build the chat client every agent shares.

    JSON response format is requested at the API level rather than only
    asked for in the prompt, so a stray sentence around the object is not
    something the parser has to survive.
    """
    return ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        max_retries=MODEL_MAX_RETRIES,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )


def parse_structured[T: BaseModel](
    agent_name: str,
    raw_content: str,
    response_model: type[T],
    guard: Callable[[T], None] | None = None,
) -> T:
    """Parse a model reply into a schema, or raise saying why it failed.

    Bad JSON, a schema violation and a failed guard are three distinct
    errors and each names itself. None of them may become an empty result:
    'the model broke' and 'the image is clean' must never look alike.
    """
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise AgentError(
            f"{agent_name}: model returned non-JSON content: {exc}"
        ) from exc

    try:
        parsed = response_model.model_validate(payload)
    except ValidationError as exc:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors()[:4]
        )
        raise AgentError(
            f"{agent_name}: schema validation failed "
            f"with {exc.error_count()} errors ({detail})"
        ) from exc

    if guard is not None:
        guard(parsed)

    return parsed


async def run_structured_agent[T: BaseModel](
    *,
    agent_name: str,
    system_prompt: str,
    user_content: str,
    response_model: type[T],
    guard: Callable[[T], None] | None = None,
) -> T:
    """Call the model with one prompt and return a validated response.

    The shared body of every agent. `guard` is where an agent adds the
    check only it can make, such as refusing invented identifiers.
    """
    response = await build_client().ainvoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_content),
        ]
    )

    parsed = parse_structured(
        agent_name,
        response.text,
        response_model,
        guard,
    )

    logger.info("%s completed", agent_name)

    return parsed
