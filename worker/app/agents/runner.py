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
