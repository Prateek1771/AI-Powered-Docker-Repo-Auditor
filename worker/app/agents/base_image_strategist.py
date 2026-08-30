import json
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import BASE_IMAGE_PROMPT
from app.agents.runner import run_structured_agent
from app.models.findings import BaseImageAnalysis, BaseImageFinding
from app.processors.profile import ImageProfile


class BaseImageResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[BaseImageFinding]
    current_base: str = ""


async def run_base_image_strategist(
    profile: ImageProfile,
) -> BaseImageResult:
    """Suggest a better base image and say what switching would cost.

    The saving is only half the answer, so the finding also carries the
    breaking risk - a recommendation without one is not actionable.
    """
    analysis = await run_structured_agent(
        agent_name="base_image_strategist",
        system_prompt=BASE_IMAGE_PROMPT,
        user_content=(
            "Image profile as JSON:\n\n"
            f"{json.dumps(profile.model_dump(), indent=2)}\n\n"
            "Recommend a better base image. Return the JSON object."
        ),
        response_model=BaseImageAnalysis,
    )

    return BaseImageResult(
        status="analysed",
        findings=analysis.findings,
        current_base=analysis.current_base,
    )
