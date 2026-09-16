from collections.abc import AsyncGenerator
from typing import Protocol

from pydantic import BaseModel

from app.storage.serialization import now_iso


class ProgressEvent(BaseModel):
    job_id: str
    status: str
    progress: int
    step: str
    at: str = ""

    # Which pipeline node this frame is about, and what it just became. Both
    # optional: a stage frame ("Running agents") names no node, and a client
    # that predates them keeps reading status/progress/step exactly as before.
    #
    # `node` is the orchestrator's own name for the step - "trivy",
    # "cve_analyst" - so the UI can key its graph off the same identifiers
    # AgentOutcome.agent already uses.
    node: str | None = None
    node_state: str | None = None

    @classmethod
    def create(
        cls,
        job_id: str,
        status: str,
        progress: int,
        step: str,
        node: str | None = None,
        node_state: str | None = None,
    ) -> "ProgressEvent":
        return cls(
            job_id=job_id,
            status=status,
            progress=progress,
            step=step,
            node=node,
            node_state=node_state,
            # now_iso() is datetime.now(UTC).isoformat() - timezone-aware, so
            # the browser reads a real instant rather than guessing local time.
            at=now_iso(),
        )


class ProgressBus(Protocol):
    async def publish(self, event: ProgressEvent) -> None: ...

    # AsyncGenerator, not AsyncIterator: the WS endpoint needs anext() to hand
    # create_task a real coroutine, and aclose() to run the unsubscribe on the
    # early-return path. Neither is on AsyncIterator.
    def listen(self, job_id: str) -> AsyncGenerator[ProgressEvent, None]: ...

    async def close(self) -> None: ...
