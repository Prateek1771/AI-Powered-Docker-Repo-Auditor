from pydantic import BaseModel, ConfigDict, Field


class StartScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=300)


class ScanAccepted(BaseModel):
    job_id: str
    status: str
    repo_id: str
    enqueued_at: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    current_step: str
    started_at: str
    updated_at: str
