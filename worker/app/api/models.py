from pydantic import BaseModel, ConfigDict, Field

# An OCI reference, or the upload:// marker app/images.py resolves.
#
# Requiring an alphanumeric FIRST character is the point: `target` becomes an
# argv element of `trivy image ... <target>` and `docker pull <target>`, and
# both cobra and Trivy parse flags positionally-anywhere. A target of
# "--server=https://attacker/" is a flag, not an image. The `--` separators in
# app/scanners/ are the other half of this fix; either alone is thinner than
# it looks.
#
# A plain string, not re.compile: pydantic hands this to the Rust regex crate,
# which spells the end anchor `\z` where Python spells it `\Z` and rejects
# look-around outright. Compiling it here too would mean writing a pattern
# both engines accept, for a Python match nothing performs.
_TARGET = r"\A(?:upload://[A-Za-z0-9._-]{1,128}|[A-Za-z0-9][A-Za-z0-9._:/@-]*)\z"

# repo_id had only a length bound while target next to it was carefully
# constrained. It is the right-hand half of the results GSI partition key
# ("{tenant_id}#{repo_id}") and it is interpolated into a URL path by the
# frontend, so `/`, `#` and `..` in it are a correctness problem in two
# places at once. Cross-tenant collision was never reachable - tenant_id is
# a Cognito sub and carries no `#`, so the key still parses from the left -
# but a tenant could confuse its own history. See docs/audits/audit-02-frontend-worker-observability.md F10.
_REPO_ID = r"\A[A-Za-z0-9][A-Za-z0-9._:/-]*\z"


class StartScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: str = Field(min_length=1, max_length=200, pattern=_REPO_ID)
    target: str = Field(min_length=1, max_length=300, pattern=_TARGET)


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

    # True when the job says `running` but no worker has renewed its lease.
    #
    # There is no reaper, so a job whose worker died - or whose message went
    # to the DLQ - used to read "in progress" for the full 30-day TTL, which
    # is indistinguishable from a slow scan. The lease answers it: nobody is
    # working on this. See docs/audits/audit-01-backend.md P3-10.
    #
    # Reported rather than rewritten to `failed`, because a redelivery can
    # still pick it up and the row would then be wrong in the other
    # direction. Optional and defaulted, so an older client ignores it.
    stale: bool = False
