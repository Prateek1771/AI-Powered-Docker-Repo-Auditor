# Phase 3 — Parallel Agents, Visible Degradation & Failure Isolation

One agent is a function call. Two agents is an architecture.

What we're building:

```text
                        Docker image
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
        TRIVY SCANNER               DOCKER HISTORY
              │                             │
              ▼                             ▼
      RawVulnerability[]              ImageLayer[]
              │                             │
              ▼                             ▼
      ┌───────────────┐            ┌───────────────┐
      │  CVE ANALYST  │            │     BLOAT     │
      │               │            │   DETECTIVE   │
      └───────┬───────┘            └───────┬───────┘
              │                             │
              │      asyncio.gather         │
              │   return_exceptions=True    │
              │                             │
              └──────────────┬──────────────┘
                             ▼
                    ┌─────────────────┐
                    │  isinstance     │
                    │  BaseException  │
                    └────────┬────────┘
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
              AgentOutcome         AgentOutcome
              status:              status:
              "analysed"           "failed"
                   │                   │
                   └─────────┬─────────┘
                             ▼
                        ScanResult
```

The rule for this phase:

```text
one agent failing must never
cancel the others
and must never be invisible
```

That second clause is the one people miss. Phase 2 established that a parse failure must not look like a clean image. Phase 3 makes agents degrade gracefully, which *reintroduces* that risk — unless the degradation is recorded in the data. We handle both.

---

# 1. Pull the image locally

Trivy pulls into its own cache, not into your Docker daemon. `docker history` needs the image in the daemon.

```powershell
docker pull python:3.8
```

```powershell
docker pull alpine:3.20
```

---

# 2. Create the history scanner

Create:

```text
worker/app/scanners/docker_history.py
```

```python
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

HISTORY_TIMEOUT_SECONDS = 60


class DockerHistoryError(RuntimeError):
    pass


async def _run(command: list[str]) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=HISTORY_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()

        raise DockerHistoryError(
            f"Command timed out: {' '.join(command)}"
        )

    return process.returncode, stdout, stderr


async def ensure_image_present(target: str) -> None:
    code, _, _ = await _run(
        ["docker", "image", "inspect", target]
    )

    if code == 0:
        return

    logger.info("Image not local, pulling: %s", target)

    code, _, stderr = await _run(
        ["docker", "pull", target]
    )

    if code != 0:
        raise DockerHistoryError(
            f"Could not pull {target}: {stderr.decode()[:300]}"
        )


async def run_docker_history(target: str) -> list[dict]:
    await ensure_image_present(target)

    code, stdout, stderr = await _run(
        [
            "docker",
            "history",
            "--no-trunc",
            "--format",
            "{{json .}}",
            target,
        ]
    )

    if code != 0:
        raise DockerHistoryError(
            f"docker history exited {code}: {stderr.decode()[:300]}"
        )

    entries = []

    for line in stdout.decode().splitlines():
        if line.strip():
            entries.append(json.loads(line))

    return entries
```

Two things to notice.

`--no-trunc` matters. Without it Docker truncates the `CreatedBy` command to about 45 characters, and the command is the entire signal the bloat agent works from. A truncated `RUN apt-get install …` tells you nothing.

The output is **NDJSON**, not JSON. One object per line, no enclosing array. `json.loads` on the whole blob fails; you parse line by line. This trips people constantly with Docker and Kubernetes tooling.

---

# 3. Parse sizes deterministically

Docker reports sizes as human strings: `0B`, `77.8MB`, `1.2GB`. You need integers.

Create:

```text
worker/app/processors/layers.py
```

```python
import re

from pydantic import BaseModel

_SIZE_UNITS = {
    "B": 1,
    "KB": 10**3,
    "MB": 10**6,
    "GB": 10**9,
    "TB": 10**12,
}

_SIZE_PATTERN = re.compile(
    r"^([0-9]*\.?[0-9]+)\s*([KMGT]?B)$"
)


def parse_size(value: str) -> int:
    match = _SIZE_PATTERN.match(value.strip().upper())

    if match is None:
        raise ValueError(
            f"Unrecognised Docker size string: {value!r}"
        )

    amount, unit = match.groups()

    return int(float(amount) * _SIZE_UNITS[unit])
```

Docker uses **SI units**, base 1000, not 1024. `1kB` is 1000 bytes. Get this wrong and every size you report is off by 2.4% per unit, which compounds and makes your bloat numbers quietly wrong.

Note this raises rather than returning 0 on an unknown format. Same principle as Phase 2 — an unparseable size and a zero-byte layer are different facts.

---

# 4. Model the layers

Add to the same file:

```python
class ImageLayer(BaseModel):
    index: int
    command: str
    size_bytes: int
    is_empty: bool


_NOP_MARKER = "#(nop)"

_BUILDKIT_PREFIX = "RUN /bin/sh -c "


def _clean_command(raw: str) -> str:
    command = raw.strip()

    if _NOP_MARKER in command:
        command = command.split(_NOP_MARKER, 1)[1].strip()

    if command.startswith("/bin/sh -c "):
        command = "RUN " + command[len("/bin/sh -c "):]

    if command.startswith(_BUILDKIT_PREFIX):
        command = "RUN " + command[len(_BUILDKIT_PREFIX):]

    return command.strip()


def extract_layers(
    history_entries: list[dict],
) -> list[ImageLayer]:
    layers: list[ImageLayer] = []

    ordered = list(reversed(history_entries))

    for index, entry in enumerate(ordered):
        size = parse_size(entry.get("Size", "0B"))

        layers.append(
            ImageLayer(
                index=index,
                command=_clean_command(
                    entry.get("CreatedBy", "")
                ),
                size_bytes=size,
                is_empty=size == 0,
            )
        )

    return layers


def total_size(layers: list[ImageLayer]) -> int:
    return sum(layer.size_bytes for layer in layers)
```

`reversed()` is not cosmetic. `docker history` prints newest layer first; a Dockerfile reads oldest first. If you skip the reversal, every layer index the agent reports points at the wrong instruction, and the fix it suggests edits the wrong line.

`_clean_command` strips Docker's build noise so the model sees something close to the original Dockerfile line. Less noise in, less confusion out — the same reduction principle from Phase 1.

---

# 5. Test the parsing before writing the agent

Create:

```text
worker/tests/test_layers.py
```

```python
import pytest

from app.processors.layers import (
    extract_layers,
    parse_size,
    total_size,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0B", 0),
        ("512B", 512),
        ("77.8MB", 77_800_000),
        ("1.2GB", 1_200_000_000),
        ("245kB", 245_000),
    ],
)
def test_parse_size(value: str, expected: int) -> None:
    assert parse_size(value) == expected


def test_parse_size_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_size("about 3 gigs")


def test_layers_are_reversed_to_dockerfile_order() -> None:
    history = [
        {"CreatedBy": "CMD [\"python\"]", "Size": "0B"},
        {"CreatedBy": "/bin/sh -c apt-get install -y curl", "Size": "45MB"},
        {"CreatedBy": "#(nop) FROM debian:11", "Size": "120MB"},
    ]

    layers = extract_layers(history)

    assert layers[0].command == "FROM debian:11"
    assert layers[0].index == 0
    assert layers[2].command.startswith("CMD")


def test_empty_layers_flagged() -> None:
    history = [{"CreatedBy": "#(nop) ENV PATH=/usr/bin", "Size": "0B"}]

    layers = extract_layers(history)

    assert layers[0].is_empty is True


def test_total_size() -> None:
    history = [
        {"CreatedBy": "a", "Size": "10MB"},
        {"CreatedBy": "b", "Size": "5MB"},
    ]

    assert total_size(extract_layers(history)) == 15_000_000
```

```powershell
uv run pytest tests/test_layers.py -v
```

Deterministic code gets tested first and thoroughly. The agent sitting on top of it is probabilistic, and you cannot debug a probabilistic layer while the layer beneath it is also suspect.

---

# 6. Generalise the finding contract

We have a second agent producing findings of a different shape. Time to split the model.

Open:

```text
worker/app/models/findings.py
```

Replace `Finding` with:

```python
class BaseFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    title: str = Field(min_length=1, max_length=140)
    impact: str = Field(min_length=1)
    fix: str = Field(min_length=1)
    effort: Effort
    priority: int = Field(ge=1, le=100)


class CVEFinding(BaseFinding):
    category: Literal["cve"] = "cve"
    vulnerability_id: str = Field(min_length=1)
    exploitability: Exploitability


class BloatFinding(BaseFinding):
    category: Literal["bloat"] = "bloat"
    layer_index: int = Field(ge=0)
    wasted_bytes: int = Field(ge=0)
    root_cause_command: str = Field(min_length=1)


class CVEAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[CVEFinding]


class BloatAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[BloatFinding]
```

Then in `app/agents/cve_analyst.py`, change the import and the return type:

```python
from app.models.findings import CVEAnalysis, CVEFinding
```

```python
def parse_analysis(
    raw_content: str,
    allowed_ids: set[str],
) -> list[CVEFinding]:
```

```python
class CVEAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[CVEFinding]
    vulnerabilities_examined: int
```

The `category` field with a default is what lets you merge both lists later and still tell them apart. A literal with a default is free discrimination — the model never sets it, Pydantic always does.

Your Phase 2 tests still pass unchanged. That's the point of having written them.

---

# 7. The bloat detective prompt

Add to:

```text
worker/app/agents/prompts.py
```

```python
BLOAT_DETECTIVE_PROMPT = """You are a Bloat Detective Agent for container images.

You receive the layer history of a Docker image: the instruction that created
each layer and the bytes it added. Your job is to find wasted space and explain
exactly which instruction caused it.

Look for:

1. Package manager caches left in the image. On Debian, apt lists not removed
   in the same RUN that installed them. On Alpine, apk cache without --no-cache.
2. Build toolchains present at runtime. Compilers, headers, build-essential.
3. Development dependencies in a production image. Test runners, linters,
   notebooks, debuggers.
4. Files added in one layer and deleted in a later one. Deleting in a later
   layer does not reclaim the space, it only hides the file.
5. Whole-context copies. COPY . . that pulls in .git, tests, and local config.

For each finding:

- layer_index is the index given in the input. Do not invent indexes.
- wasted_bytes is your estimate of reclaimable bytes. Be conservative.
  If you cannot estimate, use the layer's own size.
- root_cause_command must be the instruction as given in the input.
- fix must be a concrete rewrite of that instruction.
- priority from 1 to 100 by bytes reclaimed weighted by how easy the fix is.

Hard rules:

- Report ONLY layers present in the input.
- NEVER invent a layer_index.
- If no bloat is present, return {"findings": []}.
- Do not report a layer merely for being large. FROM layers are expected to be
  large. Report only avoidable waste.

Respond with a single JSON object:

{
  "findings": [
    {
      "layer_index": 3,
      "severity": "medium",
      "title": "short summary, max 140 chars",
      "impact": "what this costs in pulls, storage, and attack surface",
      "fix": "the rewritten instruction",
      "effort": "trivial" | "moderate" | "involved",
      "wasted_bytes": 45000000,
      "root_cause_command": "RUN apt-get install -y curl",
      "priority": 1-100
    }
  ]
}

Return no other fields. Return no prose outside the JSON object."""
```

Same structure as the CVE prompt: role, criteria, hard rules, explicit schema, the word JSON. The "do not report a layer merely for being large" rule exists because without it every model flags the base image, which is not actionable.

---

# 8. The bloat detective agent

Create:

```text
worker/app/agents/bloat_detective.py
```

```python
import json
import logging
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from app.agents.prompts import BLOAT_DETECTIVE_PROMPT
from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
)
from app.models.findings import BloatAnalysis, BloatFinding
from app.processors.layers import ImageLayer

logger = logging.getLogger(__name__)


class BloatAnalysisError(RuntimeError):
    pass


class BloatAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[BloatFinding]
    layers_examined: int


def parse_bloat_analysis(
    raw_content: str,
    allowed_indexes: set[int],
) -> list[BloatFinding]:
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise BloatAnalysisError(
            f"Model returned non-JSON content: {exc}"
        ) from exc

    try:
        analysis = BloatAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise BloatAnalysisError(
            f"Model response failed schema validation: {exc.error_count()} errors"
        ) from exc

    returned = {
        finding.layer_index
        for finding in analysis.findings
    }

    unknown = returned - allowed_indexes

    if unknown:
        raise BloatAnalysisError(
            f"Model returned layer indexes absent from input: {sorted(unknown)[:5]}"
        )

    return analysis.findings


async def run_bloat_detective(
    layers: list[ImageLayer],
) -> BloatAnalysisResult:
    if not layers:
        return BloatAnalysisResult(
            status="skipped_no_input",
            findings=[],
            layers_examined=0,
        )

    payload = json.dumps(
        [layer.model_dump() for layer in layers],
        indent=2,
    )

    client = ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )

    response = await client.ainvoke(
        [
            SystemMessage(content=BLOAT_DETECTIVE_PROMPT),
            HumanMessage(
                content=(
                    "Image layer history as JSON:\n\n"
                    f"{payload}\n\n"
                    "Identify bloat and return the JSON object."
                )
            ),
        ]
    )

    findings = parse_bloat_analysis(
        response.content,
        {layer.index for layer in layers},
    )

    return BloatAnalysisResult(
        status="analysed",
        findings=findings,
        layers_examined=len(layers),
    )
```

Identical shape to the CVE analyst: empty guard, typed input, JSON mode, schema validation, deterministic guard against invention, raise on anything unexpected.

The guard here checks layer indexes instead of CVE IDs. Same one-line set subtraction. Once you have the pattern, every new agent takes twenty minutes.

---

# 9. Measure the sequential version first

Before optimising, get a number.

Create:

```text
worker/app/scripts/compare_timing.py
```

```python
import asyncio
import sys
import time

from app.agents.bloat_detective import run_bloat_detective
from app.agents.cve_analyst import run_cve_analyst
from app.processors.layers import extract_layers
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.docker_history import run_docker_history
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    trivy_raw, history_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
    )

    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)

    start = time.perf_counter()
    await run_cve_analyst(vulnerabilities)
    await run_bloat_detective(layers)
    sequential = time.perf_counter() - start

    start = time.perf_counter()
    await asyncio.gather(
        run_cve_analyst(vulnerabilities),
        run_bloat_detective(layers),
    )
    parallel = time.perf_counter() - start

    print(f"sequential: {sequential:.1f}s")
    print(f"parallel:   {parallel:.1f}s")
    print(f"speedup:    {sequential / parallel:.2f}x")


if __name__ == "__main__":
    asyncio.run(main())
```

```powershell
uv run python -m app.scripts.compare_timing python:3.8
```

Expect roughly:

```text
sequential: 41.2s
parallel:   23.8s
speedup:    1.73x
```

With two agents you get somewhere near 2x. At six agents in Phase 4 it approaches 6x, and that is the difference between a 30-second scan and a three-minute one.

Note the scanners at the top are already gathered. Trivy and `docker history` are independent, so they fan out too.

---

# 10. Why `return_exceptions=True`

The version in section 9 has a defect. Make one agent fail and watch.

```python
await asyncio.gather(
    run_cve_analyst(vulnerabilities),
    run_bloat_detective(layers),
)
```

If the bloat detective raises, `gather` immediately propagates that exception **and the CVE analyst is cancelled mid-flight**. You paid for the tokens. You get nothing.

```text
without the flag:
    one agent fails
        ↓
    gather raises
        ↓
    siblings cancelled
        ↓
    entire scan lost
```

Add the flag:

```python
results = await asyncio.gather(
    run_cve_analyst(vulnerabilities),
    run_bloat_detective(layers),
    return_exceptions=True,
)
```

Now every coroutine runs to completion, and failures come back as **exception objects sitting in the results list** rather than being raised.

---

# 11. Why the `isinstance` checks are mandatory

This is the part people get wrong, and getting it half-right is worse than not doing it at all.

With `return_exceptions=True`, this is now possible:

```python
cve_result, bloat_result = results
# bloat_result is a BloatAnalysisError instance, not a BloatAnalysisResult
```

Downstream you write something reasonable-looking:

```python
merged = []

for result in (cve_result, bloat_result):
    if isinstance(result, list):
        merged.extend(result)
```

An exception is not a list. It is silently skipped. No error, no log, no finding.

```text
return_exceptions=True  without  type checks
        ↓
exception flows downstream as data
        ↓
defensive code silently drops it
        ↓
silent data loss
```

Compare the three options honestly:

```text
no flag, no checks   →  scan dies loudly.        Bad, but you know.
flag, no checks      →  findings vanish quietly.  Worst outcome.
flag + checks        →  degrade and record it.    Correct.
```

The flag and the checks are a **pair**. Using either alone is a bug.

---

# 12. Make degradation visible

Here is the tension with Phase 2. There we said a failure must never look like a clean image. Now we're catching failures and continuing. Both cannot be true unless the failure is recorded.

Create:

```text
worker/app/models/outcomes.py
```

```python
from typing import Literal, Union

from pydantic import BaseModel

from app.models.findings import BloatFinding, CVEFinding

AgentStatus = Literal[
    "analysed",
    "skipped_no_input",
    "failed",
    "timed_out",
]


class AgentOutcome(BaseModel):
    agent: str
    status: AgentStatus
    findings: list[Union[CVEFinding, BloatFinding]] = []
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def is_trustworthy(self) -> bool:
        return self.status in ("analysed", "skipped_no_input")


class ScanOutcome(BaseModel):
    target: str
    outcomes: list[AgentOutcome]

    @property
    def all_findings(self) -> list[Union[CVEFinding, BloatFinding]]:
        return [
            finding
            for outcome in self.outcomes
            for finding in outcome.findings
        ]

    @property
    def degraded(self) -> bool:
        return any(
            not outcome.is_trustworthy
            for outcome in self.outcomes
        )
```

`degraded` is the field the UI reads. A scan with a failed CVE analyst shows "analysis incomplete", not "no vulnerabilities found".

```text
findings == [] and degraded is False  →  the image is clean
findings == [] and degraded is True   →  we do not know
```

Phase 2's rule survives contact with Phase 3 because the *status travels with the data*.

---

# 13. Build the orchestrator

Create:

```text
worker/app/orchestrator.py
```

```python
import asyncio
import logging
import time
from typing import Awaitable, Callable

from app.agents.bloat_detective import run_bloat_detective
from app.agents.cve_analyst import run_cve_analyst
from app.config.scanning import AGENT_TIMEOUT_SECONDS
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.processors.layers import extract_layers
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.docker_history import run_docker_history
from app.scanners.trivy import run_trivy_scan

logger = logging.getLogger(__name__)


async def _timed(
    name: str,
    coroutine: Awaitable,
) -> AgentOutcome:
    start = time.perf_counter()

    result = await coroutine

    return AgentOutcome(
        agent=name,
        status=result.status,
        findings=result.findings,
        duration_seconds=time.perf_counter() - start,
    )


def _degrade(
    name: str,
    error: BaseException,
) -> AgentOutcome:
    status = (
        "timed_out"
        if isinstance(error, asyncio.TimeoutError)
        else "failed"
    )

    logger.warning(
        "Agent %s %s: %s",
        name,
        status,
        error,
    )

    return AgentOutcome(
        agent=name,
        status=status,
        findings=[],
        error=str(error) or error.__class__.__name__,
    )


async def run_scan(target: str) -> ScanOutcome:
    trivy_raw, history_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
    )

    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)

    results = await asyncio.gather(
        asyncio.wait_for(
            _timed("cve_analyst", run_cve_analyst(vulnerabilities)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        asyncio.wait_for(
            _timed("bloat_detective", run_bloat_detective(layers)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        return_exceptions=True,
    )

    names = ["cve_analyst", "bloat_detective"]

    outcomes = [
        _degrade(name, result)
        if isinstance(result, BaseException)
        else result
        for name, result in zip(names, results)
    ]

    return ScanOutcome(target=target, outcomes=outcomes)
```

Add to `app/config/scanning.py`:

```python
AGENT_TIMEOUT_SECONDS = 120
```

---

# 14. Why `wait_for` goes inside `gather`

Order matters:

```python
asyncio.gather(
    asyncio.wait_for(agent_a(), timeout=120),   # each bounded
    asyncio.wait_for(agent_b(), timeout=120),
    return_exceptions=True,
)
```

not:

```python
asyncio.wait_for(
    asyncio.gather(agent_a(), agent_b()),       # one shared budget
    timeout=120,
)
```

Inside means each agent gets its own 120 seconds and a slow one doesn't consume another's budget. Outside means the whole batch shares one clock, and a slow first agent starves the rest.

The `return_exceptions=True` flag also converts `asyncio.TimeoutError` into a returned object rather than a raise, which is why `_degrade` can distinguish `timed_out` from `failed`.

---

# 15. Test the failure isolation

Create:

```text
worker/tests/test_orchestrator.py
```

```python
import asyncio

import pytest

from app.models.outcomes import AgentOutcome, ScanOutcome


def _outcome(name: str, status: str, count: int = 0) -> AgentOutcome:
    return AgentOutcome(
        agent=name,
        status=status,
        findings=[],
        error=None if status == "analysed" else "boom",
    )


def test_scan_is_degraded_when_an_agent_fails() -> None:
    scan = ScanOutcome(
        target="python:3.8",
        outcomes=[
            _outcome("cve_analyst", "analysed"),
            _outcome("bloat_detective", "failed"),
        ],
    )

    assert scan.degraded is True


def test_clean_scan_is_not_degraded() -> None:
    scan = ScanOutcome(
        target="alpine:3.20",
        outcomes=[
            _outcome("cve_analyst", "skipped_no_input"),
            _outcome("bloat_detective", "analysed"),
        ],
    )

    assert scan.degraded is False


def test_empty_findings_alone_does_not_mean_clean() -> None:
    degraded = ScanOutcome(
        target="python:3.8",
        outcomes=[_outcome("cve_analyst", "failed")],
    )

    clean = ScanOutcome(
        target="alpine:3.20",
        outcomes=[_outcome("cve_analyst", "skipped_no_input")],
    )

    assert degraded.all_findings == clean.all_findings == []
    assert degraded.degraded != clean.degraded


async def test_gather_isolates_failure() -> None:
    async def good() -> str:
        await asyncio.sleep(0.01)
        return "ok"

    async def bad() -> str:
        raise RuntimeError("boom")

    results = await asyncio.gather(
        good(),
        bad(),
        return_exceptions=True,
    )

    assert results[0] == "ok"
    assert isinstance(results[1], BaseException)


async def test_wait_for_produces_timeout_error() -> None:
    async def slow() -> str:
        await asyncio.sleep(5)
        return "never"

    results = await asyncio.gather(
        asyncio.wait_for(slow(), timeout=0.05),
        return_exceptions=True,
    )

    assert isinstance(results[0], asyncio.TimeoutError)
```

```powershell
uv run pytest tests/test_orchestrator.py -v
```

The third test is the important one. It asserts that two scans with identical `all_findings` are distinguishable by `degraded`. That single assertion is the whole safety property of this phase, written down.

---

# 16. Run the full scan

Create:

```text
worker/app/scripts/scan_full.py
```

```python
import asyncio
import sys

from app.orchestrator import run_scan


async def main() -> None:
    scan = await run_scan(sys.argv[1])

    print(f"target:   {scan.target}")
    print(f"degraded: {scan.degraded}")
    print()

    for outcome in scan.outcomes:
        print(
            f"  {outcome.agent:18} {outcome.status:18} "
            f"{len(outcome.findings):3d} findings  "
            f"{outcome.duration_seconds:5.1f}s"
        )
        if outcome.error:
            print(f"    error: {outcome.error}")

    print()

    for finding in sorted(
        scan.all_findings,
        key=lambda item: -item.priority,
    )[:8]:
        print(f"[{finding.priority:3d}] ({finding.category}) {finding.title}")
        print(f"       fix: {finding.fix}")


if __name__ == "__main__":
    asyncio.run(main())
```

```powershell
uv run python -m app.scripts.scan_full python:3.8
```

```powershell
uv run python -m app.scripts.scan_full alpine:3.20
```

Then force a failure. Temporarily set:

```python
AGENT_TIMEOUT_SECONDS = 2
```

Run it again. You should see:

```text
degraded: True

  cve_analyst        timed_out            0 findings    2.0s
    error: 
  bloat_detective    timed_out            0 findings    2.0s
```

Both agents fail, the scan still returns, and `degraded` is `True`. Restore the timeout to 120.

---

# 17. Quality gate

```powershell
uv run ruff check .
```

```powershell
uv run ruff format --check .
```

```powershell
uv run mypy app
```

```powershell
uv run pytest -v
```

```powershell
uv run python -m app.scripts.compare_timing python:3.8
```

You should have:

```text
✓ Two independent data sources, fetched in parallel
✓ Two agents, same contract shape, running concurrently
✓ Measured speedup, not assumed
✓ One agent failing cannot cancel the other
✓ Failures recorded as status, never as an empty list
✓ ~20 tests, only the scripts touch the network
```

---

# 18. Where this sits

```text
        Phase 1              Phase 2              Phase 3  ◄── here
   ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
   │ scanners  +  │───→│ one agent    │───→│ parallel agents  │
   │ reduction    │    │ hard contract│    │ + failure model  │
   └──────────────┘    └──────────────┘    └──────────────────┘
                                                     │
                                                     ▼
                                            ┌──────────────────┐
                                            │     Phase 4      │
                                            │ dependent agents │
                                            └──────────────────┘
```

The orchestrator is now the only place that knows about failure. Agents raise; the orchestrator decides what a raise means. Keep that boundary — the moment an agent starts catching its own exceptions and returning empty lists, you are back to invisible degradation.

---

## Next: Phase 4 — Dependent Agents & the Fan-In

Not every agent can run in parallel. Some need the output of others:

```text
   CVE  ·  BLOAT  ·  BASE IMAGE  ·  COMPLIANCE      ← fan out (independent)
                        │
                        ▼
              DOCKERFILE OPTIMIZER                   ← needs all four
                        │
                        ▼
                  RISK SCORER                        ← needs everything
                        │
                        ▼
                   ScanOutcome
```

We'll add two more independent agents, then the two sequential ones, and establish the rule that decides the shape:

```text
parallelism is a property of your
data dependencies, not a setting
```

Phase 4 also covers what a dependent agent does when its inputs are degraded. The optimizer receiving a failed CVE analysis must not silently produce a Dockerfile that looks authoritative, and the risk scorer must not report a confident 82 out of 100 built on two of four inputs.