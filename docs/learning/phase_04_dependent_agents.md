# Phase 4 — Dependent Agents, the Fan-In & Degraded Inputs

Four more agents. Two of them cannot run in parallel, and understanding *why* is the whole phase.

```text
                     Docker image
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
     TRIVY          DOCKER HISTORY     IMAGE INSPECT
        │                 │                 │
        ▼                 ▼                 ▼
 RawVulnerability[]  ImageLayer[]     ImageProfile
        │                 │                 │
        └────────┬────────┴────────┬────────┘
                 │                 │
    ┌────────┬───┴────┬────────────┴───┐
    ▼        ▼        ▼                ▼
  ┌─────┐ ┌─────┐ ┌────────┐  ┌────────────┐
  │ CVE │ │BLOAT│ │  BASE  │  │ COMPLIANCE │      FAN OUT
  │     │ │     │ │ IMAGE  │  │            │      (independent)
  └──┬──┘ └──┬──┘ └───┬────┘  └─────┬──────┘
     │       │        │             │
     └───────┴────┬───┴─────────────┘
                  ▼
         ┌──────────────────┐
         │   TRUST GATE     │                     FAN IN
         │ are inputs sound │                     (dependent)
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │   DOCKERFILE     │
         │   OPTIMIZER      │
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │   RISK SCORER    │
         │  + confidence    │
         └────────┬─────────┘
                  ▼
             ScanOutcome
```

The rule for this phase:

```text
parallelism is a property of your
data dependencies, not a setting
```

And its consequence, which is the harder half:

```text
a dependent agent running on degraded input
must never produce confident output
```

---

# 1. Draw the graph before writing code

Ask one question per agent: *what does it read?*

```text
CVE analyst        ← vulnerabilities                    independent
Bloat detective    ← layers                             independent
Base image         ← image profile                      independent
Compliance         ← image profile + layers             independent
                      ↓
Dockerfile opt     ← CVE + bloat + base image + layers  DEPENDENT
Risk scorer        ← everything above                   DEPENDENT
```

The first four read different raw inputs and never read each other. They fan out.

The optimizer needs to know which CVEs to patch, which layers waste space, and which base image to move to, before it can write a better Dockerfile. It waits.

The scorer needs all of it. It waits last.

You did not choose this shape. The data did. Map dependencies first and the `gather` calls write themselves.

---

# 2. Third data source: image inspect

Create:

```text
worker/app/scanners/image_inspect.py
```

```python
import json

from app.scanners.docker_history import (
    DockerHistoryError,
    _run,
    ensure_image_present,
)


async def run_image_inspect(target: str) -> dict:
    await ensure_image_present(target)

    code, stdout, stderr = await _run(
        ["docker", "image", "inspect", target]
    )

    if code != 0:
        raise DockerHistoryError(
            f"docker image inspect exited {code}: {stderr.decode()[:300]}"
        )

    payload = json.loads(stdout)

    if not payload:
        raise DockerHistoryError(
            f"Empty inspect output for {target}"
        )

    return payload[0]
```

`docker image inspect` returns a JSON **array** even for one image. Taking `[0]` without checking for empty is how you get an `IndexError` at 2am.

---

# 3. Model the image profile

Create:

```text
worker/app/processors/profile.py
```

```python
from pydantic import BaseModel

from app.processors.layers import ImageLayer, total_size


class ImageProfile(BaseModel):
    target: str
    os_family: str
    os_name: str
    base_reference: str
    user: str
    exposed_ports: list[int]
    env_keys: list[str]
    entrypoint: list[str]
    cmd: list[str]
    has_healthcheck: bool
    layer_count: int
    total_size_bytes: int


def _parse_ports(exposed: dict | None) -> list[int]:
    ports = []

    for key in exposed or {}:
        raw = key.split("/")[0]

        if raw.isdigit():
            ports.append(int(raw))

    return sorted(ports)


def _env_keys(env: list[str] | None) -> list[str]:
    return [
        entry.split("=", 1)[0]
        for entry in (env or [])
        if "=" in entry
    ]


def build_profile(
    target: str,
    inspect_data: dict,
    trivy_data: dict,
    layers: list[ImageLayer],
) -> ImageProfile:
    config = inspect_data.get("Config") or {}
    os_meta = (trivy_data.get("Metadata") or {}).get("OS") or {}

    base_reference = ""

    for layer in layers:
        if layer.command.startswith("FROM "):
            base_reference = layer.command[5:].strip()
            break

    fallback = f"{os_meta.get('Family', '')}:{os_meta.get('Name', '')}"

    return ImageProfile(
        target=target,
        os_family=os_meta.get("Family", "unknown"),
        os_name=os_meta.get("Name", "unknown"),
        base_reference=base_reference or fallback,
        user=config.get("User") or "root",
        exposed_ports=_parse_ports(config.get("ExposedPorts")),
        env_keys=_env_keys(config.get("Env")),
        entrypoint=config.get("Entrypoint") or [],
        cmd=config.get("Cmd") or [],
        has_healthcheck=bool(config.get("Healthcheck")),
        layer_count=len(layers),
        total_size_bytes=total_size(layers),
    )
```

---

# 4. Why `env_keys` and not `env`

Look closely at `_env_keys`. It keeps names and discards values.

```text
input:   AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
stored:  AWS_SECRET_ACCESS_KEY
```

The compliance agent needs to know an environment variable named `AWS_SECRET_ACCESS_KEY` exists in the image. It does not need the credential, and sending it would put a live secret into a third-party API request, that provider's logs, and possibly a training set.

```text
the model needs the fact
not the secret
```

Trivy's secret scanner already flags the values locally, in Phase 1, with no network call. Use the local deterministic tool for the sensitive part and the model for the reasoning part.

Apply this everywhere: **before any field crosses into a prompt, ask whether the model needs the value or only its existence.**

`config.get("User") or "root"` encodes the same defensive instinct. An empty `User` in Docker means root. Defaulting to `"root"` rather than `""` means the compliance agent sees the true state rather than a blank it might read as "not applicable".

---

# 5. Collapse the agent boilerplate

You are about to write four more agents identical in shape to the two you have. Six copies of the same twelve lines is the point at which you extract.

Create:

```text
worker/app/agents/runner.py
```

```python
import json
import logging
from typing import Callable, TypeVar

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AgentError(RuntimeError):
    pass


def _client() -> ChatOpenAI:
    return ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )


def parse_structured(
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
        raise AgentError(
            f"{agent_name}: schema validation failed "
            f"with {exc.error_count()} errors"
        ) from exc

    if guard is not None:
        guard(parsed)

    return parsed


async def run_structured_agent(
    *,
    agent_name: str,
    system_prompt: str,
    user_content: str,
    response_model: type[T],
    guard: Callable[[T], None] | None = None,
) -> T:
    response = await _client().ainvoke(
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
```

The `guard` parameter is the generalisation of Phase 2's hallucination check. Every agent passes a small function that verifies the model's output against known-good input.

Now rewrite the CVE analyst on top of it:

```python
from app.agents.runner import AgentError, run_structured_agent


async def run_cve_analyst(
    vulnerabilities: list[RawVulnerability],
) -> CVEAnalysisResult:
    if not vulnerabilities:
        return CVEAnalysisResult(
            status="skipped_no_input",
            findings=[],
            vulnerabilities_examined=0,
        )

    prioritised = prioritise(vulnerabilities)
    allowed = {item.id for item in prioritised}

    def guard(analysis: CVEAnalysis) -> None:
        unknown = {
            f.vulnerability_id for f in analysis.findings
        } - allowed

        if unknown:
            raise AgentError(
                f"cve_analyst: invented vulnerability IDs "
                f"{sorted(unknown)[:5]}"
            )

    payload = json.dumps(
        [v.model_dump() for v in prioritised],
        indent=2,
    )

    analysis = await run_structured_agent(
        agent_name="cve_analyst",
        system_prompt=CVE_ANALYST_PROMPT,
        user_content=(
            f"Trivy scan results as JSON:\n\n{payload}\n\n"
            "Analyse these and return the JSON object."
        ),
        response_model=CVEAnalysis,
        guard=guard,
    )

    return CVEAnalysisResult(
        status="analysed",
        findings=analysis.findings,
        vulnerabilities_examined=len(prioritised),
    )
```

Do the same for the bloat detective. Your Phase 2 and 3 tests need exactly one change: `CVEAnalysisError` becomes `AgentError`. Everything else passes untouched.

Three repetitions is when you extract. Not one — premature abstraction on a single example gives you the wrong shape.

---

# 6. Two more independent agents

Add to `app/agents/prompts.py`:

```python
BASE_IMAGE_PROMPT = """You are a Base Image Strategist for container images.

You receive a profile of a Docker image: its base reference, OS, size, layer
count, and runtime configuration. Recommend a better base image.

Consider, roughly in order of preference:

1. Distroless or Chainguard images when the runtime allows it.
2. Alpine when the workload has no glibc dependency.
3. The -slim variant of the current base.
4. A newer patch release of the same base.

For each recommendation, state honestly what breaks. Alpine uses musl, which
breaks manylinux wheels and some compiled extensions. Distroless has no shell,
which breaks exec-based debugging and shell-form CMD.

Do not recommend a base image that cannot run the observed entrypoint or cmd.

Respond with a single JSON object:

{
  "current_base": "the base reference from the input",
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "title": "short summary, max 140 chars",
      "impact": "what staying on the current base costs",
      "fix": "the exact FROM line to use",
      "effort": "trivial" | "moderate" | "involved",
      "recommended_base": "python:3.12-slim",
      "estimated_savings_bytes": 380000000,
      "breaking_risk": "what may break and how to verify",
      "priority": 87
    }
  ]
}

Return no other fields. Return no prose outside the JSON object."""


COMPLIANCE_PROMPT = """You are a Compliance Checker for container images,
auditing against the CIS Docker Benchmark sections 4 and 5.

Check these controls:

- 4.1  A non-root USER is set.
- 4.3  No unnecessary packages. Compilers, editors, network tools, or package
       managers left in a runtime image.
- 4.6  A HEALTHCHECK instruction is present.
- 4.7  No standalone update instruction. RUN apt-get update without an install
       in the same layer produces a stale cache.
- 4.9  COPY is used rather than ADD, unless remote fetch or auto-extract is
       genuinely needed.
- 4.10 No secrets in the image. Environment variable NAMES suggesting
       credentials, keys, tokens, or passwords.
- 5.8  No privileged ports exposed. Anything below 1024.

You are given environment variable NAMES only, never their values. Judge by
the name. A variable named DATABASE_PASSWORD is a finding regardless of value.

Report only controls that FAIL. Do not report passing controls.

Respond with a single JSON object:

{
  "findings": [
    {
      "control_id": "4.1",
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "title": "short summary, max 140 chars",
      "impact": "the concrete risk of this failing",
      "fix": "the exact instruction to add or change",
      "effort": "trivial" | "moderate" | "involved",
      "evidence": "the specific value from the input that proves the failure",
      "priority": 87
    }
  ]
}

Return no other fields. Return no prose outside the JSON object."""
```

Add the models to `app/models/findings.py`:

```python
class BaseImageFinding(BaseFinding):
    category: Literal["base_image"] = "base_image"
    recommended_base: str = Field(min_length=1)
    estimated_savings_bytes: int = Field(ge=0)
    breaking_risk: str = Field(min_length=1)


class ComplianceFinding(BaseFinding):
    category: Literal["compliance"] = "compliance"
    control_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)


class BaseImageAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_base: str
    findings: list[BaseImageFinding]


class ComplianceAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[ComplianceFinding]
```

Now the two agents. Both are short, because `run_structured_agent` does the work.

Create `worker/app/agents/base_image_strategist.py`:

```python
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
```

Create `worker/app/agents/compliance_checker.py`:

```python
import json
from typing import Literal

from pydantic import BaseModel

from app.agents.prompts import COMPLIANCE_PROMPT
from app.agents.runner import AgentError, run_structured_agent
from app.models.findings import ComplianceAnalysis, ComplianceFinding
from app.processors.layers import ImageLayer
from app.processors.profile import ImageProfile

KNOWN_CONTROLS = {
    "4.1",
    "4.3",
    "4.6",
    "4.7",
    "4.9",
    "4.10",
    "5.8",
}


class ComplianceResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[ComplianceFinding]


def _guard(analysis: ComplianceAnalysis) -> None:
    unknown = {
        f.control_id for f in analysis.findings
    } - KNOWN_CONTROLS

    if unknown:
        raise AgentError(
            f"compliance_checker: invented control IDs {sorted(unknown)}"
        )


async def run_compliance_checker(
    profile: ImageProfile,
    layers: list[ImageLayer],
) -> ComplianceResult:
    analysis = await run_structured_agent(
        agent_name="compliance_checker",
        system_prompt=COMPLIANCE_PROMPT,
        user_content=(
            "Image profile:\n\n"
            f"{json.dumps(profile.model_dump(), indent=2)}\n\n"
            "Layer history:\n\n"
            f"{json.dumps([l.model_dump() for l in layers], indent=2)}\n\n"
            "Report failing controls. Return the JSON object."
        ),
        response_model=ComplianceAnalysis,
        guard=_guard,
    )

    return ComplianceResult(
        status="analysed",
        findings=analysis.findings,
    )
```

Same one-line set subtraction, third time. That is the pattern now — any agent that emits an identifier gets a guard that checks the identifier was real.

---

# 7. The dependent agent problem

Here is the situation Phase 3 set up but did not solve.

```text
CVE analyst        →  failed
Bloat detective    →  analysed, 12 findings
Base image         →  analysed, 2 findings
Compliance         →  analysed, 5 findings
                          ↓
              Dockerfile optimizer
                          ↓
        writes an "optimized" Dockerfile
        that patches no vulnerabilities
        because it never saw any
```

The output *looks* authoritative. It is a complete, plausible, syntactically valid Dockerfile. A user copies it and ships an image with eleven hundred unpatched CVEs, because one upstream agent timed out and nothing downstream knew.

The scorer is worse. It reports `overall: 82` built on two of four inputs, and 82 is a number people act on.

```text
degraded input + confident output
      = the most dangerous
        thing this system can do
```

---

# 8. Build the trust gate

Add to `app/models/outcomes.py`:

```python
AgentStatus = Literal[
    "analysed",
    "skipped_no_input",
    "skipped_degraded_input",
    "failed",
    "timed_out",
]
```

Create:

```text
worker/app/agents/trust.py
```

```python
from app.models.outcomes import AgentOutcome


def outcomes_by_agent(
    outcomes: list[AgentOutcome],
) -> dict[str, AgentOutcome]:
    return {outcome.agent: outcome for outcome in outcomes}


def required_inputs_sound(
    outcomes: dict[str, AgentOutcome],
    required: list[str],
) -> bool:
    return all(
        name in outcomes and outcomes[name].is_trustworthy
        for name in required
    )


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
        1
        for name in inputs
        if name in outcomes and outcomes[name].is_trustworthy
    )

    return round(sound / len(inputs), 2)
```

Two different policies for two different agents.

**The optimizer refuses.** It cannot produce a partially-correct Dockerfile — a Dockerfile is a single artifact that is either safe to ship or not. If its required inputs are unsound, it returns `skipped_degraded_input` and produces nothing.

**The scorer degrades.** A risk score built on three of four inputs is still useful, as long as it says so. It runs and attaches a computed confidence figure.

Choosing between refuse and degrade is a judgement about the artifact:

```text
can a consumer of this output act
safely on a partial version of it?

Dockerfile              →  no   →  refuse
score with confidence   →  yes  →  degrade
```

---

# 9. The Dockerfile optimizer

Add to `app/agents/prompts.py`:

```python
DOCKERFILE_OPTIMIZER_PROMPT = """You are a Dockerfile Optimizer.

You receive an image's layer history plus findings from other agents:
vulnerabilities, bloat, and base image recommendations. Reconstruct the
Dockerfile and produce an improved version.

Rules for the rewrite:

1. Apply the recommended base image if one was given.
2. Combine related RUN instructions and clean package caches in the SAME layer.
3. Remove build tooling and development dependencies from the runtime stage.
   Use a multi-stage build when a compiler is genuinely needed.
4. Add a non-root USER.
5. Add a HEALTHCHECK if a service port is exposed.
6. Never carry an ENV containing a credential into the output. Replace it with
   a build argument or a comment pointing at runtime secret injection.
7. Order instructions so rarely-changing layers come first, for cache reuse.

The reconstructed Dockerfile is inferred from layer history and will be
imperfect. State that in reconstruction_notes. Never claim it is exact.

Respond with a single JSON object:

{
  "reconstructed": "the inferred original Dockerfile",
  "optimized": "the improved Dockerfile",
  "reconstruction_notes": "what you inferred and what is uncertain",
  "changes": [
    {
      "instruction": "the line you changed",
      "rationale": "why",
      "addresses": ["cve", "bloat", "compliance"]
    }
  ]
}

Return no other fields. Return no prose outside the JSON object."""
```

Add to `app/models/findings.py`:

```python
class DockerfileChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    instruction: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    addresses: list[str] = []


class DockerfileOptimization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reconstructed: str
    optimized: str
    reconstruction_notes: str
    changes: list[DockerfileChange]
```

Create `worker/app/agents/dockerfile_optimizer.py`:

```python
import json
import logging
from typing import Literal, Optional

from pydantic import BaseModel

from app.agents.prompts import DOCKERFILE_OPTIMIZER_PROMPT
from app.agents.runner import run_structured_agent
from app.agents.trust import missing_inputs, required_inputs_sound
from app.models.findings import DockerfileOptimization
from app.models.outcomes import AgentOutcome
from app.processors.layers import ImageLayer

logger = logging.getLogger(__name__)

REQUIRED_INPUTS = [
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
]


class DockerfileResult(BaseModel):
    status: Literal["analysed", "skipped_degraded_input"]
    optimization: DockerfileOptimization | None = None
    skipped_because: list[str] = []


async def run_dockerfile_optimizer(
    layers: list[ImageLayer],
    prior: dict[str, AgentOutcome],
) -> DockerfileResult:
    if not required_inputs_sound(prior, REQUIRED_INPUTS):
        unsound = missing_inputs(prior, REQUIRED_INPUTS)

        logger.warning(
            "Skipping dockerfile optimizer, unsound inputs: %s",
            unsound,
        )

        return DockerfileResult(
            status="skipped_degraded_input",
            optimization=None,
            skipped_because=unsound,
        )

    findings = [
        finding.model_dump()
        for name in REQUIRED_INPUTS
        for finding in prior[name].findings
    ]

    optimization = await run_structured_agent(
        agent_name="dockerfile_optimizer",
        system_prompt=DOCKERFILE_OPTIMIZER_PROMPT,
        user_content=(
            "Layer history:\n\n"
            f"{json.dumps([l.model_dump() for l in layers], indent=2)}\n\n"
            "Findings from prior agents:\n\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Return the JSON object."
        ),
        response_model=DockerfileOptimization,
    )

    return DockerfileResult(
        status="analysed",
        optimization=optimization,
        skipped_because=[],
    )
```

The prompt's rule 6 deserves a note. The optimizer sees layer commands, and layer commands contain `ENV DATABASE_PASSWORD=hunter2` verbatim. We cannot strip that the way we stripped env values in section 4, because the command *is* the thing being rewritten. So the instruction is explicit: never carry a credential into the output. Trivy's secret scanner catches it locally regardless.

---

# 10. The risk scorer, and where confidence comes from

Add to `app/agents/prompts.py`:

```python
RISK_SCORER_PROMPT = """You are a Risk Scorer for container images.

You receive all findings from prior analysis agents. Produce four scores from
0 to 100, where 100 is perfect and 0 is unusable.

- security:    driven by exploitable vulnerabilities, weighted by priority
- efficiency:  driven by wasted bytes relative to total image size
- compliance:  driven by failed CIS controls, weighted by severity
- overall:     a weighted blend. Security carries the heaviest weight.

Then write a two-sentence summary an engineering manager can act on, and list
the three highest-value actions in order.

Be willing to give low scores. An image with active critical CVEs running as
root should score below 30. Do not cluster everything between 60 and 80.

Do NOT output a confidence value. Confidence is computed separately.

Respond with a single JSON object:

{
  "overall": 0-100,
  "security": 0-100,
  "efficiency": 0-100,
  "compliance": 0-100,
  "summary": "two sentences",
  "top_priorities": ["action one", "action two", "action three"]
}

Return no other fields. Return no prose outside the JSON object."""
```

Add to `app/models/findings.py`:

```python
class RiskScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overall: int = Field(ge=0, le=100)
    security: int = Field(ge=0, le=100)
    efficiency: int = Field(ge=0, le=100)
    compliance: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1)
    top_priorities: list[str]


class ScoredRisk(BaseModel):
    score: RiskScore
    confidence: float = Field(ge=0.0, le=1.0)
    inputs_used: list[str]
    inputs_missing: list[str]
```

Create `worker/app/agents/risk_scorer.py`:

```python
import json

from app.agents.prompts import RISK_SCORER_PROMPT
from app.agents.runner import run_structured_agent
from app.agents.trust import input_confidence, missing_inputs
from app.models.findings import RiskScore, ScoredRisk
from app.models.outcomes import AgentOutcome

SCORER_INPUTS = [
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
    "compliance_checker",
]


async def run_risk_scorer(
    prior: dict[str, AgentOutcome],
) -> ScoredRisk:
    confidence = input_confidence(prior, SCORER_INPUTS)

    missing = missing_inputs(prior, SCORER_INPUTS)

    used = [
        name for name in SCORER_INPUTS if name not in missing
    ]

    findings = [
        finding.model_dump()
        for name in used
        for finding in prior[name].findings
    ]

    score = await run_structured_agent(
        agent_name="risk_scorer",
        system_prompt=RISK_SCORER_PROMPT,
        user_content=(
            f"Findings from {len(used)} of {len(SCORER_INPUTS)} agents:\n\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Return the JSON object."
        ),
        response_model=RiskScore,
    )

    return ScoredRisk(
        score=score,
        confidence=confidence,
        inputs_used=used,
        inputs_missing=missing,
    )
```

Notice the prompt explicitly forbids the model from reporting confidence.

```text
confidence is a property of the pipeline
not an opinion of the model
```

A model asked how confident it is will produce a plausible number uncorrelated with whether its inputs were complete. Here it is `sound_inputs / total_inputs` — deterministic, auditable, correct by construction.

Contrast the reference implementation, which computes:

```python
estimatedFixTime = len(all_findings) * 2
```

and renders it in the UI as though it were measured. If a number appears in your output it should either come from data or be labelled an estimate. Inventing metrics because a dashboard has an empty card is how trust dies.

---

# 11. Rewrite the orchestrator

Open `worker/app/orchestrator.py`. Extend `ScanOutcome` in `app/models/outcomes.py` first:

```python
class ScanOutcome(BaseModel):
    target: str
    outcomes: list[AgentOutcome]
    profile: ImageProfile | None = None
    dockerfile: DockerfileResult | None = None
    risk: ScoredRisk | None = None
```

Then the orchestrator body:

```python
async def run_scan(target: str) -> ScanOutcome:
    trivy_raw, history_raw, inspect_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
        run_image_inspect(target),
    )

    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)
    profile = build_profile(target, inspect_raw, trivy_raw, layers)

    # ---- fan out: four independent agents ----

    names = [
        "cve_analyst",
        "bloat_detective",
        "base_image_strategist",
        "compliance_checker",
    ]

    results = await asyncio.gather(
        asyncio.wait_for(
            _timed(names[0], run_cve_analyst(vulnerabilities)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        asyncio.wait_for(
            _timed(names[1], run_bloat_detective(layers)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        asyncio.wait_for(
            _timed(names[2], run_base_image_strategist(profile)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        asyncio.wait_for(
            _timed(names[3], run_compliance_checker(profile, layers)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        return_exceptions=True,
    )

    outcomes = [
        _degrade(name, result)
        if isinstance(result, BaseException)
        else result
        for name, result in zip(names, results)
    ]

    prior = outcomes_by_agent(outcomes)

    # ---- fan in: dependent agents, sequential ----

    dockerfile = None

    try:
        dockerfile = await asyncio.wait_for(
            run_dockerfile_optimizer(layers, prior),
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        outcomes.append(
            AgentOutcome(
                agent="dockerfile_optimizer",
                status=dockerfile.status,
                findings=[],
            )
        )
    except (asyncio.TimeoutError, AgentError) as exc:
        outcomes.append(_degrade("dockerfile_optimizer", exc))

    risk = None

    try:
        risk = await asyncio.wait_for(
            run_risk_scorer(prior),
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        outcomes.append(
            AgentOutcome(
                agent="risk_scorer",
                status="analysed",
                findings=[],
            )
        )
    except (asyncio.TimeoutError, AgentError) as exc:
        outcomes.append(_degrade("risk_scorer", exc))

    return ScanOutcome(
        target=target,
        outcomes=outcomes,
        profile=profile,
        dockerfile=dockerfile,
        risk=risk,
    )
```

The dependent agents sit outside the `gather`, each with its own `try`. They run sequentially by necessity, so `return_exceptions=True` has nothing to isolate — a plain `except` is the right tool there.

Note `prior` is built from the fan-out outcomes only. The optimizer must not be able to read the scorer, and building the dict once, before the fan-in, makes that structurally impossible rather than a matter of discipline.

---

# 12. Tests

Create:

```text
worker/tests/test_trust.py
```

```python
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
    prior = outcomes_by_agent([
        _outcome("cve_analyst", "analysed"),
        _outcome("bloat_detective", "skipped_no_input"),
    ])

    assert required_inputs_sound(
        prior, ["cve_analyst", "bloat_detective"]
    )


def test_failed_input_fails_the_gate() -> None:
    prior = outcomes_by_agent([
        _outcome("cve_analyst", "failed"),
        _outcome("bloat_detective", "analysed"),
    ])

    assert not required_inputs_sound(
        prior, ["cve_analyst", "bloat_detective"]
    )


def test_missing_input_fails_the_gate() -> None:
    prior = outcomes_by_agent([
        _outcome("cve_analyst", "analysed"),
    ])

    assert not required_inputs_sound(
        prior, ["cve_analyst", "bloat_detective"]
    )


def test_skipped_no_input_is_trustworthy() -> None:
    prior = outcomes_by_agent([
        _outcome("cve_analyst", "skipped_no_input"),
    ])

    assert required_inputs_sound(prior, ["cve_analyst"])


def test_missing_inputs_are_named() -> None:
    prior = outcomes_by_agent([
        _outcome("a", "analysed"),
        _outcome("b", "timed_out"),
    ])

    assert missing_inputs(prior, ["a", "b", "c"]) == ["b", "c"]


def test_confidence_is_the_sound_fraction() -> None:
    prior = outcomes_by_agent([
        _outcome("a", "analysed"),
        _outcome("b", "analysed"),
        _outcome("c", "failed"),
        _outcome("d", "timed_out"),
    ])

    assert input_confidence(prior, ["a", "b", "c", "d"]) == 0.5


def test_confidence_of_no_inputs_is_zero() -> None:
    assert input_confidence({}, []) == 0.0
```

```powershell
uv run pytest tests/test_trust.py -v
```

`test_skipped_no_input_is_trustworthy` is the subtle one. An agent that skipped because the image was clean produced a *correct* result. It must pass the gate — otherwise every scan of a clean image would refuse to produce a Dockerfile.

---

# 13. Run it

Update `app/scripts/scan_full.py`:

```python
    if scan.risk:
        print(f"overall:    {scan.risk.score.overall}/100")
        print(f"security:   {scan.risk.score.security}/100")
        print(f"efficiency: {scan.risk.score.efficiency}/100")
        print(f"compliance: {scan.risk.score.compliance}/100")
        print(f"confidence: {scan.risk.confidence:.0%}")

        if scan.risk.inputs_missing:
            print(f"missing:    {', '.join(scan.risk.inputs_missing)}")

        print()
        print(scan.risk.score.summary)

    if scan.dockerfile and scan.dockerfile.status == "skipped_degraded_input":
        print()
        print(
            "Dockerfile skipped, unsound inputs: "
            f"{', '.join(scan.dockerfile.skipped_because)}"
        )
```

```powershell
uv run python -m app.scripts.scan_full python:3.8
```

Now force a degraded run. Temporarily point one agent at a model that does not exist:

```python
CVE_MODEL = "gpt-4o-does-not-exist"
```

Run again. You should see:

```text
  cve_analyst             failed                    0 findings
  bloat_detective         analysed                 12 findings
  base_image_strategist   analysed                  2 findings
  compliance_checker      analysed                  6 findings
  dockerfile_optimizer    skipped_degraded_input
  risk_scorer             analysed

confidence: 75%
missing:    cve_analyst

Dockerfile skipped, unsound inputs: cve_analyst
```

The optimizer refused. The scorer ran and said 75%. Nothing produced a confident wrong answer.

Restore the model name.

---

# 14. Quality gate

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
uv run python -m app.scripts.scan_full python:3.8
```

You should have:

```text
✓ Six agents, four parallel and two sequential
✓ Shape determined by the dependency graph, not preference
✓ Shared runner, one place for JSON mode and validation
✓ Guards on every agent that emits an identifier
✓ Secrets never enter a prompt, only their names
✓ Optimizer refuses on degraded input
✓ Scorer degrades and reports computed confidence
✓ ~30 tests, none touching the network
```

---

# 15. Where this sits

```text
   Phase 1        Phase 2        Phase 3            Phase 4  ◄── here
 ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────────┐
 │ scanners │─→│ 1 agent  │─→│ 2 parallel │─→│ 6 agents         │
 │ reduction│  │ contract │  │ isolation  │  │ fan-out + fan-in │
 └──────────┘  └──────────┘  └────────────┘  └──────────────────┘
                                                       │
                                                       ▼
                                              ┌──────────────────┐
                                              │     Phase 5      │
                                              │  does it work?   │
                                              └──────────────────┘
```

The AI system is now feature-complete. Every remaining phase either measures it or wraps it.

---

# Errata — found while implementing this phase

**`response.content` should be `response.text`** in the shared runner — same reason as
Phase 2.

**`"priority": 1-100` is not valid JSON**, in both schema blocks. See the Phase 2 errata.

**Use `X | None`, not `Optional[X]`.** Ruff's UP045 flags `Optional` on this Python version
and the rest of the codebase has none of it.

**`DockerfileResult` cannot live in `app/agents/dockerfile_optimizer.py`** if
`ScanOutcome` references it: that module imports `app.models.outcomes` for `AgentOutcome`,
so the reverse import is a cycle. Put it in `app/models/findings.py` next to
`DockerfileOptimization`.

**`schema validation failed with N errors` is not a debuggable message.** Include the
failing field paths — `exc.errors()[:4]` is enough. The missing-`priority` bug above was
invisible for two phases behind the bare count.

---

## Next: Phase 5 — The Evaluation Harness

You have six agents producing confident, well-typed output. You have no idea whether any of it is correct.

```text
              known-bad image
              known-good image
                     │
                     ▼
            ┌─────────────────┐
            │  GOLDEN FILE    │
            │  expectations   │
            └────────┬────────┘
                     ▼
              run the scan
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    RECALL      PRECISION     STABILITY
  did it find   did it        same input,
  the planted   invent        same answer
  problems      anything      across 5 runs
```

We build the deliberately terrible Dockerfile, enumerate exactly what a correct scanner must find in it, and turn that into a test suite that fails when a prompt regresses.

The uncomfortable part of Phase 5: you will discover at least one agent is worse than you think. Everyone does. That is the entire reason the phase exists, and it is why the original project's README claims a Ragas evaluation layer that was never built.