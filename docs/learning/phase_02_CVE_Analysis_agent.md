# Phase 2 — The CVE Analyst Agent: Structured Output & Fail-Loud Parsing

Phase 1 gave us a deterministic, tested, boring scanner. Now we add the first component that can be *wrong*.

The pipeline for this phase:

```text
              RawVulnerability[]
                      │
                      ▼
              ┌───────────────┐
              │  EMPTY GUARD  │──── no input ──→ skipped_no_input
              └───────┬───────┘
                      │
                      ▼
                 PRIORITISE
                      │
                      ▼
              ┌───────────────┐
              │  SYSTEM PROMPT│
              │   + contract  │
              └───────┬───────┘
                      │
                      ▼
                   MODEL
              response_format:
                 json_object
                      │
                      ▼
              ┌───────────────┐
              │ SCHEMA        │
              │ VALIDATION    │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ HALLUCINATION │
              │ GUARD         │
              └───────┬───────┘
                      │
            ┌─────────┴─────────┐
            ▼                   ▼
         valid               invalid
            │                   │
            ▼                   ▼
       Finding[]         CVEAnalysisError
        status:              (raise)
       "analysed"
```

The rule this phase exists to enforce:

```text
a parse failure and a clean image
must never produce the same result
```

In the reference implementation they do. Both return `[]`. Which means a malformed model response reports a vulnerable image as clean, silently, with a green score on the dashboard. That is the worst possible failure mode for a security tool, and we're going to make it structurally impossible.

---

# 1. Install the dependencies

```powershell
uv add langchain-openai langchain-core
```

```powershell
uv add --dev pytest-asyncio
```

Add to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

Without that line every async test silently no-ops instead of running. Pytest will report them as passed.

---

# 2. Set your API key

PowerShell, current session only:

```powershell
$env:OPENAI_API_KEY = "sk-..."
```

PowerShell, persisted for your user:

```powershell
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-...", "User")
```

The persisted version needs a new terminal before it takes effect.

Verify:

```powershell
$env:OPENAI_API_KEY.Substring(0,7)
```

---

# 3. Define the output contract first

This ordering matters. Write the schema, *then* write the prompt from the schema.

The reverse — prompt first, then figure out what came back — is how you end up with the string-surgery parsing we're replacing.

Create:

```text
worker/app/models/findings.py
```

```powershell
mkdir app\models
New-Item app\models\__init__.py -ItemType File
```

```python
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.processors.vulnerabilities import Severity

Effort = Literal[
    "trivial",
    "moderate",
    "involved",
]

Exploitability = Literal[
    "actively_exploited",
    "likely",
    "unlikely",
    "theoretical",
]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1, max_length=140)
    impact: str = Field(min_length=1)
    fix: str = Field(min_length=1)
    effort: Effort
    exploitability: Exploitability
    priority: int = Field(ge=1, le=100)


class CVEAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]
```

Three details in there are doing real work.

`extra="forbid"` means a model that invents an extra field fails validation instead of quietly passing it through.

`Literal` types mean `effort` can only ever be one of three strings. A model that returns `"easy"` fails loudly rather than polluting your data with a fourth category you never planned for.

`Field(ge=1, le=100)` means a priority of `9000` is rejected at the boundary, not discovered three screens later in the UI.

---

# 4. Why the envelope exists

Notice `CVEAnalysis` wraps a list rather than being one.

That isn't stylistic. OpenAI's JSON mode requires the response be a **JSON object**. You cannot ask for a bare top-level array.

```text
{"findings": [...]}   ← valid
[...]                 ← rejected
```

So the envelope is forced by the API. Given that, use it: later phases will add `analysis_notes` and `regression_summary` alongside `findings` without a breaking change.

---

# 5. Agent configuration

Open:

```text
worker/app/config/scanning.py
```

Add:

```python
CVE_MODEL = "gpt-4o"

CVE_TEMPERATURE = 0.0

CVE_TIMEOUT_SECONDS = 90
```

The model name lives in config so you can swap it without touching agent code. You will want to, either to cut cost or to try a newer model.

While developing, drop your limit:

```python
MAX_VULNERABILITIES_TO_MODEL = 25
```

`python:3.8` produces well over a thousand vulnerabilities. At 150 per call you're paying a few cents every time you run the script, and you'll run it twenty times today. Raise it back before the quality gate.

---

# 6. Write the system prompt

Create:

```text
worker/app/agents/prompts.py
```

```powershell
mkdir app\agents
New-Item app\agents\__init__.py -ItemType File
```

```python
CVE_ANALYST_PROMPT = """You are a CVE Analysis Agent for container images.

You receive vulnerabilities discovered by Trivy in a Docker image. Your job is
to turn raw scanner output into prioritised, actionable findings for an engineer
who must decide what to fix first.

For each vulnerability you report:

1. Judge real exploitability, not just the CVSS number. A critical CVE in a
   library that is installed but never loaded at runtime is lower priority than
   a high CVE in the request path.
2. Set priority from 1 to 100, where 100 means fix today. Use the full range.
   Do not cluster everything at 90.
3. State the concrete impact in one sentence. What can an attacker actually do.
4. Give the exact fix. Prefer the fixed package version from the scan data.
   If no fix version exists, say so and give the mitigation.
5. Estimate effort as trivial, moderate, or involved.

Hard rules:

- Report ONLY vulnerabilities present in the input data.
- NEVER invent a CVE ID. Every vulnerability_id you return must appear verbatim
  in the input.
- If the input contains no vulnerabilities, return {"findings": []}.
- Do not pad the response to seem thorough.

Respond with a single JSON object matching this schema exactly:

{
  "findings": [
    {
      "vulnerability_id": "CVE-2023-1234",
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "title": "short summary, max 140 chars",
      "impact": "one sentence on what an attacker gains",
      "fix": "exact remediation step",
      "effort": "trivial" | "moderate" | "involved",
      "exploitability": "actively_exploited" | "likely" | "unlikely" | "theoretical",
      "priority": 1-100
    }
  ]
}

Return no other fields. Return no prose outside the JSON object."""
```

Two things about this prompt are load-bearing.

**The word "JSON" must appear in your messages.** OpenAI's `json_object` mode rejects the request outright if it doesn't. It's a real API constraint and the error message is not obvious.

**The anti-hallucination rule is stated twice** — once as "report ONLY what's present" and once as "NEVER invent a CVE ID." Section 11 then enforces it in Python, because a rule in a prompt is a request, not a guarantee.

---

# 7. Build the model client

Create:

```text
worker/app/agents/cve_analyst.py
```

```python
import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import ValidationError

from app.agents.prompts import CVE_ANALYST_PROMPT
from app.config.scanning import (
    CVE_MODEL,
    CVE_TEMPERATURE,
    CVE_TIMEOUT_SECONDS,
)
from app.models.findings import CVEAnalysis, Finding
from app.processors.vulnerabilities import RawVulnerability, prioritise

logger = logging.getLogger(__name__)


class CVEAnalysisError(RuntimeError):
    pass


def _build_client() -> ChatOpenAI:
    return ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        model_kwargs={
            "response_format": {"type": "json_object"},
        },
    )
```

`response_format` is the line that deletes an entire category of bug.

```text
without it:
    model returns ```json\n{...}\n```
    you write string surgery to strip fences
    a model that adds prose breaks it
    a bare except returns []

with it:
    the API guarantees a parseable JSON object
    json.loads works, always
```

`temperature=0.0` means the same image produces the same findings. Reproducibility is not optional in a security tool — an engineer needs to know whether a finding disappeared because they fixed it or because the model felt different today.

---

# 8. Write the parser — three outcomes, not two

Add to the same file:

```python
def parse_analysis(
    raw_content: str,
    allowed_ids: set[str],
) -> list[Finding]:
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise CVEAnalysisError(
            f"Model returned non-JSON content: {exc}"
        ) from exc

    try:
        analysis = CVEAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise CVEAnalysisError(
            f"Model response failed schema validation: {exc.error_count()} errors"
        ) from exc

    returned_ids = {
        finding.vulnerability_id
        for finding in analysis.findings
    }

    hallucinated = returned_ids - allowed_ids

    if hallucinated:
        raise CVEAnalysisError(
            "Model returned vulnerability IDs absent from scan input: "
            f"{sorted(hallucinated)[:5]}"
        )

    return analysis.findings
```

Read the three failure branches. Each one **raises**. None of them returns an empty list.

That is the entire point of this phase.

```text
findings == []          →  the image is clean
CVEAnalysisError raised →  we do not know anything
```

Those are different states and the code now says so.

---

# 9. The hallucination guard

Section 8's third check is worth dwelling on.

The prompt tells the model not to invent CVE IDs. That's a request. This is enforcement:

```python
hallucinated = returned_ids - allowed_ids
```

Every ID the model returned must have appeared in the input we sent it. Set subtraction, one line, deterministic.

```text
model asserts            →  Python verifies
prompt rule              →  code guarantee
```

Whenever you can check a model's output against a known-good set, do it in Python. Prompts shape behaviour; they don't constrain it.

This same pattern generalises: if a model cites sources, verify the URLs were in the input. If it references line numbers, verify they exist.

---

# 10. Write the agent

Add:

```python
from typing import Literal

from pydantic import BaseModel


class CVEAnalysisResult(BaseModel):
    status: Literal["analysed", "skipped_no_input"]
    findings: list[Finding]
    vulnerabilities_examined: int


def _build_messages(
    vulnerabilities: list[RawVulnerability],
) -> list:
    payload = json.dumps(
        [item.model_dump() for item in vulnerabilities],
        indent=2,
    )

    return [
        SystemMessage(content=CVE_ANALYST_PROMPT),
        HumanMessage(
            content=(
                "Trivy scan results as JSON:\n\n"
                f"{payload}\n\n"
                "Analyse these and return the JSON object."
            )
        ),
    ]


async def run_cve_analyst(
    vulnerabilities: list[RawVulnerability],
) -> CVEAnalysisResult:
    if not vulnerabilities:
        logger.info("No vulnerabilities found, skipping model call")

        return CVEAnalysisResult(
            status="skipped_no_input",
            findings=[],
            vulnerabilities_examined=0,
        )

    prioritised = prioritise(vulnerabilities)

    allowed_ids = {item.id for item in prioritised}

    response = await _build_client().ainvoke(
        _build_messages(prioritised)
    )

    findings = parse_analysis(
        response.content,
        allowed_ids,
    )

    logger.info(
        "CVE analyst produced %d findings from %d vulnerabilities",
        len(findings),
        len(prioritised),
    )

    return CVEAnalysisResult(
        status="analysed",
        findings=findings,
        vulnerabilities_examined=len(prioritised),
    )
```

---

# 11. Why the empty guard comes first

```python
if not vulnerabilities:
    return CVEAnalysisResult(status="skipped_no_input", ...)
```

Three reasons, in order of importance.

**It makes "clean" explicit.** Downstream code reads `status`, not `len(findings)`. A clean image and a skipped agent are now distinguishable in the data itself.

**It prevents invention.** Hand a model an empty list and ask it to analyse vulnerabilities and it will often help by producing plausible-sounding CVEs. The safest prompt is the one you never send.

**It's free.** Alpine images routinely scan clean. Not calling the API is the cheapest possible optimisation.

Note the `status` field is what the orchestrator in Phase 4 will branch on. Design your result types so callers never have to infer state from a length check.

---

# 12. Run it

Create:

```text
worker/app/scripts/analyse_once.py
```

```python
import asyncio
import sys

from app.agents.cve_analyst import run_cve_analyst
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    raw = await run_trivy_scan(target)

    vulnerabilities = extract_vulnerabilities(raw)

    result = await run_cve_analyst(vulnerabilities)

    print(f"status:    {result.status}")
    print(f"examined:  {result.vulnerabilities_examined}")
    print(f"findings:  {len(result.findings)}")
    print()

    for finding in sorted(
        result.findings,
        key=lambda item: -item.priority,
    )[:5]:
        print(f"[{finding.priority:3d}] {finding.vulnerability_id}  ({finding.severity})")
        print(f"       {finding.title}")
        print(f"       fix: {finding.fix}")
        print(f"       effort: {finding.effort} | {finding.exploitability}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
```

Run against a vulnerable image:

```powershell
uv run python -m app.scripts.analyse_once python:3.8
```

Then a clean one:

```powershell
uv run python -m app.scripts.analyse_once alpine:3.20
```

Expected:

```text
python:3.8   →  status: analysed           findings: 20+
alpine:3.20  →  status: skipped_no_input   findings: 0
```

The second one should return instantly and cost nothing. If it takes ten seconds, your empty guard isn't firing.

---

# 13. Break it on purpose

This is the most valuable five minutes in the phase.

Temporarily comment out the `response_format` line:

```python
def _build_client() -> ChatOpenAI:
    return ChatOpenAI(
        model=CVE_MODEL,
        temperature=CVE_TEMPERATURE,
        timeout=CVE_TIMEOUT_SECONDS,
        # model_kwargs={"response_format": {"type": "json_object"}},
    )
```

Run it a few times against `python:3.8`. Sooner or later the model wraps its answer in markdown fences or adds a sentence of preamble, and you get:

```text
CVEAnalysisError: Model returned non-JSON content: Expecting value: line 1 column 1
```

Now imagine that same run with the reference implementation's handling:

```python
except Exception:
    return []
```

The scan completes. The dashboard shows zero vulnerabilities. The image has eleven hundred.

Restore the line. You now understand why it's there.

---

# 14. Add tests

Create:

```text
worker/tests/test_cve_analyst.py
```

```python
import json

import pytest

from app.agents.cve_analyst import (
    CVEAnalysisError,
    parse_analysis,
    run_cve_analyst,
)

ALLOWED = {"CVE-2023-0001", "CVE-2023-0002"}


def _finding(vuln_id: str = "CVE-2023-0001") -> dict:
    return {
        "vulnerability_id": vuln_id,
        "severity": "high",
        "title": "OpenSSL buffer overflow",
        "impact": "Remote attacker can crash the TLS handshake.",
        "fix": "Upgrade openssl to 1.1.1w",
        "effort": "trivial",
        "exploitability": "likely",
        "priority": 85,
    }


def test_valid_response_parses() -> None:
    content = json.dumps({"findings": [_finding()]})

    findings = parse_analysis(content, ALLOWED)

    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2023-0001"
    assert findings[0].priority == 85


def test_empty_findings_is_valid() -> None:
    content = json.dumps({"findings": []})

    assert parse_analysis(content, ALLOWED) == []


def test_malformed_json_raises() -> None:
    with pytest.raises(CVEAnalysisError, match="non-JSON"):
        parse_analysis("```json\n{\"findings\": []}\n```", ALLOWED)


def test_missing_required_field_raises() -> None:
    broken = _finding()
    del broken["fix"]

    with pytest.raises(CVEAnalysisError, match="schema validation"):
        parse_analysis(json.dumps({"findings": [broken]}), ALLOWED)


def test_invalid_enum_value_raises() -> None:
    broken = _finding()
    broken["effort"] = "easy"

    with pytest.raises(CVEAnalysisError, match="schema validation"):
        parse_analysis(json.dumps({"findings": [broken]}), ALLOWED)


def test_out_of_range_priority_raises() -> None:
    broken = _finding()
    broken["priority"] = 9000

    with pytest.raises(CVEAnalysisError, match="schema validation"):
        parse_analysis(json.dumps({"findings": [broken]}), ALLOWED)


def test_extra_field_raises() -> None:
    broken = _finding()
    broken["confidence"] = 0.9

    with pytest.raises(CVEAnalysisError, match="schema validation"):
        parse_analysis(json.dumps({"findings": [broken]}), ALLOWED)


def test_hallucinated_cve_raises() -> None:
    invented = _finding("CVE-9999-0000")

    with pytest.raises(CVEAnalysisError, match="absent from scan input"):
        parse_analysis(json.dumps({"findings": [invented]}), ALLOWED)


async def test_empty_input_skips_model_entirely() -> None:
    result = await run_cve_analyst([])

    assert result.status == "skipped_no_input"
    assert result.findings == []
    assert result.vulnerabilities_examined == 0
```

Run:

```powershell
uv run pytest tests/test_cve_analyst.py -v
```

Nine tests, no API calls, no network, sub-second.

That last test is the important one structurally: it proves the empty path never reaches the model. It runs without an API key set, which is how you know.

And notice `test_malformed_json_raises` uses markdown fences as its input. That's the exact failure the reference implementation swallows. Here it's a passing test asserting an exception.

---

# 15. Run the quality gate

Restore your production limit first:

```python
MAX_VULNERABILITIES_TO_MODEL = 150
```

Then:

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

Live runs:

```powershell
uv run python -m app.scripts.analyse_once python:3.8
```

```powershell
uv run python -m app.scripts.analyse_once alpine:3.20
```

You should have:

```text
✓ Model output is structurally guaranteed JSON
✓ Every field validated against a closed schema
✓ Invented CVE IDs rejected in Python, not trusted from the prompt
✓ Parse failure raises, never returns empty
✓ Clean images skip the model call entirely
✓ 15 tests total across both phases, none touching the network
```

---

# 16. Where this sits

```text
                   Phase 1                      Phase 2  ◄── you are here
        ┌──────────────────────────┐   ┌──────────────────────────┐
        │  TRIVY  →  REDUCTION     │──→│  CVE ANALYST → Finding[] │
        └──────────────────────────┘   └──────────────────────────┘
                                                    │
                                                    ▼
                                             ┌─────────────┐
                                             │  Phase 3    │
                                             │  more agents│
                                             └─────────────┘
```

You now have one agent with a hard contract. That contract is the template — every agent from here copies this shape:

```text
typed input  →  empty guard  →  prompt  →  json_object
             →  schema validation  →  deterministic guard  →  typed output
             →  raise on anything unexpected
```

---

## Next: Phase 3 — Parallel Agents & Failure Isolation

We add a second agent that reads image layers instead of vulnerabilities, then run both at once:

```text
                  Scan data
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   ┌─────────────┐         ┌─────────────┐
   │ CVE ANALYST │         │    BLOAT    │
   │             │         │  DETECTIVE  │
   └──────┬──────┘         └──────┬──────┘
          │                       │
          │      asyncio.gather   │
          │  return_exceptions=True
          │                       │
          └───────────┬───────────┘
                      ▼
              ┌───────────────┐
              │ isinstance    │
              │ BaseException │
              └───────┬───────┘
                      │
            ┌─────────┴─────────┐
            ▼                   ▼
        Finding[]         degrade to []
                          + log warning
```

The rule for Phase 3:

```text
one agent failing must never
cancel the other three
```

That sounds obvious. Getting it wrong is a single missing keyword argument, and the failure mode is that your entire scan dies because one model call timed out. We'll also cover why `return_exceptions=True` and the `isinstance` checks are only safe as a pair — using either one alone is worse than using neither.