# Phase 1 — Scanner Layer: Trivy Runner & Deterministic Reduction

Before any AI exists, the system needs a source of truth.

The pipeline we're building in this phase:

```text
                    Docker image
                         │
                         ▼
                   TRIVY RUNNER
                  (docker subprocess)
                         │
                         ▼
                  Raw JSON  (2–10 MB)
                         │
                         ▼
                    REDUCTION
                 (deterministic Python)
                         │
                         ▼
              Typed vulnerabilities (~80 KB)
                         │
                         ▼
                   PRIORITISATION
                         │
                         ▼
                 Top N by real severity
```

By the end of this phase you will have scanned a real image and cut its output by roughly 50x, with tests proving the cut is safe.

No LLM appears until Phase 2. That ordering is deliberate — the model is the last thing you add, not the first.

---

# 1. Create the project layout

```bash
mkdir -p docker-auditor/worker/app/{config,scanners,processors}
mkdir -p docker-auditor/worker/tests
cd docker-auditor/worker
```

Create the package markers:

```bash
touch app/__init__.py app/config/__init__.py app/scanners/__init__.py app/processors/__init__.py tests/__init__.py
```

Your tree:

```text
worker/
├── app/
│   ├── __init__.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── scanning.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── trivy.py
│   └── processors/
│       ├── __init__.py
│       └── vulnerabilities.py
└── tests/
    ├── __init__.py
    └── test_reduction.py
```

---

# 2. Set up the environment

```bash
uv init --no-workspace
uv add pydantic
uv add --dev pytest pytest-asyncio ruff mypy
```

If you don't have `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

# 3. Prime the Trivy cache

This is the single most important setup command in the project.

```bash
docker volume create trivy-cache
```

```bash
docker run --rm -v trivy-cache:/root/.cache/trivy \
  aquasec/trivy:latest image --download-db-only
```

That pulls a few hundred MB of CVE data **once**.

Without it, every scan you ever run re-downloads that database first:

```text
with cache:     ~90 seconds
without cache:  ~4 minutes
```

Later, in the production Dockerfile, this exact step becomes a `RUN` layer so the database is baked into the image at build time.

---

# 4. Create scanner configuration

Create:

```text
worker/app/config/scanning.py
```

```python
TRIVY_IMAGE = "aquasec/trivy:latest"

TRIVY_CACHE_VOLUME = "trivy-cache"

TRIVY_SCANNERS = "vuln,secret"

TRIVY_TIMEOUT_SECONDS = 600

MAX_VULNERABILITIES_TO_MODEL = 150

DESCRIPTION_TRUNCATE_CHARS = 200
```

Same principle as before: don't scatter

```python
600
150
200
```

through the codebase.

Every one of these is an operational limit. They belong in one file where you can see them together and reason about them together.

`TRIVY_SCANNERS` includes `secret` deliberately. That's the scanner that catches hardcoded credentials in `ENV` instructions, and we'll need it in Phase 5.

---

# 5. Create the Trivy runner

Create:

```text
worker/app/scanners/trivy.py
```

```python
import asyncio
import json
import logging

from app.config.scanning import (
    TRIVY_CACHE_VOLUME,
    TRIVY_IMAGE,
    TRIVY_SCANNERS,
    TRIVY_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class TrivyScanError(RuntimeError):
    pass


def build_command(target: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy",
        TRIVY_IMAGE,
        "image",
        "--format",
        "json",
        "--quiet",
        "--scanners",
        TRIVY_SCANNERS,
        "--timeout",
        "10m",
        target,
    ]


async def run_trivy_scan(target: str) -> dict:
    command = build_command(target)

    logger.info(
        "Starting Trivy scan: %s",
        target,
    )

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=TRIVY_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()

        raise TrivyScanError(
            f"Trivy scan timed out after {TRIVY_TIMEOUT_SECONDS}s: {target}"
        )

    if process.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited {process.returncode}: {stderr.decode()[:500]}"
        )

    if not stdout.strip():
        raise TrivyScanError(
            f"Trivy returned empty output for {target}"
        )

    return json.loads(stdout)
```

---

# 6. Why `create_subprocess_exec` and not `subprocess.run`

This is the first design decision worth defending.

The obvious version is:

```python
result = subprocess.run(command, capture_output=True, timeout=600)
```

It works. It is also wrong in an async worker.

```text
subprocess.run()
    ↓
blocks the entire event loop
    ↓
for up to 10 minutes
    ↓
nothing else in the process can run
```

That includes your SIGTERM handler. So when the platform tries to shut the worker down gracefully during a scan, it can't, and the task gets hard-killed.

```python
await asyncio.create_subprocess_exec(...)
```

yields to the loop while the container runs.

Marking a function `async` does not make it non-blocking. Only awaiting something that genuinely yields does.

The reference implementation of this project uses `subprocess.run` inside an `async def`. We're building the corrected version from the start.

---

# 7. Why the flags matter

Three of them are load-bearing.

`--quiet` suppresses the progress bar.

```text
without --quiet:
    progress output → stdout
    JSON            → stdout
    result          → json.loads() raises
```

`--format json` without `--quiet` is a trap people hit constantly.

`-v /var/run/docker.sock:...` lets the Trivy container see images in your local daemon.

Understand the cost: mounting the Docker socket gives that container root on your host. Acceptable for a local scan you control. Never in something you deploy.

`--rm` deletes the container after each scan. Without it you accumulate one dead container per scan.

**Windows note.** Replace the socket mount with:

```text
-v //var/run/docker.sock:/var/run/docker.sock
```

---

# 8. Run your first scan

Create a scratch script:

```text
worker/app/scripts/scan_once.py
```

```python
import asyncio
import json
import sys

from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    result = await run_trivy_scan(target)

    with open("out.json", "w") as handle:
        json.dump(result, handle, indent=2)

    print(f"Wrote out.json for {target}")


if __name__ == "__main__":
    asyncio.run(main())
```

```bash
mkdir -p app/scripts && touch app/scripts/__init__.py
```

Run it:

```bash
uv run python -m app.scripts.scan_once python:3.8
```

Then:

```bash
(Get-Item out.json).Length
```

Or if you want it formatted with separators:

```bash
"{0:N0} bytes" -f (Get-Item out.json).Length
```

You should see something in the range:

```text
2,000,000 – 10,000,000 bytes
```

Open the file. The shape is:

```text
{
  "Results": [
    {
      "Target": "python:3.8 (debian 11.7)",
      "Vulnerabilities": [ { …25 fields… }, … ]
    }
  ]
}
```

---

# 9. The problem

You cannot hand that file to a language model.

```text
8 MB of JSON
    ≈ 2,000,000 tokens
    ≈ far beyond any context window
    ≈ and if it fit, it would cost dollars per scan
```

And roughly 90% of it is metadata the model will never use — layer digests, package URLs, reference link arrays, vendor severity maps.

So we reduce **before** we reason.

This is the most transferable habit in the entire project.

```text
LLM sees raw API response
    ↓
expensive, slow, more surface to hallucinate against

LLM sees a 20-line deterministic reduction
    ↓
cheap, fast, focused
```

---

# 10. Define the reduced model

Create:

```text
worker/app/processors/vulnerabilities.py
```

```python
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "informational",
    "NEGLIGIBLE": "informational",
}


class RawVulnerability(BaseModel):
    id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: Severity
    cvss_score: float = Field(default=0.0)
    description: str
    target: str


def normalise_severity(value: str) -> Severity:
    return _SEVERITY_MAP.get(
        value.upper(),
        "informational",
    )
```

Typed output from the reduction step matters more than it looks. Phase 2 hands this straight to a model, and Phase 3 validates the model's answer against a sibling schema. Untyped dicts here mean untyped dicts everywhere downstream.

---

# 11. Write the extraction function

Add to the same file:

```python
from app.config.scanning import DESCRIPTION_TRUNCATE_CHARS


def _extract_cvss(entry: dict) -> float:
    cvss = entry.get("CVSS") or {}

    nvd_score = cvss.get("nvd", {}).get("V3Score")

    if nvd_score is not None:
        return float(nvd_score)

    ghsa_score = cvss.get("ghsa", {}).get("V3Score")

    if ghsa_score is not None:
        return float(ghsa_score)

    return 0.0


def extract_vulnerabilities(
    trivy_data: dict,
) -> list[RawVulnerability]:
    vulnerabilities: list[RawVulnerability] = []

    for result in trivy_data.get("Results") or []:
        target = result.get("Target", "")

        for entry in result.get("Vulnerabilities") or []:
            vulnerabilities.append(
                RawVulnerability(
                    id=entry.get("VulnerabilityID", ""),
                    package=entry.get("PkgName", ""),
                    installed_version=entry.get("InstalledVersion", ""),
                    fixed_version=entry.get("FixedVersion", ""),
                    severity=normalise_severity(
                        entry.get("Severity", "UNKNOWN")
                    ),
                    cvss_score=_extract_cvss(entry),
                    description=entry.get("Description", "")[
                        :DESCRIPTION_TRUNCATE_CHARS
                    ],
                    target=target,
                )
            )

    return vulnerabilities
```

---

# 12. The `or []` detail

Look closely at:

```python
for entry in result.get("Vulnerabilities") or []:
```

Not:

```python
for entry in result.get("Vulnerabilities", []):
```

Trivy emits an **explicit null** for clean targets:

```json
{ "Target": "app/requirements.txt", "Vulnerabilities": null }
```

Then:

```text
.get("Vulnerabilities", [])   → None   → TypeError
.get("Vulnerabilities") or [] → []     → correct
```

The default in `.get()` only fires when the key is **absent**, not when its value is null.

This is a small thing that will crash you on your third scan if you get it wrong.

---

# 13. Prioritisation — truncate by count, never by characters

Add:

```python
from app.config.scanning import MAX_VULNERABILITIES_TO_MODEL


def prioritise(
    vulnerabilities: list[RawVulnerability],
    limit: int = MAX_VULNERABILITIES_TO_MODEL,
) -> list[RawVulnerability]:
    ordered = sorted(
        vulnerabilities,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -item.cvss_score,
        ),
    )

    return ordered[:limit]
```

This function exists to prevent a specific bug.

The naive approach is:

```python
summary = json.dumps(vulns)[:40000]
```

which produces:

```text
[
  {"id": "CVE-2023-1", …},
  {"id": "CVE-2023-2", …},
  {"id": "CVE-2023-3", "packa
```

A JSON array cut mid-object. The model now receives malformed structure, and worse, it received the vulnerabilities in **Trivy's arbitrary order** — so the ones that got cut are random, not unimportant.

Sorting first and truncating by item count guarantees two things:

```text
1. the model always receives well-formed input
2. the model always sees the worst findings
```

The reference implementation of this project uses the character-slice version. This is the corrected one.

---

# 14. Measure your reduction

Update `scan_once.py`:

```python
import asyncio
import json
import sys

from app.processors.vulnerabilities import (
    extract_vulnerabilities,
    prioritise,
)
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    raw = await run_trivy_scan(target)

    raw_bytes = len(json.dumps(raw))

    vulnerabilities = extract_vulnerabilities(raw)

    top = prioritise(vulnerabilities)

    reduced = json.dumps(
        [item.model_dump() for item in top],
        indent=2,
    )

    print(f"target:        {target}")
    print(f"raw bytes:     {raw_bytes:,}")
    print(f"vulns found:   {len(vulnerabilities):,}")
    print(f"sent to model: {len(top):,}")
    print(f"reduced bytes: {len(reduced):,}")
    print(f"reduction:     {raw_bytes / max(len(reduced), 1):.1f}x")


if __name__ == "__main__":
    asyncio.run(main())
```

```bash
uv run python -m app.scripts.scan_once python:3.8
```

Expected shape of output:

```text
target:        python:3.8
raw bytes:     6,284,113
vulns found:   1,247
sent to model: 150
reduced bytes: 61,904
reduction:     101.5x
```

That number is the whole point of this phase.

Run it against a clean image too:

```bash
uv run python -m app.scripts.scan_once alpine:3.20
```

You should get near-zero vulnerabilities and no crash. That path matters more than it seems — it's the one that trips the `null` handling from section 12.

---

# 15. Add tests

Create:

```text
worker/tests/test_reduction.py
```

```python
from app.processors.vulnerabilities import (
    extract_vulnerabilities,
    normalise_severity,
    prioritise,
)


def _vulnerability(
    vuln_id: str,
    severity: str,
    score: float,
) -> dict:
    return {
        "VulnerabilityID": vuln_id,
        "PkgName": "openssl",
        "InstalledVersion": "1.1.1",
        "FixedVersion": "1.1.1w",
        "Severity": severity,
        "CVSS": {"nvd": {"V3Score": score}},
        "Description": "x" * 500,
    }


def test_extracts_and_truncates_description() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    _vulnerability("CVE-1", "HIGH", 7.5)
                ],
            }
        ]
    }

    result = extract_vulnerabilities(data)

    assert len(result) == 1
    assert result[0].id == "CVE-1"
    assert result[0].severity == "high"
    assert len(result[0].description) == 200


def test_handles_null_vulnerabilities() -> None:
    data = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": None,
            }
        ]
    }

    assert extract_vulnerabilities(data) == []


def test_handles_missing_results() -> None:
    assert extract_vulnerabilities({}) == []


def test_unknown_severity_becomes_informational() -> None:
    assert normalise_severity("BOGUS") == "informational"
    assert normalise_severity("NEGLIGIBLE") == "informational"


def test_prioritise_keeps_worst_findings() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    _vulnerability("CVE-LOW", "LOW", 2.0),
                    _vulnerability("CVE-CRIT", "CRITICAL", 9.8),
                    _vulnerability("CVE-MED", "MEDIUM", 5.0),
                ],
            }
        ]
    }

    result = prioritise(
        extract_vulnerabilities(data),
        limit=2,
    )

    assert [item.id for item in result] == [
        "CVE-CRIT",
        "CVE-MED",
    ]


def test_prioritise_breaks_ties_by_cvss() -> None:
    data = {
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    _vulnerability("CVE-A", "HIGH", 7.1),
                    _vulnerability("CVE-B", "HIGH", 8.9),
                ],
            }
        ]
    }

    result = prioritise(extract_vulnerabilities(data))

    assert result[0].id == "CVE-B"
```

Run:

```bash
uv run pytest tests/test_reduction.py -v
```

Six tests, all passing.

Notice what's being tested: the null case, the missing case, the unknown-severity case, and the ordering guarantee. Those are the four ways this function fails in production. The happy path is the least interesting test here.

---

# 16. Run the quality gate

Do this before moving on:

```bash
uv run ruff check .
```

```bash
uv run ruff format --check .
```

```bash
uv run mypy app
```

```bash
uv run pytest -v
```

Then a live run against both a bad and a clean image:

```bash
uv run python -m app.scripts.scan_once python:3.8
```

```bash
uv run python -m app.scripts.scan_once alpine:3.20
```

You should have:

```text
✓ Trivy runs as a container, never blocks the event loop
✓ Timeouts raise instead of hanging
✓ Null and missing fields handled
✓ Severity normalised to a closed set
✓ Output sorted worst-first, truncated by count
✓ 50–100x reduction measured, not assumed
```

---

# 17. Where this sits in the finished system

```text
                        Phase 1  ◄── you are here
                           │
                ┌──────────┴──────────┐
                │                     │
           TRIVY RUNNER          REDUCTION
                │                     │
                └──────────┬──────────┘
                           ▼
                    RawVulnerability[]
                           │
                           ▼
                    ┌─────────────┐
                    │ CVE ANALYST │   ← Phase 2
                    └─────────────┘
                           │
                           ▼
                    Finding[]
```

Everything from here on consumes `RawVulnerability`. The scanner is now a solved, tested, boring problem — which is exactly what you want underneath a probabilistic layer.

---

## Next: Phase 2 — The CVE Analyst Agent

We add the first LLM call, and immediately constrain it:

```text
              RawVulnerability[]
                      │
                      ▼
              ┌──────────────┐
              │ SYSTEM PROMPT│
              │  + contract  │
              └──────┬───────┘
                     │
                     ▼
                  GPT-4o
              response_format:
                json_object
                     │
                     ▼
              ┌──────────────┐
              │  PYDANTIC    │
              │  VALIDATION  │
              └──────┬───────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
           valid         invalid
              │             │
              ▼             ▼
          Finding[]      raise
```

The critical rule we'll establish in Phase 2:

```text
a parse failure and a clean image
must never produce the same result
```

In the reference implementation they do — both return an empty list — which means a malformed model response reports a vulnerable image as clean. We'll make that structurally impossible before we write a second agent.