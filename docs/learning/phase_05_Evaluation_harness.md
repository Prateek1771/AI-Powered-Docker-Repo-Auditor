# Phase 5 — The Evaluation Harness: Recall, Precision & Stability

You have six agents producing confident, well-typed, schema-validated output. You have no evidence any of it is correct.

```text
        ┌─────────────────┐      ┌─────────────────┐
        │  BAD FIXTURE    │      │ CLEAN FIXTURE   │
        │  known problems │      │ known-good      │
        └────────┬────────┘      └────────┬────────┘
                 │                        │
                 ▼                        ▼
          scanner cache            scanner cache
                 │                        │
                 ▼                        ▼
            run agents               run agents
                 │                        │
                 ▼                        ▼
        ┌─────────────────┐      ┌─────────────────┐
        │     RECALL      │      │   PRECISION     │
        │ found / planted │      │ noise on clean  │
        └────────┬────────┘      └────────┬────────┘
                 │                        │
                 └───────────┬────────────┘
                             ▼
                      ┌─────────────┐
                      │  STABILITY  │
                      │ 5 runs,     │
                      │ same answer?│
                      └──────┬──────┘
                             ▼
                       EVAL REPORT
                             │
                             ▼
                    regression gate in CI
```

The rule for this phase:

```text
a test that mocks the model
tests your plumbing, not your system
```

---

# 1. Why your current tests prove nothing

Every test you've written so far is good — and none of them measure quality. `test_hallucinated_cve_raises` proves your guard works. It says nothing about whether the CVE analyst finds real vulnerabilities.

The reference implementation is a clean illustration of the trap. Its entire agent test suite looks like this:

```python
mock_response.content = json.dumps([
    {"severity": "critical", "title": "CVE-2023-1234", ...}
])

with patch("app.agents.cve_analyst.ChatOpenAI") as mock_llm_class:
    mock_llm.ainvoke = AsyncMock(return_value=mock_response)
    findings = await run_cve_analyst(sample_trivy_output, {}, None)

assert findings[0]["severity"] == "critical"
```

It hardcodes a finding, mocks the model to return it, and asserts it came back.

```text
what it proves:   json.loads works
what it implies:  the agent works
gap between them: the entire product
```

Replace that agent's system prompt with `"Return an empty array."` and the test still passes. Replace it with `"Return random CVE IDs."` and it still passes.

Evaluation needs real model calls against inputs whose correct answer you already know.

---

# 2. Build the two fixture images

You need one image where you planted the problems yourself, and one you built correctly.

```powershell
mkdir eval\fixtures\bad
mkdir eval\fixtures\clean
```

Create `worker/eval/fixtures/bad/Dockerfile`:

```dockerfile
FROM python:3.8

RUN apt-get update
RUN apt-get install -y curl wget git vim nano gcc build-essential libssl-dev
RUN apt-get install -y openssh-client nmap netcat-openbsd

ADD app.py /app/app.py

RUN pip install flask requests boto3 pytest black flake8 jupyter pandas numpy

ENV SECRET_KEY=mysupersecretkey123
ENV DATABASE_PASSWORD=admin123
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

EXPOSE 22
EXPOSE 80

CMD ["python", "/app/app.py"]
```

Create `worker/eval/fixtures/bad/app.py`:

```python
print("bad fixture")
```

Create `worker/eval/fixtures/clean/Dockerfile`:

```dockerfile
FROM python:3.12-slim

RUN adduser --system --no-create-home --group appuser

WORKDIR /app

COPY --chown=appuser:appuser app.py .

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import sys; sys.exit(0)"]

CMD ["python", "app.py"]
```

Create `worker/eval/fixtures/clean/app.py`:

```python
print("clean fixture")
```

Build both:

```powershell
docker build -t auditor-eval:bad .\eval\fixtures\bad
```

```powershell
docker build -t auditor-eval:clean .\eval\fixtures\clean
```

Every line in the bad image is a deliberate violation. Every line in the clean one is a deliberate correction. You control the ground truth because you wrote it.

---

# 3. Enumerate the ground truth

This is the part people skip, and it is the actual work of the phase. Sit down and write out what a correct scanner *must* find.

```powershell
uv add pyyaml
```

Create `worker/eval/expectations/bad.yaml`:

```yaml
image: auditor-eval:bad

expectations:
  - id: cis-4.1-root
    agent: compliance_checker
    match:
      control_id: "4.1"
    min_severity: high
    why: no USER instruction, container runs as root

  - id: cis-4.3-unnecessary-packages
    agent: compliance_checker
    match:
      control_id: "4.3"
    min_severity: medium
    why: nmap, netcat, gcc, vim, jupyter in a runtime image

  - id: cis-4.6-no-healthcheck
    agent: compliance_checker
    match:
      control_id: "4.6"
    min_severity: low
    why: no HEALTHCHECK instruction

  - id: cis-4.7-update-alone
    agent: compliance_checker
    match:
      control_id: "4.7"
    min_severity: medium
    why: RUN apt-get update in its own layer

  - id: cis-4.9-add-over-copy
    agent: compliance_checker
    match:
      control_id: "4.9"
    min_severity: low
    why: ADD used for a local file that COPY would handle

  - id: cis-4.10-secrets
    agent: compliance_checker
    match:
      control_id: "4.10"
    min_severity: critical
    why: SECRET_KEY, DATABASE_PASSWORD, AWS_ACCESS_KEY_ID in ENV

  - id: cis-5.8-privileged-port
    agent: compliance_checker
    match:
      control_id: "5.8"
    min_severity: medium
    why: EXPOSE 22 and EXPOSE 80 are below 1024

  - id: bloat-apt-cache
    agent: bloat_detective
    match:
      keywords_any: [apt, cache, lists, "rm -rf"]
    min_severity: medium
    why: apt lists never removed in the installing layer

  - id: bloat-dev-tooling
    agent: bloat_detective
    match:
      keywords_any: [pytest, black, flake8, jupyter, dev]
    min_severity: medium
    why: test and lint tooling installed into the runtime image

  - id: bloat-build-toolchain
    agent: bloat_detective
    match:
      keywords_any: [gcc, build-essential, compiler, toolchain]
    min_severity: medium
    why: compiler present at runtime, needs multi-stage

  - id: base-image-outdated
    agent: base_image_strategist
    match:
      keywords_any: [slim, alpine, distroless, "3.12", "3.11", upgrade]
    min_severity: high
    why: python:3.8 is end of life

  - id: cve-present
    agent: cve_analyst
    match:
      min_count: 10
    min_severity: high
    why: python:3.8 carries hundreds of known CVEs

scores:
  overall_at_most: 40
  security_at_most: 40
  compliance_at_most: 40
```

And `worker/eval/expectations/clean.yaml`:

```yaml
image: auditor-eval:clean

forbidden:
  - id: no-root-finding
    agent: compliance_checker
    match:
      control_id: "4.1"
    why: a non-root USER is set, reporting 4.1 is a false positive

  - id: no-secret-finding
    agent: compliance_checker
    match:
      control_id: "4.10"
    why: no credential-shaped env vars exist

  - id: no-healthcheck-finding
    agent: compliance_checker
    match:
      control_id: "4.6"
    why: HEALTHCHECK is present

  - id: no-privileged-port-finding
    agent: compliance_checker
    match:
      control_id: "5.8"
    why: only 8080 is exposed

limits:
  compliance_findings_at_most: 2
  bloat_findings_at_most: 3

scores:
  overall_at_least: 60
  compliance_at_least: 70
```

Two files, two different jobs.

```text
bad.yaml    →  did you FIND the problems      →  recall
clean.yaml  →  did you INVENT problems        →  precision
```

The clean fixture will still have CVEs — `python:3.12-slim` isn't vulnerability-free and pretending otherwise would make the eval dishonest. That's why `clean.yaml` constrains compliance and bloat, not CVE count.

---

# 4. Cache the scanner output

Evaluation means running the scan many times. Trivy takes 90 seconds and the layer data never changes between runs of the same image. Paying that repeatedly is why people stop running their evals.

Create `worker/eval/cache.py`:

```python
import hashlib
import json
from pathlib import Path
from typing import Any

CACHE_DIR = Path(__file__).parent / ".cache"


def _key(target: str, kind: str) -> Path:
    digest = hashlib.sha256(target.encode()).hexdigest()[:16]

    return CACHE_DIR / f"{kind}-{digest}.json"


def load(target: str, kind: str) -> Any | None:
    path = _key(target, kind)

    if not path.exists():
        return None

    return json.loads(path.read_text())


def save(target: str, kind: str, payload: Any) -> None:
    CACHE_DIR.mkdir(exist_ok=True)

    _key(target, kind).write_text(json.dumps(payload))
```

Then a cached scan gatherer:

```python
from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
from app.scanners.trivy import run_trivy_scan


async def cached_scanners(target: str) -> tuple[dict, list, dict]:
    trivy = load(target, "trivy")
    history = load(target, "history")
    inspect = load(target, "inspect")

    if trivy is None:
        trivy = await run_trivy_scan(target)
        save(target, "trivy", trivy)

    if history is None:
        history = await run_docker_history(target)
        save(target, "history", history)

    if inspect is None:
        inspect = await run_image_inspect(target)
        save(target, "inspect", inspect)

    return trivy, history, inspect
```

Add `eval/.cache/` to `.gitignore`.

Cache the deterministic parts, never the probabilistic parts. Caching the *agent* output would make your eval measure a stale file instead of your current prompts, which is the exact failure the harness exists to catch.

Rebuild a fixture and the tag stays the same, so delete `eval/.cache/` when you change a Dockerfile. That's the one manual step this design costs you.

---

# 5. Write the matcher

An expectation matches a finding if the identifier lines up or a keyword appears. Deterministic, cheap, and slightly brittle.

Create `worker/eval/matcher.py`:

```python
from typing import Any

from app.models.outcomes import AgentOutcome

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _text_of(finding: Any) -> str:
    parts = [
        getattr(finding, "title", ""),
        getattr(finding, "fix", ""),
        getattr(finding, "impact", ""),
        getattr(finding, "root_cause_command", ""),
        getattr(finding, "recommended_base", ""),
        getattr(finding, "evidence", ""),
    ]

    return " ".join(str(p) for p in parts).lower()


def finding_matches(finding: Any, match: dict) -> bool:
    if "control_id" in match:
        if getattr(finding, "control_id", None) != match["control_id"]:
            return False

    if "vulnerability_id" in match:
        if getattr(finding, "vulnerability_id", None) != match["vulnerability_id"]:
            return False

    if "keywords_any" in match:
        text = _text_of(finding)

        if not any(
            keyword.lower() in text
            for keyword in match["keywords_any"]
        ):
            return False

    return True


def evaluate_expectation(
    expectation: dict,
    outcomes: dict[str, AgentOutcome],
) -> tuple[bool, str]:
    agent = expectation["agent"]

    if agent not in outcomes:
        return False, "agent did not run"

    outcome = outcomes[agent]

    if not outcome.is_trustworthy:
        return False, f"agent {outcome.status}"

    match = expectation.get("match", {})

    if "min_count" in match:
        found = len(outcome.findings) >= match["min_count"]

        return found, f"{len(outcome.findings)} findings"

    hits = [
        finding
        for finding in outcome.findings
        if finding_matches(finding, match)
    ]

    if not hits:
        return False, "no matching finding"

    minimum = expectation.get("min_severity")

    if minimum:
        best = max(SEVERITY_RANK[h.severity] for h in hits)

        if best < SEVERITY_RANK[minimum]:
            return False, f"found but severity too low"

    return True, f"{len(hits)} matching"
```

A word on the alternative. You could pass each finding and each expectation to a model and ask "do these describe the same problem?" That handles paraphrase, which keyword matching does not.

```text
LLM-as-judge:
  flexible, expensive, and now
  you have a second unmeasured
  model in your measurement path
```

If you go that route you must evaluate the judge against human labels first, or you have moved the uncertainty rather than removed it. Start with deterministic matching. Reach for a judge only when keyword brittleness is demonstrably your bottleneck, and budget for validating it.

---

# 6. Compute the three metrics

Create `worker/eval/metrics.py`:

```python
import statistics
from dataclasses import dataclass, field


@dataclass
class ExpectationResult:
    expectation_id: str
    agent: str
    passed: bool
    note: str
    why: str


@dataclass
class RecallReport:
    results: list[ExpectationResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def found(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def recall(self) -> float:
        if not self.total:
            return 0.0

        return round(self.found / self.total, 3)

    @property
    def missed(self) -> list[ExpectationResult]:
        return [r for r in self.results if not r.passed]


@dataclass
class PrecisionReport:
    violations: list[ExpectationResult] = field(default_factory=list)
    limit_breaches: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations and not self.limit_breaches


@dataclass
class StabilityReport:
    overall_scores: list[int]
    finding_id_sets: list[set[str]]

    @property
    def score_stdev(self) -> float:
        if len(self.overall_scores) < 2:
            return 0.0

        return round(statistics.stdev(self.overall_scores), 2)

    @property
    def score_range(self) -> int:
        if not self.overall_scores:
            return 0

        return max(self.overall_scores) - min(self.overall_scores)

    @property
    def mean_jaccard(self) -> float:
        if len(self.finding_id_sets) < 2:
            return 1.0

        scores = []

        for i in range(len(self.finding_id_sets)):
            for j in range(i + 1, len(self.finding_id_sets)):
                a = self.finding_id_sets[i]
                b = self.finding_id_sets[j]

                union = a | b

                if not union:
                    scores.append(1.0)
                    continue

                scores.append(len(a & b) / len(union))

        return round(statistics.mean(scores), 3)
```

The three numbers answer three different questions.

```text
recall         did it find what is really there
precision      did it invent what is not
stability      would it say the same thing tomorrow
```

Stability matters more than people expect. `temperature=0` reduces variance; it does not eliminate it. If your risk score swings from 34 to 61 across identical runs, the number is not a measurement and users will notice within a week.

Jaccard similarity on finding identifiers is the right stability measure here because it tolerates ordering differences while punishing findings that appear and vanish.

---

# 7. The eval runner

Create `worker/eval/run.py`:

```python
import argparse
import asyncio
from pathlib import Path

import yaml

from app.agents.trust import outcomes_by_agent
from app.orchestrator import run_scan_from_raw
from eval.cache import cached_scanners
from eval.matcher import evaluate_expectation, finding_matches
from eval.metrics import (
    ExpectationResult,
    PrecisionReport,
    RecallReport,
    StabilityReport,
)

EXPECTATIONS = Path(__file__).parent / "expectations"


def _load(name: str) -> dict:
    return yaml.safe_load((EXPECTATIONS / name).read_text())


async def _scan(target: str):
    trivy, history, inspect = await cached_scanners(target)

    return await run_scan_from_raw(target, trivy, history, inspect)


async def measure_recall(spec: dict) -> RecallReport:
    scan = await _scan(spec["image"])
    outcomes = outcomes_by_agent(scan.outcomes)

    report = RecallReport()

    for expectation in spec["expectations"]:
        passed, note = evaluate_expectation(expectation, outcomes)

        report.results.append(
            ExpectationResult(
                expectation_id=expectation["id"],
                agent=expectation["agent"],
                passed=passed,
                note=note,
                why=expectation["why"],
            )
        )

    limits = spec.get("scores", {})

    if scan.risk:
        score = scan.risk.score

        for key, cap in limits.items():
            if key.endswith("_at_most"):
                field = key.replace("_at_most", "")
                actual = getattr(score, field)

                report.results.append(
                    ExpectationResult(
                        expectation_id=f"score-{field}",
                        agent="risk_scorer",
                        passed=actual <= cap,
                        note=f"{actual} (cap {cap})",
                        why=f"{field} should be at most {cap} on a bad image",
                    )
                )

    return report


async def measure_precision(spec: dict) -> PrecisionReport:
    scan = await _scan(spec["image"])
    outcomes = outcomes_by_agent(scan.outcomes)

    report = PrecisionReport()

    for rule in spec.get("forbidden", []):
        agent = rule["agent"]

        if agent not in outcomes:
            continue

        hits = [
            f
            for f in outcomes[agent].findings
            if finding_matches(f, rule["match"])
        ]

        if hits:
            report.violations.append(
                ExpectationResult(
                    expectation_id=rule["id"],
                    agent=agent,
                    passed=False,
                    note=f"{len(hits)} false positives",
                    why=rule["why"],
                )
            )

    limits = spec.get("limits", {})

    for key, cap in limits.items():
        agent = key.replace("_findings_at_most", "")

        agent_key = {
            "compliance": "compliance_checker",
            "bloat": "bloat_detective",
            "cve": "cve_analyst",
        }.get(agent)

        if agent_key and agent_key in outcomes:
            count = len(outcomes[agent_key].findings)

            if count > cap:
                report.limit_breaches.append(
                    f"{agent_key}: {count} findings, limit {cap}"
                )

    return report


async def measure_stability(target: str, runs: int) -> StabilityReport:
    scores: list[int] = []
    id_sets: list[set[str]] = []

    for _ in range(runs):
        scan = await _scan(target)

        if scan.risk:
            scores.append(scan.risk.score.overall)

        ids = set()

        for outcome in scan.outcomes:
            for finding in outcome.findings:
                ids.add(
                    getattr(finding, "vulnerability_id", None)
                    or getattr(finding, "control_id", None)
                    or finding.title[:60]
                )

        id_sets.append(ids)

    return StabilityReport(
        overall_scores=scores,
        finding_id_sets=id_sets,
    )


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--skip-stability", action="store_true")
    args = parser.parse_args()

    bad = _load("bad.yaml")
    clean = _load("clean.yaml")

    print("=" * 62)
    print("RECALL  — did it find the planted problems")
    print("=" * 62)

    recall = await measure_recall(bad)

    for result in recall.results:
        mark = "PASS" if result.passed else "FAIL"
        print(f"  [{mark}] {result.expectation_id:32} {result.note}")

    print(f"\n  recall: {recall.recall:.0%} ({recall.found}/{recall.total})\n")

    print("=" * 62)
    print("PRECISION — did it invent problems on a clean image")
    print("=" * 62)

    precision = await measure_precision(clean)

    if precision.clean:
        print("  no false positives\n")
    else:
        for violation in precision.violations:
            print(f"  [FAIL] {violation.expectation_id:30} {violation.why}")

        for breach in precision.limit_breaches:
            print(f"  [FAIL] {breach}")

        print()

    if not args.skip_stability:
        print("=" * 62)
        print(f"STABILITY — {args.runs} runs of the same input")
        print("=" * 62)

        stability = await measure_stability(bad["image"], args.runs)

        print(f"  scores:        {stability.overall_scores}")
        print(f"  stdev:         {stability.score_stdev}")
        print(f"  range:         {stability.score_range}")
        print(f"  mean jaccard:  {stability.mean_jaccard}")


if __name__ == "__main__":
    asyncio.run(main())
```

This needs one small change in the orchestrator. Split `run_scan` so the agent half can be called with pre-fetched scanner data:

```python
async def run_scan(target: str) -> ScanOutcome:
    trivy_raw, history_raw, inspect_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
        run_image_inspect(target),
    )

    return await run_scan_from_raw(
        target, trivy_raw, history_raw, inspect_raw
    )


async def run_scan_from_raw(
    target: str,
    trivy_raw: dict,
    history_raw: list,
    inspect_raw: dict,
) -> ScanOutcome:
    # everything from `vulnerabilities = extract_vulnerabilities(...)` onward
    ...
```

Separating fetch from analysis is worth doing regardless. It makes the expensive, cacheable, deterministic half independent of the cheap-to-rerun probabilistic half.

---

# 8. Run your first evaluation

```powershell
uv run python -m eval.run --runs 3
```

The first run pays for Trivy on both fixtures. Every later run reads the cache and only pays for model calls.

A realistic first result:

```text
==============================================================
RECALL  — did it find the planted problems
==============================================================
  [PASS] cis-4.1-root                     1 matching
  [PASS] cis-4.3-unnecessary-packages     2 matching
  [FAIL] cis-4.6-no-healthcheck           no matching finding
  [PASS] cis-4.7-update-alone             1 matching
  [FAIL] cis-4.9-add-over-copy            no matching finding
  [PASS] cis-4.10-secrets                 3 matching
  [PASS] cis-5.8-privileged-port          1 matching
  [PASS] bloat-apt-cache                  2 matching
  [PASS] bloat-dev-tooling                1 matching
  [FAIL] bloat-build-toolchain            found but severity too low
  [PASS] base-image-outdated              1 matching
  [PASS] cve-present                      47 findings
  [PASS] score-overall                    22 (cap 40)

  recall: 77% (10/13)
```

Three misses on the first attempt is normal. Everyone's first eval run looks like this. That number is the reason the phase exists.

---

# 9. The prompt iteration loop

Now you have a signal to optimise against.

```text
       read the misses
             │
             ▼
    is it the prompt or the input?
             │
     ┌───────┴───────┐
     ▼               ▼
  prompt          the model
  never asked     never saw it
  for it          in the data
     │               │
     ▼               ▼
  edit prompt    fix the reducer
     │               │
     └───────┬───────┘
             ▼
      rerun the eval
             │
             ▼
     did recall improve
     WITHOUT breaking
        precision?
```

Work the three misses above.

**`cis-4.6-no-healthcheck`.** Look at the input. `ImageProfile.has_healthcheck` is in there, so the model saw it. The prompt lists control 4.6 but buried it among six others. Fix: state explicitly that a `has_healthcheck` of false is always a 4.6 failure.

**`cis-4.9-add-over-copy`.** The profile has no layer commands, and the compliance agent gets layers separately. Check whether `ADD app.py /app/app.py` actually survived `_clean_command`. If the reducer dropped it, no prompt change will help. **Always check the input before editing the prompt.**

**`bloat-build-toolchain` found but severity too low.** The agent found it and rated it `low`. Either your expectation is wrong or the prompt lacks severity guidance. Adding "a compiler present at runtime is at least medium severity" fixes it. Ask honestly which side is wrong — moving the expectation to match the output is how evaluations become decorative.

The discipline that makes this work:

```text
change ONE thing
rerun BOTH recall and precision
keep it only if recall rose
and precision held
```

Prompt changes that raise recall by loosening the model's threshold will raise false positives on the clean fixture too. Measuring only recall is how you build a scanner that flags everything.

---

# 10. What the numbers should look like

Rough targets after a few iterations:

```text
recall        ≥ 85%     misses should be things you chose not to chase
precision     clean     zero forbidden findings on the clean fixture
score stdev   ≤ 5       on a 0-100 scale
mean jaccard  ≥ 0.75    across runs
```

If stability is poor while `temperature=0`:

```text
scores: [22, 58, 31]
stdev:  18.15
```

Something upstream is non-deterministic. Usual suspects, in order: an agent timing out on some runs and not others, a `set` being iterated into the prompt, or `prioritise` producing unstable ordering on ties. That last one is real — `sorted` is stable, but if two vulnerabilities have equal severity and equal CVSS, their relative order depends on the order Trivy emitted them, which can vary. Add a final tiebreak on `id` and the noise disappears.

Stability failures are almost always a bug in your code, not variance in the model.

---

# 11. What this costs

Per full eval run with `--runs 3`:

```text
recall scan          6 agent calls
precision scan       6 agent calls
stability x3        18 agent calls
                    ─────────────
                    30 model calls
```

At roughly a cent or two per call on a mid-tier model, that's a coffee per run and it will still be the best money you spend on this project.

Ways to keep it down while iterating:

```powershell
uv run python -m eval.run --skip-stability
```

Drop `MAX_VULNERABILITIES_TO_MODEL` to 25 during prompt work. Run stability only before committing a prompt change, not during exploration.

If you delete the scanner cache, add roughly three minutes and no dollars.

---

# 12. The regression gate

An eval you run manually is a demo. An eval that fails a build is infrastructure.

Create `worker/tests/test_eval_gate.py`:

```python
import pytest

from eval.run import _load, measure_precision, measure_recall

pytestmark = pytest.mark.eval

MIN_RECALL = 0.80


async def test_recall_meets_threshold() -> None:
    report = await measure_recall(_load("bad.yaml"))

    missed = ", ".join(r.expectation_id for r in report.missed)

    assert report.recall >= MIN_RECALL, (
        f"recall {report.recall:.0%} below {MIN_RECALL:.0%}. Missed: {missed}"
    )


async def test_no_false_positives_on_clean_image() -> None:
    report = await measure_precision(_load("clean.yaml"))

    problems = [v.expectation_id for v in report.violations]
    problems += report.limit_breaches

    assert report.clean, f"false positives: {problems}"
```

Register the marker in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
markers = [
    "eval: hits the real model API, costs money, needs Docker",
]
```

Now your fast suite stays fast:

```powershell
uv run pytest -m "not eval" -v
```

And the expensive gate runs deliberately:

```powershell
uv run pytest -m eval -v
```

Two separate suites, two separate purposes.

```text
unit tests    every save        free, milliseconds
eval gate     before a merge    costs money, minutes
```

Set `MIN_RECALL` to slightly below your current measured recall. It is a ratchet against regression, not a target to hit. Every time you improve a prompt and recall rises, raise the floor.

---

# 13. Test the harness itself

The matcher is deterministic code, so it gets normal tests.

Create `worker/tests/test_matcher.py`:

```python
from app.models.findings import ComplianceFinding
from eval.matcher import evaluate_expectation, finding_matches
from app.agents.trust import outcomes_by_agent
from app.models.outcomes import AgentOutcome


def _compliance(control: str, severity: str = "high") -> ComplianceFinding:
    return ComplianceFinding(
        control_id=control,
        severity=severity,
        title="Container runs as root",
        impact="Full host access on escape",
        fix="Add a USER instruction",
        effort="trivial",
        evidence="User field is root",
        priority=90,
    )


def test_control_id_match() -> None:
    assert finding_matches(_compliance("4.1"), {"control_id": "4.1"})
    assert not finding_matches(_compliance("4.3"), {"control_id": "4.1"})


def test_keyword_match_is_case_insensitive() -> None:
    finding = _compliance("4.1")

    assert finding_matches(finding, {"keywords_any": ["ROOT"]})
    assert not finding_matches(finding, {"keywords_any": ["healthcheck"]})


def test_severity_floor_is_enforced() -> None:
    outcomes = outcomes_by_agent([
        AgentOutcome(
            agent="compliance_checker",
            status="analysed",
            findings=[_compliance("4.1", severity="low")],
        )
    ])

    passed, note = evaluate_expectation(
        {
            "agent": "compliance_checker",
            "match": {"control_id": "4.1"},
            "min_severity": "high",
        },
        outcomes,
    )

    assert passed is False
    assert "severity" in note


def test_degraded_agent_fails_the_expectation() -> None:
    outcomes = outcomes_by_agent([
        AgentOutcome(
            agent="compliance_checker",
            status="failed",
            findings=[],
        )
    ])

    passed, note = evaluate_expectation(
        {"agent": "compliance_checker", "match": {"control_id": "4.1"}},
        outcomes,
    )

    assert passed is False
    assert note == "agent failed"
```

That last test closes the loop with Phase 3. A failed agent must not be scored as "found nothing" — it must be scored as "we do not know", which is a miss. Without it, an agent that crashes on every run could show a respectable recall simply because nothing was expected of it.

```powershell
uv run pytest tests/test_matcher.py -v
```

---

# 14. Quality gate

```powershell
uv run ruff check .
```

```powershell
uv run ruff format --check .
```

```powershell
uv run mypy app eval
```

```powershell
uv run pytest -m "not eval" -v
```

```powershell
uv run python -m eval.run --runs 3
```

```powershell
uv run pytest -m eval -v
```

You should have:

```text
✓ Two fixture images with ground truth you wrote
✓ Recall measured against planted problems
✓ Precision measured on a known-clean image
✓ Stability measured across repeated runs
✓ Scanner output cached, agent output never cached
✓ Fast suite and paid suite separated by marker
✓ A recall floor that fails the build when a prompt regresses
```

---

# 15. Where this sits

```text
  Phase 1     Phase 2     Phase 3      Phase 4        Phase 5  ◄── here
 ┌────────┐ ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐
 │scanners│→│ 1 agent │→│ parallel │→│ 6 agents  │→│ measurement  │
 │reduce  │ │contract │ │isolation │ │ fan-in    │ │ recall/prec  │
 └────────┘ └─────────┘ └──────────┘ └───────────┘ └──────────────┘

                    ─── the AI system is done ───
                                 │
                                 ▼
                       Phase 6 onward: product
```

You now have something most production AI systems lack: a number that goes down when you make it worse.

Everything from Phase 6 on is plumbing — real, necessary plumbing, but no longer the interesting part. Persistence, queues, an API, a UI, containers, Terraform. If you stopped here you would have a working, tested, measurable scanner, and you would understand the part of the system that actually required judgement.

---

# Errata — found while implementing this phase

**`netcat` will not install on the bad fixture.** It is a virtual package on Debian
bookworm, which `python:3.8` is built on, so `docker build` fails with
`Package 'netcat' has no installation candidate`. Use `netcat-openbsd`; the ground truth
for CIS 4.3 is unchanged.

**Stability may read lower than the system deserves.** `measure_stability` identifies a
finding by `vulnerability_id or control_id or title[:60]`. Bloat and base-image findings
have neither id, so their identity falls back to free text the model rewrites every run —
two runs flagging the same wasted layer score as a non-match if the wording shifts. For
bloat, `layer_index` is the real identity; for base image, `recommended_base`.

Change it if you agree it is measuring the wrong thing, but note the direction of travel:
adjusting a metric because the number is inconvenient is exactly how an evaluation becomes
decorative. Decide on the merits, not on the reading.

**A first run at 100% recall is a warning, not a win.** It means the expectations were
written to match what the agents already do. The real test of the harness is whether it
goes red when you break a prompt on purpose — do that once before trusting the floor.

---

## Next: Phase 6 — Persistence

Scan results currently vanish when the process exits.

```text
                  ScanOutcome
                       │
                       ▼
              ┌────────────────┐
              │  scan_jobs     │   hot, tiny, written on
              │  status/progress│   every progress tick
              └────────────────┘
                       │
              ┌────────────────┐
              │  scan_results  │   cold, large, written
              │  findings/score│   once at the end
              └────────────────┘
```

We run DynamoDB Local in a container, so no AWS account is needed until Phase 12 — the endpoint is the only thing that changes later.

Three real bugs from the reference implementation get fixed on the way, and I checked all three against the source:

```text
1. get_previous_scan queries scan_jobs, a table that
   holds status and progress and no findings at all,
   so regression detection silently never works

2. Limit=1 with a FilterExpression on user_id reads one
   item then filters it, so two tenants with a repo of
   the same name hide each other's results

3. the scan_jobs table declares a TTL on expires_at and
   the writer never sets that attribute, so job records
   accumulate forever
```

The third one is the most instructive: TTL requires a Number holding epoch seconds. Write an ISO-8601 string there and DynamoDB accepts the item and silently ignores the TTL — configured, plausible, and doing nothing.