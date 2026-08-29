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
