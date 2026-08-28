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
        parse_analysis('```json\n{"findings": []}\n```', ALLOWED)


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
