"""Trivy's secret findings, which were being fetched and discarded.

`TRIVY_SCANNERS = "vuln,secret"` has always asked Trivy to hunt for hardcoded
credentials, and Trivy has always found them. It puts them in
`Results[].Secrets`, and the only consumer of the report read
`Results[].Vulnerabilities` and nothing else - so an AWS key baked into a layer
was detected, parsed into memory, and dropped on the floor.

Meanwhile the compliance agent was being asked to *guess* at secrets from
environment variable names, while the real detection sat unread in the same
dict. See docs/audits/audit-01-backend.md P2-2.

Deterministic, like the CIS controls in processors/compliance.py: no model is
involved, so these survive every agent failing.
"""

from app.models.findings import SecretFinding
from app.processors.vulnerabilities import normalise_severity

# How much of the matched line to keep. Enough to find the line; never enough
# to use. See _redact.
_CONTEXT_CHARS = 12


def _redact(match: str) -> str:
    """Return a locator for a secret, never the secret.

    `Match` is the line Trivy matched, and for a hit worth reporting that
    line CONTAINS A LIVE CREDENTIAL. Storing it verbatim would copy the
    secret into the report blob, the API response, and any export - and a
    vulnerability report is exactly the document an attacker wants.

    So: first few characters to locate the line, then the length, so a
    reader can confirm they are looking at the right thing.
    """
    stripped = match.strip()

    if not stripped:
        return "<empty>"

    if len(stripped) <= _CONTEXT_CHARS:
        return f"<redacted, {len(stripped)} chars>"

    return f"{stripped[:_CONTEXT_CHARS]}... <redacted, {len(stripped)} chars>"


def extract_secrets(trivy_data: dict) -> list[SecretFinding]:
    """Flatten Trivy's secret hits into findings.

    Severity comes straight from Trivy and is never asked of a model: a
    hardcoded private key is critical whatever prose surrounds it.
    """
    findings: list[SecretFinding] = []

    for result in trivy_data.get("Results") or []:
        target = result.get("Target", "")

        for entry in result.get("Secrets") or []:
            rule = entry.get("RuleID", "unknown")
            title = entry.get("Title") or rule

            findings.append(
                SecretFinding(
                    severity=normalise_severity(entry.get("Severity", "HIGH")),
                    title=f"Hardcoded secret: {title}"[:140],
                    impact=(
                        "A credential baked into an image layer is readable by "
                        "anyone who can pull the image, and deleting it in a "
                        "later layer does not remove it from the earlier one."
                    ),
                    fix=(
                        "Remove the credential, rotate it - assume it is "
                        "compromised - and inject it at runtime instead."
                    ),
                    effort="moderate",
                    priority=95,
                    rule_id=rule,
                    category_name=entry.get("Category", ""),
                    file_path=target,
                    line=int(entry.get("StartLine") or 0),
                    redacted_match=_redact(entry.get("Match", "")),
                )
            )

    return findings
