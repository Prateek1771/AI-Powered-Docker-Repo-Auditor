"""CIS controls decided in Python, not asked of a model.

Three of the seven controls the compliance agent checks are fully determined
by fields `build_profile()` already computes. Asking a model to read
`user == "root"` and report back adds nothing but a place for prompt
injection to lie: content in the image being scanned reaches that prompt, and
a model talked into silence produces an image that "passes" 4.1.

A comparison a human wrote cannot be talked out of its answer. The model keeps
the controls that need judgement (4.3 unnecessary packages, 4.7 stale update
layers, 4.9 ADD vs COPY, 4.10 credential-shaped names) and loses the ones that
need only reading.

See docs/audits/audit-01-backend.md P1-1.
"""

from app.models.findings import ComplianceFinding
from app.processors.profile import ImageProfile

# The controls this module owns. The compliance agent is told not to report
# them, and any it reports anyway is dropped - two sources for one control
# would double-count in the score.
DETERMINISTIC_CONTROLS = {"4.1", "4.6", "5.8"}

PRIVILEGED_PORT_CEILING = 1024


def _root_user(profile: ImageProfile) -> ComplianceFinding | None:
    """CIS 4.1 - a non-root USER is set."""
    # build_profile defaults a missing User to "root", which is what Docker
    # itself does, so an empty value is a finding rather than unknown.
    if profile.user not in ("", "root", "0"):
        return None

    return ComplianceFinding(
        control_id="4.1",
        severity="high",
        title="Container runs as root",
        impact=(
            "A process that escapes the container does so as uid 0 on the host, "
            "and any file it writes to a mounted volume is root-owned."
        ),
        fix="Add a non-root USER instruction before the entrypoint.",
        effort="trivial",
        evidence=f"USER is {profile.user or 'unset, which means root'}",
        priority=85,
    )


def _no_healthcheck(profile: ImageProfile) -> ComplianceFinding | None:
    """CIS 4.6 - a HEALTHCHECK instruction is present."""
    if profile.has_healthcheck:
        return None

    return ComplianceFinding(
        control_id="4.6",
        severity="low",
        title="No HEALTHCHECK instruction",
        impact=(
            "The orchestrator cannot tell a hung process from a healthy one, "
            "so a wedged container keeps receiving traffic."
        ),
        fix="Add a HEALTHCHECK that exercises the service, not just the process.",
        effort="trivial",
        evidence="No Healthcheck in the image config",
        priority=35,
    )


def _privileged_ports(profile: ImageProfile) -> ComplianceFinding | None:
    """CIS 5.8 - no privileged ports exposed."""
    privileged = [p for p in profile.exposed_ports if p < PRIVILEGED_PORT_CEILING]

    if not privileged:
        return None

    return ComplianceFinding(
        control_id="5.8",
        severity="medium",
        title=f"Privileged port exposed: {', '.join(str(p) for p in privileged)}",
        impact=(
            "Binding below 1024 requires elevated capabilities, which keeps the "
            "container from dropping them."
        ),
        fix="Expose a port above 1024 and map it at the orchestrator.",
        effort="moderate",
        evidence=f"EXPOSE includes {privileged}",
        priority=55,
    )


def check_deterministic_controls(
    profile: ImageProfile,
) -> list[ComplianceFinding]:
    """Evaluate every control that needs reading rather than judgement.

    Runs before any model call and cannot fail, so these findings are
    present even when the compliance agent times out or is degraded.
    """
    checks = (_root_user, _no_healthcheck, _privileged_ports)

    return [finding for check in checks if (finding := check(profile)) is not None]
