import asyncio
import json
import logging

from app.config.scanning import (
    LIST_ALL_PKGS,
    SCANNER_MODE,
    TAR_SCHEME,
    TRIVY_CACHE_VOLUME,
    TRIVY_CONTAINER_LIMITS,
    TRIVY_IMAGE,
    TRIVY_SCANNERS,
    TRIVY_TIMEOUT_ARG,
    TRIVY_TIMEOUT_SECONDS,
)
from app.telemetry import metrics

logger = logging.getLogger(__name__)


class TrivyScanError(RuntimeError):
    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


# Failures that will look exactly the same on a retry, because the target
# itself is wrong. Everything else is assumed transient.
#
# The old code marked EVERY non-zero exit permanent, and a permanent failure
# deletes the queue message rather than retrying it. So a GHCR rate-limit
# while pulling the vulnerability DB, a registry 5xx, an OOM-killed Trivy or
# a transient ECR auth failure all produced a job that was failed, un-retried,
# and never reached the DLQ. On Fargate the Trivy cache is ephemeral, so every
# cold task re-downloads that DB - which made this the expected failure mode
# under load rather than an edge case. See docs/AUDIT.md P3-1.
_PERMANENT_PATTERNS = (
    "no such image",
    "not found",
    "manifest unknown",
    "unknown manifest",
    "repository does not exist",
    "unauthorized",
    "authentication required",
    "denied",
    "invalid reference",
    "could not parse reference",
    "no such file or directory",
)

# Trivy uses 2 for usage errors - a malformed flag or argument, which no
# amount of retrying corrects.
_USAGE_EXIT_CODE = 2


def is_permanent_failure(returncode: int, stderr: str) -> bool:
    """Decide whether a Trivy failure is worth retrying.

    Wrong by default in the safe direction: an unrecognised error is
    treated as transient, so the worst case is three attempts and a DLQ
    entry rather than a silently discarded scan.
    """
    if returncode == _USAGE_EXIT_CODE:
        return True

    lowered = stderr.lower()

    return any(pattern in lowered for pattern in _PERMANENT_PATTERNS)


def build_command(target: str) -> list[str]:
    """Build the Trivy invocation for whichever mode this deployment runs.

    Registry mode calls the binary directly and needs no daemon; socket
    mode runs Trivy as a sibling container through the host's Docker. An
    uploaded tar is read with --input in either mode, because it must
    never reach the daemon - see the note below.
    """
    if target.startswith(TAR_SCHEME):
        path = target[len(TAR_SCHEME) :]

        # --input, never `docker load`. Loading an untrusted archive applies
        # the RepoTags ITS manifest declares, so an upload tagged
        # python:3.12-slim silently replaces the daemon's real one and every
        # later socket-mode scan of that tag - including other tenants' -
        # analyses the attacker's image. Trivy reads the tar directly and
        # cannot mutate shared state. See docs/AUDIT.md P1-4.
        if SCANNER_MODE == "registry":
            return [
                "trivy",
                "image",
                "--format",
                "json",
                "--quiet",
                LIST_ALL_PKGS,
                "--scanners",
                TRIVY_SCANNERS,
                "--timeout",
                TRIVY_TIMEOUT_ARG,
                "--input",
                path,
            ]

        return [
            "docker",
            "run",
            "--rm",
            *TRIVY_CONTAINER_LIMITS,
            "-v",
            f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy",
            # Read-only: the container needs to read the archive and nothing
            # else, and this one is handling attacker-supplied bytes.
            "-v",
            f"{path}:/scan/image.tar:ro",
            TRIVY_IMAGE,
            "image",
            "--format",
            "json",
            "--quiet",
            LIST_ALL_PKGS,
            "--scanners",
            TRIVY_SCANNERS,
            "--timeout",
            TRIVY_TIMEOUT_ARG,
            "--input",
            "/scan/image.tar",
        ]

    if SCANNER_MODE == "registry":
        # No daemon, no socket. Trivy pulls the image itself with whatever
        # credentials the environment gives it - the task role, on Fargate.
        return [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            LIST_ALL_PKGS,
            "--scanners",
            TRIVY_SCANNERS,
            "--timeout",
            TRIVY_TIMEOUT_ARG,
            # Everything after this is an operand, never a flag. Without it a
            # target of "--server=https://attacker/" is parsed as a Trivy flag.
            "--",
            target,
        ]

    return [
        "docker",
        "run",
        "--rm",
        *TRIVY_CONTAINER_LIMITS,
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy",
        TRIVY_IMAGE,
        "image",
        "--format",
        "json",
        "--quiet",
        LIST_ALL_PKGS,
        "--scanners",
        TRIVY_SCANNERS,
        "--timeout",
        TRIVY_TIMEOUT_ARG,
        # See above: `--` is what makes the target an operand, not a flag.
        "--",
        target,
    ]


async def _execute(target: str) -> dict:
    """Run Trivy once and return its parsed JSON report.

    A non-zero exit, a timeout and empty output are three different
    failures and each raises with the detail needed to tell them apart.
    """
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
    except TimeoutError:
        process.kill()
        await process.wait()

        metrics.trivy_failure.add(1, {"classification": "timeout"})

        raise TrivyScanError(
            f"Trivy scan timed out after {TRIVY_TIMEOUT_SECONDS}s: {target}"
        )

    if process.returncode != 0:
        detail = stderr.decode()[:500]

        permanent = is_permanent_failure(process.returncode or 0, detail)

        # Here rather than at the run_trivy_scan call site: in registry mode
        # _inflight shares one subprocess across three awaiters, so counting
        # outside this function would treble every failure.
        metrics.trivy_failure.add(
            1,
            {
                "classification": "permanent" if permanent else "retryable",
                "returncode": process.returncode or 0,
            },
        )

        raise TrivyScanError(
            f"Trivy exited {process.returncode}: {detail}",
            permanent=permanent,
        )

    if not stdout.strip():
        # Exit 0 with nothing on stdout never reaches is_permanent_failure,
        # so without its own classification this failure mode is invisible.
        metrics.trivy_failure.add(1, {"classification": "empty_output"})

        raise TrivyScanError(f"Trivy returned empty output for {target}")

    return json.loads(stdout)


# In registry mode the layer history and the image config both come out of the
# Trivy report, so the three scanners the orchestrator gathers would otherwise
# run Trivy three times over.
#
# This shares the run between callers that are ALREADY WAITING, and keeps
# nothing afterwards. A result cache would be smaller code and would hand a
# rescan of the same tag its pre-rebuild report - the one answer this tool must
# never give.
_inflight: dict[str, asyncio.Task[dict]] = {}


async def image_report(target: str) -> dict:
    """Return the Trivy report for an image, sharing concurrent runs.

    In registry mode all three scanners want this same report and the
    orchestrator asks for them at once, so without sharing Trivy would run
    three times over one image.
    """
    task = _inflight.get(target)

    if task is None:
        task = asyncio.create_task(_execute(target))

        _inflight[target] = task

        task.add_done_callback(lambda _: _inflight.pop(target, None))

    return await asyncio.shield(task)


async def run_trivy_scan(target: str) -> dict:
    """Scan an image and return Trivy's raw JSON report."""
    return await image_report(target)
