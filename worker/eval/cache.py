import hashlib
import json
from pathlib import Path
from typing import Any

from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
from app.scanners.trivy import run_trivy_scan

CACHE_DIR = Path(__file__).parent / ".cache"


def _key(target: str, kind: str) -> Path:
    """Return the cache file for one target and scanner kind."""
    digest = hashlib.sha256(target.encode()).hexdigest()[:16]

    return CACHE_DIR / f"{kind}-{digest}.json"


def load(target: str, kind: str) -> Any | None:
    """Read cached scanner output, or None if it was never stored."""
    path = _key(target, kind)

    if not path.exists():
        return None

    return json.loads(path.read_text())


def save(target: str, kind: str, payload: Any) -> None:
    """Write scanner output to the cache."""
    CACHE_DIR.mkdir(exist_ok=True)

    _key(target, kind).write_text(json.dumps(payload))


async def cached_scanners(target: str) -> tuple[dict, list, dict]:
    """Return the three scanner outputs for a target, scanning only once.

    Scanner output only changes when the image does, so caching it makes
    repeated eval runs measure the agents rather than Trivy. Model calls
    are deliberately not cached - they are what is being measured.
    """
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
