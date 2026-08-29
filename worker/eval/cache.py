import hashlib
import json
from pathlib import Path
from typing import Any

from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
from app.scanners.trivy import run_trivy_scan

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
