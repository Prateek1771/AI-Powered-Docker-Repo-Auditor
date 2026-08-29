import json
from pathlib import Path

from app.config.storage import BLOB_DIR


def _path(key: str) -> Path:
    path = Path(BLOB_DIR) / f"{key}.json"

    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def put_blob(key: str, payload: dict) -> str:
    _path(key).write_text(json.dumps(payload, default=str))

    return key


def get_blob(key: str) -> dict | None:
    path = _path(key)

    if not path.exists():
        return None

    return json.loads(path.read_text())
