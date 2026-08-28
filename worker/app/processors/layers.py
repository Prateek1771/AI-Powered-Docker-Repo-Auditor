import re

from pydantic import BaseModel


class ImageLayer(BaseModel):
    index: int
    command: str
    size_bytes: int
    is_empty: bool


_SIZE_UNITS = {
    "B": 1,
    "KB": 10**3,
    "MB": 10**6,
    "GB": 10**9,
    "TB": 10**12,
}

_SIZE_PATTERN = re.compile(r"^([0-9]*\.?[0-9]+)\s*([KMGT]?B)$")

_NOP_MARKER = "#(nop)"

_BUILDKIT_PREFIX = "RUN /bin/sh -c "


def parse_size(value: str) -> int:
    match = _SIZE_PATTERN.match(value.strip().upper())

    if match is None:
        raise ValueError(f"Unrecognised Docker size string: {value!r}")

    amount, unit = match.groups()

    return int(float(amount) * _SIZE_UNITS[unit])


def _clean_command(raw: str) -> str:
    command = raw.strip()

    if _NOP_MARKER in command:
        command = command.split(_NOP_MARKER, 1)[1].strip()

    if command.startswith("/bin/sh -c "):
        command = "RUN " + command[len("/bin/sh -c ") :]

    if command.startswith(_BUILDKIT_PREFIX):
        command = "RUN " + command[len(_BUILDKIT_PREFIX) :]

    return command.strip()


def extract_layers(
    history_entries: list[dict],
) -> list[ImageLayer]:
    layers: list[ImageLayer] = []

    ordered = list(reversed(history_entries))

    for index, entry in enumerate(ordered):
        size = parse_size(entry.get("Size", "0B"))

        layers.append(
            ImageLayer(
                index=index,
                command=_clean_command(entry.get("CreatedBy", "")),
                size_bytes=size,
                is_empty=size == 0,
            )
        )

    return layers


def total_size(layers: list[ImageLayer]) -> int:
    return sum(layer.size_bytes for layer in layers)
