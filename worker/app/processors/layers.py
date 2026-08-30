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
    """Turn a Docker size string like `180MB` into bytes.

    Raises rather than defaulting to zero: a size we cannot read would
    make a fat layer look empty, which is the one mistake the bloat agent
    must never be handed.
    """
    match = _SIZE_PATTERN.match(value.strip().upper())

    if match is None:
        raise ValueError(f"Unrecognised Docker size string: {value!r}")

    amount, unit = match.groups()

    return int(float(amount) * _SIZE_UNITS[unit])


def _clean_command(raw: str) -> str:
    """Recover the Dockerfile instruction from a history entry.

    Docker records `/bin/sh -c` wrappers and `#(nop)` markers around the
    original line. The agents are asked to quote the instruction back as a
    fix, so they need it in the form the user actually wrote.
    """
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
    """Turn raw history entries into indexed layers, oldest first.

    The docker CLI prints newest first, so this reverses. Index 0 being the
    base is what lets the bloat agent name a layer and be understood - the
    prompt forbids inventing indexes, so they have to mean something.
    """
    layers: list[ImageLayer] = []

    ordered = list(reversed(history_entries))

    for index, entry in enumerate(ordered):
        size = parse_size(entry.get("Size", "0B"))

        # A registry-mode entry says outright whether the step produced a
        # layer. The docker CLI does not, so there size is the only signal -
        # which is why a real-but-tiny layer can read as empty locally.
        is_empty = bool(entry["EmptyLayer"]) if "EmptyLayer" in entry else size == 0

        layers.append(
            ImageLayer(
                index=index,
                command=_clean_command(entry.get("CreatedBy", "")),
                size_bytes=size,
                is_empty=is_empty,
            )
        )

    return layers


def total_size(layers: list[ImageLayer]) -> int:
    """Sum every layer's bytes, which is the image's uncompressed size."""
    return sum(layer.size_bytes for layer in layers)
