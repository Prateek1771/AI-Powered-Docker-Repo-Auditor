from pydantic import BaseModel

from app.processors.layers import ImageLayer, total_size


class ImageProfile(BaseModel):
    target: str
    os_family: str
    os_name: str
    base_reference: str
    user: str
    exposed_ports: list[int]
    env_keys: list[str]
    entrypoint: list[str]
    cmd: list[str]
    has_healthcheck: bool
    layer_count: int
    total_size_bytes: int


def _parse_ports(exposed: dict | None) -> list[int]:
    """Turn Docker's `{'8080/tcp': {}}` port map into sorted integers.

    Non-numeric keys are dropped rather than guessed at.
    """
    ports = []

    for key in exposed or {}:
        raw = key.split("/")[0]

        if raw.isdigit():
            ports.append(int(raw))

    return sorted(ports)


def _env_keys(env: list[str] | None) -> list[str]:
    """List the NAMES of environment variables, never their values.

    The compliance agent needs to know a variable called AWS_SECRET_KEY is
    set; sending what it contains would leak the secret into a prompt.
    """
    return [entry.split("=", 1)[0] for entry in (env or []) if "=" in entry]


def build_profile(
    target: str,
    inspect_data: dict,
    trivy_data: dict,
    layers: list[ImageLayer],
) -> ImageProfile:
    """Combine inspect output, Trivy metadata and layers into one profile.

    This is what the base image and compliance agents read instead of raw
    scanner output. The base reference comes from the first FROM in the
    layer history, falling back to Trivy's OS family and name when the
    history has been squashed away.
    """
    config = inspect_data.get("Config") or {}
    os_meta = (trivy_data.get("Metadata") or {}).get("OS") or {}

    base_reference = ""

    for layer in layers:
        if layer.command.startswith("FROM "):
            base_reference = layer.command[5:].strip()
            break

    fallback = f"{os_meta.get('Family', '')}:{os_meta.get('Name', '')}"

    return ImageProfile(
        target=target,
        os_family=os_meta.get("Family", "unknown"),
        os_name=os_meta.get("Name", "unknown"),
        base_reference=base_reference or fallback,
        user=config.get("User") or "root",
        exposed_ports=_parse_ports(config.get("ExposedPorts")),
        env_keys=_env_keys(config.get("Env")),
        entrypoint=config.get("Entrypoint") or [],
        cmd=config.get("Cmd") or [],
        has_healthcheck=bool(config.get("Healthcheck")),
        layer_count=len(layers),
        total_size_bytes=total_size(layers),
    )
