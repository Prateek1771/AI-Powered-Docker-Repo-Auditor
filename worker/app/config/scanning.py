import os

# How the scanners reach an image.
#
#   socket    Trivy runs as a sibling container and docker history/inspect
#             shell out to the CLI. Needs /var/run/docker.sock.
#   registry  Trivy runs as a local binary against the registry, and layer
#             history comes out of its report. Fargate has no Docker socket,
#             and mounting one would be a privilege problem anyway.
#
# Explicit rather than inferred: the socket path does not exist on Windows
# even though the CLI works there, so probing for it guesses wrong locally.
SCANNER_MODE = os.environ.get("SCANNER_MODE", "socket")

# A resolved upload: a local `docker save` tar the scanners read directly.
#
# Lives here rather than in app/images.py so the scanners can recognise it
# without importing that module - images.py already imports from
# app/scanners/, and the reverse would be a cycle.
TAR_SCHEME = "tarfile://"

# Pinned by digest, like every other image in this repo. This one runs with
# the host Docker socket mounted, so a compromised push to the mutable tag
# would be root on the host - it was the only image here still floating.
TRIVY_IMAGE = (
    "aquasec/trivy:0.74.0@sha256:"
    "62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
)

# Applied to the sibling Trivy container. It parses attacker-supplied image
# content, so an unbounded one can exhaust the host rather than just fail.
TRIVY_CONTAINER_LIMITS = [
    "--memory=2g",
    "--cpus=2",
    "--pids-limit=512",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
]

TRIVY_CACHE_VOLUME = "trivy-cache"

TRIVY_SCANNERS = "vuln,secret"

# Trivy reports every package it finds, not just the vulnerable ones, and puts
# them in Results[].Packages. That is the whole bill of materials, already paid
# for by the run we do anyway - so an SBOM needs no second scan.
#
# Passed explicitly even though current Trivy defaults it true: we pin 0.74.0,
# and an SBOM that silently empties on a version bump is worse than one that
# was never there.
LIST_ALL_PKGS = "--list-all-pkgs"

TRIVY_TIMEOUT_SECONDS = 600

# What Trivy is told, derived rather than written twice. The wait_for bound
# above and Trivy's own --timeout used to be a 600 and a hardcoded "10m" in
# four places: equal today, with nothing keeping them so.
TRIVY_TIMEOUT_ARG = f"{TRIVY_TIMEOUT_SECONDS}s"

# Overridable so CI can run the eval gate on a cheaper sample. Recall on a
# smaller slice is noisier, but the gate is a ratchet, not a measurement.
MAX_VULNERABILITIES_TO_MODEL = int(
    os.environ.get("MAX_VULNERABILITIES_TO_MODEL", "150")
)

DESCRIPTION_TRUNCATE_CHARS = 200

# An OpenAI-compatible gateway in front of every model call. Empty means
# talk to the provider directly, which is the default and exactly the old
# behaviour - the same discipline as OTEL_EXPORTER_OTLP_ENDPOINT.
LLM_GATEWAY_URL = os.environ.get("LLM_GATEWAY_URL", "").strip()

_MODEL = os.environ.get("CVE_MODEL", "gpt-4o")

# A gateway routes on "provider/model" and 404s on a bare model name. Rather
# than leave that as a trap for whoever turns the gateway on and forgets to
# change CVE_MODEL, add the prefix here when it is missing. An explicit
# "anthropic/claude-..." is left alone, which is how you point one agent at a
# different provider.
CVE_MODEL = f"openai/{_MODEL}" if LLM_GATEWAY_URL and "/" not in _MODEL else _MODEL

CVE_TEMPERATURE = 0.0

CVE_TIMEOUT_SECONDS = 90

AGENT_TIMEOUT_SECONDS = 120

# ponytail: TPM is the binding limit at 4 concurrent agents; the OpenAI SDK
# already honours Retry-After, so a bigger budget is the whole fix.
MODEL_MAX_RETRIES = 6
