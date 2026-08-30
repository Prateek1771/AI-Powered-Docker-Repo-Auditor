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

TRIVY_IMAGE = "aquasec/trivy:latest"

TRIVY_CACHE_VOLUME = "trivy-cache"

TRIVY_SCANNERS = "vuln,secret"

TRIVY_TIMEOUT_SECONDS = 600

# Overridable so CI can run the eval gate on a cheaper sample. Recall on a
# smaller slice is noisier, but the gate is a ratchet, not a measurement.
MAX_VULNERABILITIES_TO_MODEL = int(
    os.environ.get("MAX_VULNERABILITIES_TO_MODEL", "150")
)

DESCRIPTION_TRUNCATE_CHARS = 200

CVE_MODEL = os.environ.get("CVE_MODEL", "gpt-4o")

CVE_TEMPERATURE = 0.0

CVE_TIMEOUT_SECONDS = 90

AGENT_TIMEOUT_SECONDS = 120

# ponytail: TPM is the binding limit at 4 concurrent agents; the OpenAI SDK
# already honours Retry-After, so a bigger budget is the whole fix.
MODEL_MAX_RETRIES = 6
