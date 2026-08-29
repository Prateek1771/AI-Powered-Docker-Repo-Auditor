TRIVY_IMAGE = "aquasec/trivy:latest"

TRIVY_CACHE_VOLUME = "trivy-cache"

TRIVY_SCANNERS = "vuln,secret"

TRIVY_TIMEOUT_SECONDS = 600

MAX_VULNERABILITIES_TO_MODEL = 150

DESCRIPTION_TRUNCATE_CHARS = 200

CVE_MODEL = "gpt-4o"

CVE_TEMPERATURE = 0.0

CVE_TIMEOUT_SECONDS = 90

AGENT_TIMEOUT_SECONDS = 120

# ponytail: TPM is the binding limit at 4 concurrent agents; the OpenAI SDK
# already honours Retry-After, so a bigger budget is the whole fix.
MODEL_MAX_RETRIES = 6
