import os

# CISA's Known Exploited Vulnerabilities catalog. One JSON file, updated a few
# times a week, so a day-old copy under-reports slightly and never invents.
KEV_CATALOG_URL = os.environ.get(
    "KEV_CATALOG_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

KEV_REFRESH_SECONDS = int(os.environ.get("KEV_REFRESH_SECONDS", str(24 * 3600)))

# FIRST's Exploit Prediction Scoring System.
EPSS_API_URL = os.environ.get("EPSS_API_URL", "https://api.first.org/data/v1/epss")

# The API takes a comma-separated list; this keeps the query string well
# inside any sane URL length limit.
EPSS_BATCH_SIZE = int(os.environ.get("EPSS_BATCH_SIZE", "100"))

# Short on purpose. Enrichment is a bonus on top of a scan that already
# works, so it must never be the reason one takes minutes.
ENRICHMENT_TIMEOUT_SECONDS = float(os.environ.get("ENRICHMENT_TIMEOUT_SECONDS", "15"))

ENRICHMENT_CACHE_DIR = os.environ.get("ENRICHMENT_CACHE_DIR", ".enrichment-cache")

# Set to "0" to skip both feeds entirely - for an air-gapped deployment, or a
# test that must not touch the network.
ENRICHMENT_ENABLED = os.environ.get("ENRICHMENT_ENABLED", "1") == "1"
