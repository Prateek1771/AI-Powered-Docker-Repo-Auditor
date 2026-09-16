# Configuration

**Audience:** anyone running this locally or deploying it.
**Scope:** every environment variable the application actually reads, verified against
`worker/app/config/`, `frontend/`, and `docker-compose.yml` rather than copied forward.
`example.env` at the repo root is the runnable copy, with the longer commentary.

---

## Required

| Variable | Default | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | - | Required. All six agents run on it. |

## The model

| Variable | Default | Meaning |
|---|---|---|
| `CVE_MODEL` | `gpt-4o` | Model for every agent. Auto-prefixed to `openai/…` when `LLM_GATEWAY_URL` is set - see [the gateway](../architecture/llm-gateway.md). |
| `MAX_VULNERABILITIES_TO_MODEL` | `150` | Worst-N vulnerabilities sent to the CVE agent, after deterministic ranking. Overridable so CI can run the eval gate on a cheaper sample. |
| `LLM_GATEWAY_URL` | - | Empty calls the provider directly, which is the default and what CI does. Set to `http://bifrost:8080/v1` to route every call through the gateway. |
| `ANTHROPIC_API_KEY` | - | Optional. A second provider for the gateway to fail over to. |

Not environment variables, though older docs implied otherwise: `AGENT_TIMEOUT_SECONDS`
(120), `CVE_TIMEOUT_SECONDS` (90), `CVE_TEMPERATURE` (0.0) and `MODEL_MAX_RETRIES` (6) are
constants in `worker/app/config/scanning.py`. Changing one is a code change.

## Scanning

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_MODE` | `socket` | `socket` runs Trivy as a sibling container; `registry` uses the Trivy binary and takes history from the registry. Fargate runs `registry`, which is what removes the Docker-socket dependency in production. |
| `MAX_UPLOAD_BYTES` | 2 GiB | Tar upload ceiling; an overflow deletes the partial file. |

## Enrichment

| Variable | Default | Meaning |
|---|---|---|
| `ENRICHMENT_ENABLED` | `1` | KEV and EPSS lookups. `0` disables both; findings then carry no exploit-likelihood signal. |
| `ENRICHMENT_TIMEOUT_SECONDS` | - | Per-request timeout for the two feeds. |
| `ENRICHMENT_CACHE_DIR` | `.enrichment-cache` | On-disk cache so a scan does not re-fetch the KEV catalogue. |
| `EPSS_API_URL` | `https://api.first.org/data/v1/epss` | Overridable for an air-gapped mirror. |
| `EPSS_BATCH_SIZE` | - | CVEs per EPSS request. |
| `KEV_REFRESH_SECONDS` | - | How stale the KEV catalogue may get before a re-fetch. |

## State

| Variable | Default | Meaning |
|---|---|---|
| `BLOB_DIR` | `./.blobs` | Reports and uploads. A shared volume between API and worker. |
| `REPORTS_BUCKET` | - | S3 bucket for reports when deployed; unset uses `BLOB_DIR`. |
| `DYNAMODB_ENDPOINT_URL` | - | Unset means real AWS. Set for DynamoDB Local. |
| `SCAN_QUEUE_URL`, `SQS_ENDPOINT_URL` | local | Point at ElasticMQ or real SQS. |
| `REDIS_URL` | `redis://localhost:6379/0` | Rate limiting and progress pub/sub. |
| `REDIS_PASSWORD` | `localdev` locally | Redis AUTH. Kept out of `REDIS_URL` so the URL can stay a plain env var; deployed, it comes from Secrets Manager. |
| `AWS_REGION` | `us-east-1` | |

## Authentication

| Variable | Default | Meaning |
|---|---|---|
| `DEV_AUTH` | `0` | `1` mounts a local `/dev` JWKS endpoint and token issuer. **Never set it deployed** - `/dev/token` mints a token for any tenant to any caller. |
| `TOKEN_ISSUER` | the dev issuer | The `iss` claim that must match. Cognito's issuer URL when deployed. |
| `TOKEN_AUDIENCE` | `local-client-id` | The `aud` claim that must match. |
| `AUTH_ALLOW_DEV_DEFAULTS` | - | Guards the two defaults above from being used unintentionally outside local work. |
| `CORS_ORIGINS` | - | Comma-separated allowed origins. |

## Frontend

All five are read in the browser bundle or the Next server, and the `NEXT_PUBLIC_*` ones
are **baked in at build time** - changing one needs a rebuild, not a restart.

| Variable | Default | Meaning |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | - | Where the browser reaches the API. |
| `NEXT_PUBLIC_WS_URL` | - | Where the browser opens the progress WebSocket. |
| `NEXT_PUBLIC_COGNITO_USER_POOL_ID`, `NEXT_PUBLIC_COGNITO_CLIENT_ID` | - | Empty selects the `DEV_AUTH` token path; set, the UI requires a real Cognito sign-in. |
| `NEXT_PUBLIC_GRAFANA_URL` | - | Where the browser reaches Grafana for the Analytics tab's embed. Empty hides that tab. |
| `PROMETHEUS_URL` | compose service | **Server-side only**, deliberately not `NEXT_PUBLIC_`: the Analytics tabs query through a server proxy that accepts named panels, never raw PromQL. See [observability](../architecture/observability.md). |

## Observability

| Variable | Default | Meaning |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | - | Unset disables all telemetry - no exporter, no network calls, unchanged behaviour in the tests and the eval harness. `http://otel-collector:4318` with the observability profile up. |

## Host ports

Compose only, so a taken port on one machine does not become a code change.

| Variable | Default | Meaning |
|---|---|---|
| `API_PORT` | `8080` | Used by **both** the port mapping and the URL baked into the frontend bundle, so the two cannot disagree. |
| `BIFROST_PORT` | `8085` | The gateway's own UI. Not 8080, which the API already owns. |

---

## Related

- `example.env` - the runnable copy, with commentary on the non-obvious ones
- [Architecture overview](../architecture/overview.md) - what reads which of these
- [LLM gateway](../architecture/llm-gateway.md) - `LLM_GATEWAY_URL` and what it buys
- [Observability](../architecture/observability.md) - `OTEL_EXPORTER_OTLP_ENDPOINT` and the stack behind it
