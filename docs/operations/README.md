# Operations

Running, configuring and deploying the auditor.

| Document | Covers |
|---|---|
| [Configuration](configuration.md) | Every environment variable the code actually reads |

Deployment and CI/CD are not duplicated here. The pipeline gates are in the
[repo README](../../README.md#ci-gate), the infrastructure is 11 Terraform modules under
`terraform/`, and the reasoning for both is in build phases
[12](../history/build-phases/12-infrastructure.md) and
[13](../history/build-phases/13-cicd.md).

There are no runbooks yet. The alerts in `observability/alerts.yml` each name the failure
they were written for - see [observability](../architecture/observability.md) - but nothing
yet documents the response.
