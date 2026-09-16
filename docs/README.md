# Documentation

Everything written about this project, organised by what you are trying to do.

The repository [`README.md`](../README.md) is the front door - what was built, quick start,
the API surface and the CI gates. This tree is the depth behind it.

---

## Start here

| | |
|---|---|
| **[Architecture](../README.md#architecture)** | What talks to what, and why - the diagrams are in the repo README |
| [Setup](../README.md#setup) | Local, the UI, AWS and CI/CD |
| [Configuration](operations/configuration.md) | Every environment variable, verified against the code |

## Architecture

The current system. If one of these disagrees with the code, the document is wrong.

- [Overview](architecture/overview.md) - where each piece lives; the component diagram itself is in the [repo README](../README.md#architecture)
- [The scan pipeline](architecture/pipeline.md) - pointers to the [lifecycle](../README.md#the-scan-lifecycle) and [agent graph](../README.md#the-agent-graph) diagrams
- [Observability](architecture/observability.md) - the collector, the instruments, the alerts, the Analytics tabs
- [The LLM gateway](architecture/llm-gateway.md) - Bifrost, cost, key health, and what caching does *not* do

## Operations

- [Configuration](operations/configuration.md) - environment variables
- [Deployment and CI/CD](../README.md#ci-gate) - the pipeline gates, in the repo README
- Infrastructure: `terraform/` - 11 modules, walked through in [build phase 12](history/build-phases/12-infrastructure.md)

## Development

- [Tests](../README.md#tests) - unit, integration, eval, frontend
- [The docs gate](../README.md#ci-gate) - `scripts/check_code_blocks.py` diffs every code block in the build phases against the file it was copied from
- [Evaluation harness](history/build-phases/05-evaluation-harness.md) - recall, precision, stability

## Security

- [Audit 01](audits/audit-01-backend.md) §3-6 - trust integrity, report quality, correctness, infrastructure
- [Audit 02](audits/audit-02-frontend-worker-observability.md) - frontend, worker, observability
- [Known limitations](../README.md#known-limitations-audited-not-hidden) - the short list, in the repo README

## Design records

Decisions and open proposals. Not architecture - some of this has not been built.

- [Pipeline graph](design/pipeline-graph.md) - the React Flow decision record; backend landed, graph deferred
- [Improvements](design/improvements.md) - what this would need to be a product, and to be production software

## Audits

Point-in-time findings with a remediation status. **Historical by nature** - read the
architecture docs for what is true now.

- [Audit 01 - backend security and quality](audits/audit-01-backend.md)
- [Audit 02 - frontend, worker, observability](audits/audit-02-frontend-worker-observability.md)

## Engineering history

- [Build phases 01-14](history/build-phases/README.md) - the reasoning behind each layer, written as it was built

## Generated

- [`code-graph/`](code-graph/GRAPH_REPORT.md) - a structural graph of the whole repo, built from tree-sitter ASTs. Regenerated, never hand-edited.
- [`index.html`](index.html) - the GitHub Pages landing page for this directory
- [`assets/screenshots/`](assets/screenshots) - images referenced from the docs and the repo README

---

## How this is organised

| Directory | Contains | Canonical for |
|---|---|---|
| `architecture/` | The system as it is today | architecture, pipeline, observability, gateway |
| `operations/` | Running and configuring it | configuration |
| `audits/` | Point-in-time findings | security findings |
| `design/` | Decisions and proposals | product and production gaps |
| `history/` | How it was built | nothing current |
| `code-graph/`, `assets/` | Generated and binary | nothing |

One canonical document per subject. Where a build phase and an architecture document cover
the same ground, **the architecture document wins** - a phase describes the state at the
time it was written, and several describe bugs that have since been fixed.
