# Audits

Point-in-time findings, each with a remediation status recorded in the document itself.

**These are historical by nature.** An audit describes what was wrong on the day it was
written; many of its findings have since been fixed, and the document says so inline rather
than being edited into agreement with the code. For what is true now, read
[architecture](../architecture/README.md).

| Audit | Scope |
|---|---|
| [01 - backend security and quality](audit-01-backend.md) | Trust integrity (P1), report quality (P2), correctness and QA (P3), infrastructure (P4), plus the Docker Scout and observability additions |
| [02 - frontend, worker, observability](audit-02-frontend-worker-observability.md) | 15 findings across the three areas, with a remediation section |

## They are cited from the source

Roughly a hundred comments across the Python, TypeScript and Terraform name a finding by
its identifier:

```python
# See docs/audits/audit-01-backend.md P4-1.
```

That is deliberate - it puts the reasoning next to the code it constrains. It also means
**renaming these files is a repo-wide change**, not a documentation one.
