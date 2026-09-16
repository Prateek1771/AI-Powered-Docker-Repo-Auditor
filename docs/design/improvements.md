# What This Would Need To Be A Product, And To Be Production Software

A candid assessment, written after auditing the three layers and then running the whole
thing end to end. Every claim below names the file it came from.

The summary is that this repository is an **excellent engineering artifact and a weak
product**. Those are different scores and it is worth keeping them apart:

| Judged as | Score | Why |
|---|---|---|
| A learning artifact / portfolio piece | 9/10 | Genuinely top decile. See §3. |
| A product someone would pay for | 3/10 | §1 |
| Production software | 4/10 | §2 |

What follows is the case for the two low scores, and what would move them.

---

## 1. Product: 3/10

### 1.1 The best feature cannot be bought

`app/cli.py` is the CI gate — `--fail-on-severity high`, exit 0/1/2. It is the one feature
here with an unambiguous job to be done: fail a build when an image is too vulnerable to
ship.

It cannot be sold, because it does not call the API:

```
app/cli.py:21   from app.orchestrator import run_scan
app/cli.py:73   scan = asyncio.run(run_scan(args.target))
```

It runs the **entire pipeline in-process**. To use it, a customer must install the worker
package, provide Docker-in-Docker, mount a Docker socket into their CI job, and supply
their own OpenAI key. That is a library they self-host and pay OpenAI for directly. There
is no hosted path.

And they could not call the API instead even if the CLI offered it, because **no machine
credential exists**. `terraform/modules/auth/main.tf:29-40` provisions a public browser
client:

```hcl
generate_secret = false
explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
```

No resource server, no `client_credentials` grant. Cognito here can authenticate a human
at a keyboard and nothing else. A CI job has no way in.

**The fix, in order:** a `scan_keys` table keyed by tenant; `Authorization: Bearer sk_...`
accepted alongside the JWT path in `app/core/auth.py`; a `--api-url/--token` client mode in
the CLI that POSTs to `/api/v1/scans` and polls. Then
`auditor scan myimage:tag --fail-on-severity high` works in anyone's CI with one secret and
no Docker socket. This is the single change that turns a demo into a business.

### 1.2 The UI renders a state no user can create

`app/policy/store.py:123` defines `save_policy()`. Nothing calls it — not a route, not the
CLI, nothing. Yet `apply_policy()` runs on every `GET /report` (`app/api/scans.py:132`) and
`FindingCard.tsx` renders `suppressed`, `suppressed_reason` and `suppressed_until`
faithfully.

So the suppression feature is fully built on the read side and has no write side. The only
way to suppress a finding today is to hand-write a blob into storage.

This matters more than its size suggests: without it, every rescan re-reports what the team
already looked at and accepted. That is the specific reason security tools get muted and
then switched off. `POST/GET/DELETE /api/v1/policy/suppressions` plus an "Accept this risk"
button is a day of work — every finding already carries a `fingerprint` to key it on.

### 1.3 There is nothing to charge for

One tenant is one Cognito `sub`. There are no organisations, no teams, no invitations, no
roles, no seats. `SCAN_LIMIT = 5` (`app/config/api.py:40`) is a module constant, not a plan
tier, and there is no usage metering of any kind.

Billing is not a feature you bolt on; it is a data model. Tenants need to be first-class
rows with a plan, a quota read from that row, and recorded usage.

### 1.4 The model writes prose, it does not find things

Strip the LLM out and Trivy still finds every CVE. The agents summarise, rank and narrate
scanner output. That is worth something, but it is not worth a subscription, and it is the
part a competitor reproduces in a weekend.

Three things a model could add that a scanner cannot:

- **Base-image advice backed by a registry lookup.** The README already lists this as a
  known limitation: `base_image_strategist` performs no lookup and recommends from training
  memory, so it names tags that were current at training time. A registry API turns a guess
  into a fact.
- **Reachability.** Is the vulnerable symbol actually called by this image's entrypoint?
  This is the single biggest noise reducer in the category and nothing here attempts it.
- **Tested fix-paths.** Not "upgrade libcrypto3" but the diff that does it, built and
  proven not to break the image.

And the inverse: **delete agents that do not pay their way.** Measure each against the eval
harness and cut any a deterministic rule matches. `bloat_detective` versus
`docker history | sort -h` is the first test to run — the CIS controls already made this
move, from model judgement to `check_deterministic_controls()`, and got strictly better.

### 1.5 Nobody can try it

There is no hosted instance, no sample report, no "scan a public image" link. The README is
unusually good and the first thing a reader can do with it is clone a repo and run
Terraform.

---

## 2. Production software: 4/10

### 2.1 It has never run successfully on AWS

This is the one that subsumes the rest. Found while auditing:

- `terraform/modules/ecs/main.tf` set `JWKS_URL` and `TOKEN_AUDIENCE` but **not
  `TOKEN_ISSUER`**, and `assert_production_auth()` treats that as a refuse-to-start
  condition. The API task raised `InsecureAuthConfig` and crash-looped.
- The frontend's only auth path was `/dev/token`, which 404s wherever `DEV_AUTH` is unset —
  as Terraform correctly leaves it.

Both are now fixed, but the point stands: nothing had ever exercised the deployment, so
every claim `docs/history/build-phases/12-infrastructure.md` makes is untested. Until one
green deploy exists, `terraform/` is aspiration.

### 2.2 JWTs travel over plain HTTP

Tasks run with `assign_public_ip`. There is **no `aws_lb`, no ACM certificate, no HTTPS
listener anywhere in `terraform/`**. Identity tokens and full vulnerability reports cross
the public internet in clear text.

This is the highest-severity production issue in the repository, and fixing it also
supplies the stable hostname that the frontend, the smoke test, and any future OAuth
callback all need.

### 2.3 Detective controls are still absent

Zero `aws_cloudwatch_metric_alarm`. Zero `aws_sns_topic`. No ADOT sidecar, no `OTEL_*` in
any task definition. The seven Prometheus alert rules evaluate against a local stack and
reach nobody.

`docs/audits/audit-01-backend.md` opens at §1.3 with "there is no detective control anywhere in the
infrastructure". That is still true. A local Grafana is not a control.

### 2.4 No capacity or failure story

No autoscaling, no multi-AZ, fixed `desired_count`. One task per service. A traffic spike
queues behind a single worker; an AZ event is an outage.

### 2.5 Data protection is half-built

Present and good: DynamoDB point-in-time recovery, S3 versioning.

Absent: no KMS customer-managed key, no `deletion_protection` on anything, no AWS Backup
plan, no restore ever rehearsed. And still open from the first audit, **P4-2**: the OpenAI
key is written into Terraform state, in an unmanaged state bucket.

### 2.6 The release process shipped stale images

While testing I found the running API image was 18 hours old and the frontend image 17
**days** old, both serving traffic while the source had long moved on. Nothing asserted
that a running image matched the commit that was supposed to be deployed.

A deploy should refuse to ship an image older than `HEAD`, and a smoke test should assert
the build SHA it is talking to.

### 2.7 Throttling is per tenant, and tenants are free

The rate limiter keys on `ratelimit:scan:{tenant_id}`. Locally, `/dev/token` mints a token
for any tenant on request; deployed, sign-up is open. An unauthenticated flood still
reaches `verify_token` and the JWKS fetch before any quota is consulted. This needs an
edge-level limit — WAF rules or an ALB listener rule.

---

## 3. What is genuinely good, and worth preserving

Listing the flaws without this would misrepresent the work.

- **The degradation model.** `AgentOutcome.is_trustworthy`, and splitting
  `skipped_no_input` ("we looked, there was nothing") from `skipped_missing_input` ("the
  evidence never arrived"), is better thinking than most shipped production systems
  contain. It is applied consistently from the model layer to the dashed ring in the UI.
- **Deterministic before model.** CIS controls and secret findings are computed from the
  image config before any agent runs, so they survive every agent failing and no injected
  text can alter them. This is the right architecture for a security tool and the project
  moved *toward* it over time.
- **Comments that name the rejected alternative.** `to_thread` on blocking boto3 calls,
  `EXPIRE` after `ZADD`, `Exception` rather than `BaseException` in the gather loop,
  accepting a WebSocket before closing it so the browser sees 1008 rather than 1006 — each
  explains the bug the obvious version causes. This is rare and it is why auditing this
  codebase was fast.
- **The docs gate.** `check_code_blocks.py` enforcing that every phase-doc code block still
  matches its file is a real control, not a gesture.

The instincts are good. They are pointed at too large a surface. A smaller product built
with this much care would be worth paying for.

---

## 4. Sequence

1. **§2.1** — deploy once, end to end. Nothing else is provable until it does.
2. **§2.2** — TLS. A severity issue on a live system.
3. **§1.1** — API keys and CLI client mode. The item that changes what this is.
4. **§1.2** — suppression write path. Small, and the difference between a report and a
   workflow.
5. **§2.3** — alarms and routing, closing §1.3 of the original audit.

Everything else is real and secondary.
