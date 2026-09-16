"""Per-tenant suppression policy.

A scanner nobody can silence is a scanner people route around. But a
suppression that deletes evidence cannot be reviewed, cannot expire, and
quietly becomes permanent - which is how a security tool stops finding
anything without anyone deciding that.

So every suppression here needs a reason, may carry an expiry, and marks the
finding rather than dropping it. See docs/audits/audit-01-backend.md P2-7.

Stored as a blob at `policy/{tenant_id}`, reusing the tenant-as-directory
pattern from uploads: an id guessed from another tenant resolves to a key that
does not exist, so there is no ownership check to forget to write. No new
table, and it works identically on the filesystem and on S3.
"""

import logging
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from app.storage.blobs import get_blob, put_blob

logger = logging.getLogger(__name__)


class Suppression(BaseModel):
    """One accepted risk.

    Exactly one of the three targets is matched, most specific first:
    `fingerprint` pins one finding, `vulnerability_id` covers a CVE
    everywhere it appears, `package` covers everything in one package.
    """

    fingerprint: str = ""
    vulnerability_id: str = ""
    package: str = ""

    # Required, and the reason it is required: "suppressed" with no
    # explanation is indistinguishable from "lost", and six months later
    # nobody can tell whether it was a considered decision or a mistake.
    reason: str = Field(min_length=1)

    # ISO-8601. Absent means it never expires, which is allowed but is the
    # thing to look for when a report goes quiet.
    expires_at: str = ""

    added_by: str = ""
    added_at: str = ""

    def is_expired(self, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False

        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            # An unparseable expiry is treated as expired: the safe direction
            # is for the finding to come back, not to stay hidden forever on
            # the strength of a typo.
            logger.warning("Unparseable suppression expiry: %s", self.expires_at)

            return True

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)

        return expiry < (now or datetime.now(UTC))

    def matches(self, finding: dict) -> bool:
        """Whether this suppression covers a finding.

        Takes a plain dict because that is what the stored report holds -
        findings are model_dump()ed on the way in.
        """
        if self.fingerprint:
            return finding.get("fingerprint") == self.fingerprint

        if self.vulnerability_id:
            return finding.get("vulnerability_id") == self.vulnerability_id

        if self.package:
            return finding.get("package") == self.package

        return False


class Policy(BaseModel):
    suppressions: list[Suppression] = Field(default_factory=list)

    def active(self, now: datetime | None = None) -> list[Suppression]:
        return [s for s in self.suppressions if not s.is_expired(now)]


def policy_key(tenant_id: str) -> str:
    return f"policy/{tenant_id}"


def load_policy(tenant_id: str) -> Policy:
    """Read a tenant's policy, or an empty one.

    Never raises. A policy that cannot be read must not fail a scan - the
    failure direction is "we reported something you had accepted", which
    is noisy, rather than "we reported nothing", which is dangerous.
    """
    try:
        blob = get_blob(policy_key(tenant_id))

        if not blob:
            return Policy()

        return Policy.model_validate(blob)
    except Exception:
        logger.warning(
            "Could not load policy for %s, proceeding with none",
            tenant_id,
            exc_info=True,
        )

        return Policy()


def save_policy(tenant_id: str, policy: Policy) -> None:
    put_blob(policy_key(tenant_id), policy.model_dump())
