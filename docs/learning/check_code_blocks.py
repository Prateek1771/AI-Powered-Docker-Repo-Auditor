"""Every code block in the phase 9/10 docs that names a repo file must match it.

Run after editing either doc. Drift means the prose and the working code have
diverged, which is what let phases 9 and 10 ship teaching their own bugs.

    python docs/learning/check_code_blocks.py

EXEMPT holds files the docs deliberately no longer mirror - see the note in
phase 10 section 10. Those blocks are the minimal version that makes the
phase's argument; the shipped components carry a design system on top.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ["phase_09_realtime_process.md", "phase_10_frontend.md"]

# Presentation diverged from the docs in the UI rebuild. The state handling the
# phases actually teach - types, api client, hooks, tests - is still enforced.
EXEMPT = {
    "frontend/components/DegradedNotice.tsx",
    "frontend/components/ScoreCard.tsx",
    "frontend/components/FindingsEmpty.tsx",
    "frontend/components/EffortBreakdown.tsx",
    "frontend/app/page.tsx",
    "frontend/app/scans/[jobId]/page.tsx",
}

# "Create `path`:" (prose may wrap) then a fenced block.
INLINE = re.compile(
    r"(?:Create|Replace) `([^`]+\.(?:py|ts|tsx|mts))`.*?:\n+```[a-z]*\n(.*?)\n```",
    re.DOTALL,
)
# Phase 9 style: a ```text block listing paths, then the code block.
LISTED = re.compile(
    r"```text\n((?:[\w./\[\]-]+\n)+)```\n+```[a-z]*\n(.*?)\n```",
    re.DOTALL,
)


def resolve(declared: str) -> pathlib.Path | None:
    for candidate in (ROOT / declared, ROOT / "worker" / declared):
        if candidate.is_file():
            return candidate

    return None


def compare(declared: str, block: str, seen: set, bad: list, skipped: list) -> None:
    if declared in seen or declared in EXEMPT:
        if declared in EXEMPT and declared not in skipped:
            skipped.append(declared)

        return

    target = resolve(declared)

    if target is None:
        return

    seen.add(declared)

    if block.strip() == target.read_text(encoding="utf-8").strip():
        print(f"  OK    {declared}")
    else:
        print(f"  DRIFT {declared}")
        bad.append(declared)


def main() -> int:
    bad: list[str] = []
    skipped: list[str] = []
    seen: set[str] = set()

    for doc in DOCS:
        text = (ROOT / "docs/learning" / doc).read_text(encoding="utf-8")
        body = text[: text.index("# Errata")]

        print(f"\n{doc}")

        for match in INLINE.finditer(body):
            compare(match.group(1), match.group(2), seen, bad, skipped)

        for match in LISTED.finditer(body):
            # The last path in the list is what the following block implements.
            paths = [p for p in match.group(1).split() if "." in p]

            if paths:
                compare(paths[-1], match.group(2), seen, bad, skipped)

    print(f"\n{len(seen) - len(bad)}/{len(seen)} enforced blocks match their file")

    if skipped:
        print(f"{len(skipped)} exempt (presentation diverged by design)")

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
