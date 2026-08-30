"""Every code block in the phase 9-13 docs that names a repo file must match it.

Run after editing any of them. Drift means the prose and the working code have
diverged, which is what let phases 9 and 10 ship teaching their own bugs.

    python docs/learning/check_code_blocks.py
    python docs/learning/check_code_blocks.py --write

--write pushes each file's current contents back into its block, which is the
direction that makes sense: the code is the source of truth and the doc quotes
it. It is also the only sane way to resync phases 9 and 10, whose blocks were
placed by hand rather than by a generator.

EXEMPT holds files the docs deliberately no longer mirror - see the note in
phase 10 section 10, and phase 11 section 3, where the block is a quoted
excerpt making a point rather than the file.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = [
    "phase_09_realtime_process.md",
    "phase_10_frontend.md",
    "phase_11_containerisation.md",
    "phase_12_infrastructure.md",
    "phase_13_cicd.md",
]

# Presentation diverged from the docs in the UI rebuild. The state handling the
# phases actually teach - types, api client, hooks, tests - is still enforced.
EXEMPT = {
    "frontend/components/DegradedNotice.tsx",
    "frontend/components/ScoreCard.tsx",
    "frontend/components/FindingsEmpty.tsx",
    "frontend/components/EffortBreakdown.tsx",
    "frontend/app/page.tsx",
    "frontend/app/scans/[jobId]/page.tsx",
    # Phase 11 section 3 quotes build_command() to make an argument about where
    # Trivy runs. It is four lines of a file, deliberately elided.
    "app/scanners/trivy.py",
    # Phase 9 shows one function and one router registration, not the files
    # they live in - "Update run_and_store in ..." and "Register it in ...".
    "app/orchestrator.py",
    "app/api/main.py",
}

# Terraform lives at the repo root, and phase 12 names its files that way.

# A backticked path, whatever prose follows on that line, a colon, then a fence.
# Covers "Create `x`:", "Replace `x`:", "Enable ... in `x`:", "`x` in the
# project root:". Anything that does not resolve to a real file is skipped, so
# a loose match costs nothing.
INLINE = re.compile(
    r"`([\w./\[\]-]+)`[^\n`]*:\n+```[a-z]*\n(.*?)\n```",
    re.DOTALL,
)
# Phase 9 style: a ```text block listing paths, then the code block.
LISTED = re.compile(
    r"```text\n((?:[\w./\[\]-]+\n)+)```\n+```[a-z]*\n(.*?)\n```",
    re.DOTALL,
)


def resolve(declared: str) -> pathlib.Path | None:
    """Find the repo file a doc block names, or None if it does not exist.

    Paths are written either from the repo root or from inside worker/, and a
    name that resolves to neither is prose rather than a declaration.
    """
    for candidate in (ROOT / declared, ROOT / "worker" / declared):
        if candidate.is_file():
            return candidate

    return None


def compare(
    declared: str,
    block: str,
    span: tuple[int, int],
    seen: set,
    bad: list,
    skipped: list,
    edits: list,
) -> None:
    """Check one block against its file, recording where a rewrite would go.

    Only the first mention of a path is enforced. A doc that shows a file twice
    is making a point with the second one, and overwriting it would delete the
    point.
    """
    if declared in seen or declared in EXEMPT:
        if declared in EXEMPT and declared not in skipped:
            skipped.append(declared)

        return

    target = resolve(declared)

    if target is None:
        return

    seen.add(declared)

    current = target.read_text(encoding="utf-8").strip()

    if block.strip() == current:
        print(f"  OK    {declared}")
    else:
        print(f"  DRIFT {declared}")
        bad.append(declared)
        edits.append((span, current))


def apply(path: pathlib.Path, edits: list) -> None:
    """Replace each drifting block in a doc with its file's contents.

    Applied back to front so an earlier edit never shifts a later offset, and
    against the doc's full text so everything past the errata marker survives
    untouched - those sections quote the broken code on purpose.
    """
    full = path.read_text(encoding="utf-8")

    for (start, end), current in sorted(edits, reverse=True):
        full = full[:start] + current + full[end:]

    path.write_text(full, encoding="utf-8")

    print(f"  wrote {len(edits)} block(s) into {path.name}")


def main() -> int:
    """Report drift between the phase docs and the files they quote."""
    write = "--write" in sys.argv

    bad: list[str] = []
    skipped: list[str] = []
    seen: set[str] = set()

    for doc in DOCS:
        path = ROOT / "docs/learning" / doc
        text = path.read_text(encoding="utf-8")

        # Errata sections quote the broken version on purpose; a doc corrected
        # inline from the start has none.
        if "# Errata" in text:
            text = text[: text.index("# Errata")]

        print(f"\n{doc}")

        edits: list = []

        for match in INLINE.finditer(text):
            compare(
                match.group(1), match.group(2), match.span(2), seen, bad, skipped, edits
            )

        for match in LISTED.finditer(text):
            # The last path in the list is what the following block implements.
            paths = [p for p in match.group(1).split() if "." in p]

            if paths:
                compare(
                    paths[-1], match.group(2), match.span(2), seen, bad, skipped, edits
                )

        if write and edits:
            apply(path, edits)

    if write:
        print("\nrewritten - run again without --write to confirm")

        return 0

    print(f"\n{len(seen) - len(bad)}/{len(seen)} enforced blocks match their file")

    if skipped:
        print(f"{len(skipped)} exempt (presentation or excerpt, by design)")

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
