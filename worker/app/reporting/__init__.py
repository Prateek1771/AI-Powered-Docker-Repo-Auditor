"""Export formats, in one table.

The API and the CLI both need the same question answered - "what does
`sarif` mean?" - and answering it twice is how the two end up disagreeing
about the media type or the file extension.

Every renderer is a pure function from the stored report dict to a string,
so an export works against any historical scan without re-running it, and
tests need no scan at all.
"""

from collections.abc import Callable
from typing import NamedTuple

from app.reporting.cyclonedx import to_cyclonedx
from app.reporting.sarif import to_sarif
from app.reporting.tabular import to_csv, to_junit


class Format(NamedTuple):
    render: Callable[[dict], str]
    media_type: str
    extension: str


FORMATS: dict[str, Format] = {
    "sarif": Format(to_sarif, "application/sarif+json", "sarif"),
    "cyclonedx": Format(to_cyclonedx, "application/vnd.cyclonedx+json", "cdx.json"),
    "csv": Format(to_csv, "text/csv", "csv"),
    "junit": Format(to_junit, "application/xml", "xml"),
}

__all__ = ["FORMATS", "Format", "to_csv", "to_cyclonedx", "to_junit", "to_sarif"]
