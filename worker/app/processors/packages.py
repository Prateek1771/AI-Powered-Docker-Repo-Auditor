"""The image's full package inventory, for the SBOM.

Trivy already reports every package it finds, not just the vulnerable ones -
`--list-all-pkgs` puts them in `Results[].Packages`. Nothing read that key, so
the one run we already pay for carried a complete bill of materials and threw
it away, and generating an SBOM looked like it needed a second scan.

Stored on the report blob because the raw Trivy output is discarded the moment
it is reduced, and CycloneDX is generated on read from the stored report.
"""

from pydantic import BaseModel, Field


class Package(BaseModel):
    name: str
    version: str = ""

    # The package URL - purl - is what makes a component resolvable rather
    # than a name a human has to guess at. CycloneDX keys on it.
    purl: str = ""

    licenses: list[str] = Field(default_factory=list)

    # Which Trivy result it came from: the OS layer, a lockfile, a jar.
    source: str = ""


def extract_packages(trivy_data: dict) -> list[Package]:
    """Flatten every package Trivy listed into one inventory.

    Deduplicated on (name, version, purl): the same library vendored into
    several jars is one component in a bill of materials, even though it is
    several findings in a vulnerability report.
    """
    seen: dict[tuple[str, str, str], Package] = {}

    for result in trivy_data.get("Results") or []:
        source = result.get("Target", "")

        for entry in result.get("Packages") or []:
            name = entry.get("Name", "")

            if not name:
                continue

            # Trivy moved the purl under Identifier in newer schemas and kept
            # a top-level PURL in older ones; read both so a Trivy bump does
            # not silently empty the SBOM.
            identifier = entry.get("Identifier") or {}

            purl = identifier.get("PURL") or entry.get("PURL") or ""

            # PURL is sometimes an object with a `.purl` string on it.
            if isinstance(purl, dict):
                purl = purl.get("purl", "")

            version = entry.get("Version", "")

            seen.setdefault(
                (name, version, str(purl)),
                Package(
                    name=name,
                    version=version,
                    purl=str(purl),
                    licenses=list(entry.get("Licenses") or []),
                    source=source,
                ),
            )

    return list(seen.values())
