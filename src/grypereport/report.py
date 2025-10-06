from __future__ import annotations
import csv
import json
import os
import platform
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from math import floor
from pathlib import Path
from pprint import pprint, pformat
from typing import Optional, Any, TypeVar, cast, TypedDict, Final

try:
    """setting __package__ attribute for imports."""
    if __package__ is None:
        pathname = Path(__file__).resolve()
        for item in [
            parent for parent in pathname.parents if str(parent) != str(pathname.parent)
        ]:
            sys.path.append(str(item))  # updating sys.path
    import click  # type: ignore
    from grypereport.__version__ import version as __version__
except (ImportError, ModuleNotFoundError) as error:
    print(error)
    sys.exit(1)


class FixAvailable(TypedDict):
    version: str
    date: str
    kind: str


class Fix(TypedDict, total=False):
    state: str
    versions: list[str]
    # available: list[dict[str, str]]
    available: list[FixAvailable]


@dataclass(order=True, kw_only=True)
class ReportEntry:
    package: str = ""
    version: str = ""
    source: str | None = ""
    namespace: str | None = ""
    # fix: Fix = field(default_factory=lambda: cast(Fix, {}), metadata={"nested": False})
    fix: dict[str, str | list[str] | list[dict[str, str]]] = field(
        default_factory=dict, metadata={"nested": False}
    )
    fix_report: str = ""
    pkg_type: str = ""
    vulnerability: str = ""
    severity: str = ""
    purl: str | None = ""
    locations: list[dict[str, str | dict[str, Any]]] = field(
        default_factory=list, metadata={"nested": False}
    )
    locations_report: str | None = ""
    description: str | None = ""
    epss: list[dict[str, Any]] | None = None
    epss_report: str = ""
    risk: float = 0.0
    risk_report: str | None = ""


@dataclass(order=True, kw_only=True)
class VulnerabilitiesReport:
    entries: list[ReportEntry] = field(
        default_factory=list, metadata={"description": "report entries", "nested": True}
    )


def lengths(report: VulnerabilitiesReport) -> dict[str, int]:
    """Fields length calculation."""
    return {
        "name": len(max((item.package for item in report.entries), key=len)),
        "version": len(max((item.version for item in report.entries), key=len)),
        "fix": len(max((item.fix_report for item in report.entries), key=len)),
        "type": len(max((item.pkg_type for item in report.entries), key=len)),
        "id": len(max((item.vulnerability for item in report.entries), key=len)),
        "severity": len(max((item.severity for item in report.entries), key=len)),
        "epss": len(max((item.epss_report for item in report.entries), key=len)),
        # "risk": len(max((item.risk_report for item in report.entries),key=len)),
        "risk": len(
            max(
                (
                    "{0} ({1})".format(
                        (
                            str(round(item.risk, 1))
                            if round(item.risk, 1) >= 0.1
                            else "< 0.1"
                        ),
                        round(item.risk, 4),
                    )
                    for item in report.entries
                ),
                key=len,
            )
        ),
    }


def ordinal(percentile: int) -> str:
    """Adding suffix to epss percentile value"""

    if 10 <= percentile % 100 <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(percentile % 10, "th")

    return f"{percentile}{suffix}"


def normalize_description(text: str, encoding_fix: bool = False) -> str:
    """Normalize the "description" field and remove non-ASCII characters."""

    _replace: dict[str, str] = {
        '"': "'",
    }

    # print("text: {0}".format(text))
    if encoding_fix:
        try:
            from ftfy import fix_text  # type: ignore
        except (ImportError, ModuleNotFoundError) as error:
            print(error)
            return text
        else:
            return (
                "".join(
                    _replace.get(char, char)
                    for char in " ".join(fix_text(text).split())
                )
                if text is not None
                else text
            )

    return (
        "".join(
            ch
            for ch in unicodedata.normalize(
                "NFKD",
                "".join(
                    _replace.get(char, char)
                    for char in " ".join(" ".join(text.splitlines()).split())
                ),
            )
            if not unicodedata.combining(ch)
        )
        .encode("ascii", errors="ignore")
        .decode("ascii")
        if text is not None
        else text
    )


def print_header(field_lengths: dict[str, int]) -> None:
    """Printing report header."""

    print(
        "{idx:>3} {0:<{n}} {1:<{v}} {2:<{f}} {3:<{t}} {4:<{i}} {5:<{s}} {6:<{e}} {7:<{r}}".format(
            "NAME",
            "INSTALLED",
            "FIXED IN",
            "TYPE",
            "VULNERABILITY",
            "SEVERITY",
            "EPSS",
            "RISK",
            idx="#",
            n=field_lengths["name"],
            v=field_lengths["version"],
            f=field_lengths["fix"],
            t=field_lengths["type"],
            i=field_lengths["id"],
            s=field_lengths["severity"],
            e=field_lengths["epss"],
            r=field_lengths["risk"],
        )
    )

    print(
        "{0} {1} {2} {3} {4} {5} {6} {7} {8}".format(
            "-" * 3,
            "-" * field_lengths["name"],
            "-" * field_lengths["version"],
            "-" * field_lengths["fix"],
            "-" * field_lengths["type"],
            "-" * field_lengths["id"],
            "-" * field_lengths["severity"],
            "-" * field_lengths["epss"],
            "-" * field_lengths["risk"],
        )
    )


def report_output(
    entries: list[ReportEntry],
    field_lengths: dict[str, int],
    export: bool = False,
    csv_path: Optional[os.PathLike[str]] = None,
) -> None:
    """Printing a report to stdout and/or exporting to CSV."""

    if export and csv_path is not None:
        with open(
            csv_path, mode="w", newline="", encoding="utf-8-sig"
        ) as csv_report:  # "utf-8" -> "utf-8-sig"
            writer = csv.DictWriter(
                csv_report,
                fieldnames=[
                    "NAME",
                    "INSTALLED",
                    "NAMESPACE",
                    "FIXED",
                    "FIXED IN",
                    "TYPE",
                    "VULNERABILITY",
                    "SEVERITY",
                    "PURL",
                    "LOCATIONS",
                    "EPSS",
                    "RISK",
                    "SOURCE",
                    "DESCRIPTION",
                ],
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()  # write header to csv

            # write entries to csv
            for idx, entry in enumerate(entries):
                writer.writerow(
                    {
                        "NAME": entry.package,
                        "INSTALLED": entry.version,
                        "NAMESPACE": entry.namespace,
                        "FIXED": entry.fix.get("state", ""),
                        "FIXED IN": (
                            ", ".join(
                                # [version for version in cast(list[str], entry.fix.get("versions", []))]
                                cast(list[str], entry.fix.get("versions", []))
                            )
                            if entry.fix.get("state", "") == "fixed"
                            else ""
                        ),
                        "TYPE": entry.pkg_type,
                        "VULNERABILITY": entry.vulnerability,
                        "SEVERITY": entry.severity,
                        "PURL": entry.purl,
                        "LOCATIONS": entry.locations_report,
                        "EPSS": entry.epss_report,
                        "RISK": entry.risk_report,
                        "SOURCE": entry.source,
                        "DESCRIPTION": entry.description,
                    }
                )

    print_header(field_lengths)  # print header to stdout
    # print entries to stdout
    for idx, entry in enumerate(entries, start=1):
        print(
            "{entry_index:>3} {0:<{n}} {1:<{v}} {2:<{f}} {3:<{t}} {4:<{i}} {5:<{s}} {6:<{e}} {7:<{r}}".format(
                entry.package,
                entry.version,
                entry.fix_report,
                entry.pkg_type,
                entry.vulnerability,
                entry.severity,
                entry.epss_report,
                entry.risk_report,
                entry_index=idx,
                n=field_lengths["name"],
                v=field_lengths["version"],
                f=field_lengths["fix"],
                t=field_lengths["type"],
                i=field_lengths["id"],
                s=field_lengths["severity"],
                e=field_lengths["epss"],
                r=field_lengths["risk"],
            )
        )


def build(
    matches: list[dict[str, Any]],
    export: bool = False,
    csv_path: Optional[os.PathLike[str]] = None,
    encoding_fix: bool = False,
) -> int:
    """Building vulnerabilities report."""

    # building a dataclass with report entries
    report = VulnerabilitiesReport()
    for idx, item in enumerate(matches):
        artifact: dict[str, Any] = item.get("artifact", {})
        details: list[dict[str, Any]] = item.get("matchDetails", [])
        vulnerability: dict[str, Any] = item.get("vulnerability", {})
        report.entries.append(
            ReportEntry(
                package=artifact.get("name", None),
                version=artifact.get("version", None),
                source=vulnerability.get("dataSource", None),
                namespace=vulnerability.get("namespace", None),
                fix=vulnerability.get("fix", {}),
                fix_report="{0}".format(
                    "{0} ({1})".format(
                        vulnerability.get("fix", {}).get("state", ""),
                        ", ".join(
                            [
                                item
                                for item in vulnerability.get("fix", {}).get(
                                    "versions", []
                                )
                            ]
                        ),
                    )
                    if vulnerability.get("fix", {}).get("state", "") == "fixed"
                    else vulnerability.get("fix", {}).get("state", "")
                ),
                pkg_type=artifact.get("type", None),
                vulnerability=vulnerability.get("id", None),
                severity=vulnerability.get("severity", None),
                purl=artifact.get("purl", None),
                locations=artifact.get("locations", []),
                locations_report=", ".join(
                    item.get("path", "") for item in artifact.get("locations", [])
                ),
                description=normalize_description(
                    vulnerability.get("description", None), encoding_fix
                ),  # normalized description
                epss=vulnerability.get("epss", None),
                epss_report=", ".join(
                    "{0:<}% ({1})".format(
                        (
                            str(round(item.get("epss", 0.0) * 100, 1))
                            if round(item.get("epss", 0.0) * 100, 1) > 0.1
                            else "< 0.1"
                        ),
                        ordinal(floor(item.get("percentile", 0.0) * 100)),
                    )
                    for item in vulnerability.get("epss", [])
                ),
                risk=vulnerability.get("risk", 0.0),
                risk_report="{0} ({1:<.4f})".format(
                    "{0}".format(
                        str(round(vulnerability.get("risk", 0), 1))
                        if round(vulnerability.get("risk", 0), 1) >= 0.1
                        else "< 0.1"
                    ),
                    round(vulnerability.get("risk", 0.0), 4),
                ),
            )
        )
    # pprint(report, indent=2, sort_dicts=False)

    try:
        report_output(report.entries, lengths(report), export, csv_path)
    except Exception as error:
        print("Runtime error: {0}".format(str(error)))
        return 1

    return 0
