from __future__ import annotations
import json
import os
import platform
import sys
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
    from grypereport.report import build
    from grypereport.__version__ import version as __version__
except (ImportError, ModuleNotFoundError) as error:
    print(error)
    sys.exit(1)


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "-i",
    "--input-json",
    "grype_json",
    default=None,
    multiple=False,
    required=False,
    # https://click.palletsprojects.com/en/stable/handling-files/
    type=click.File(mode="r", encoding="utf-8"),
    help="input grype-generated vulnerability report in JSON format",
)
@click.option(
    "-c",
    "--csv",
    "csv_export",
    default=False,
    multiple=False,
    required=False,
    is_flag=True,
    type=click.BOOL,
    help="export to csv",
)
@click.option(
    "--teamcity/--no-teamcity",
    " /-T",
    "teamcity",
    default=True,
    multiple=False,
    required=False,
    is_flag=True,
    type=click.BOOL,
    help="teamcity CI integration (default: True)",
)
@click.version_option(
    __version__,
    "-v",
    "--version",
    prog_name=click.style("grypereport", fg="green", bold=True),
    message=(
        f"%(prog)s, %(version)s\n"
        f"Python ({platform.python_implementation()}) {platform.python_version()}"
    ),
    help="show the version and exit",
)
@click.help_option("-h", "--help", help="show this message and exit")
def main(
    grype_json: Optional[click.File] = None,
    *,
    csv_export: bool = False,
    teamcity: bool = False,
) -> int:
    data: dict[str, Any]
    try:
        if grype_json is not None:
            data = json.load(grype_json)
        else:
            if not sys.stdin.isatty():
                print("Reading piped data...")
                data = json.loads(sys.stdin.read())
            else:
                raise ValueError("No input data provided (stdin is empty).")
    except (ValueError, json.JSONDecodeError) as error:
        print(
            "An error occurred while reading piped data, fallback to reading from default file."
        )
        try:
            default_json = Path("grype.json")
            if default_json.exists():
                with open(default_json, "r", encoding="utf-8") as grype_json:
                    data = json.load(grype_json)
            else:
                raise FileNotFoundError(
                    "No such file or directory: '{0}'.".format(default_json.name)
                )
        except (FileNotFoundError, json.JSONDecodeError) as error:
            sys.exit("Data import error: {0}".format(str(error)))
        except Exception as error:
            sys.exit("Unknown data import error: {0}".format(str(error)))

    if len(data.get("matches", list())) > 0:
        critical: int = len(
            tuple(
                item["vulnerability"].get("severity", "")
                for item in data.get("matches", list())
                if item["vulnerability"].get("severity", "").lower() == "critical"
            )
        )
        print(
            "Grype vulnerability scanner found {0} vulnerabilities. Critical: {1}".format(
                len(data.get("matches", list())), critical
            )
        )

        if teamcity:
            print(
                "##teamcity[addBuildTag 'vulnerabilities: {0} (critical: {1})']".format(
                    len(data.get("matches", list())), critical
                )
            )
        print("")
    else:
        print("Nothing to process.")
        return 1

    return build(data.get("matches", list()), csv_export)


if __name__ == "__main__":
    sys.exit(main())
