from __future__ import annotations
import os
import sys

if sys.version_info < (3, 10):
    print("Python version 3.10+ is required!")
    sys.exit(1)
import importlib.util
import json
import platform
from pathlib import Path
from pprint import pprint, pformat
from typing import Optional, Any


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
    "-o",
    "--csv-output",
    "csv_output",
    default="grype.csv",
    multiple=False,
    required=False,
    type=click.Path(dir_okay=False, file_okay=True, writable=True, exists=False),
    help="output csv file",
)
@click.option(
    "-f",
    "--fix-encoding",
    "encoding_fix",
    default=False,
    multiple=False,
    required=False,
    is_flag=True,
    type=click.BOOL,
    help="check and fix encoding for the 'description' field",
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
@click.option(
    "-n",
    "--image",
    "image_name",
    default=None,
    multiple=False,
    required=False,
    is_flag=False,
    type=click.STRING,
    help="image name",
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
    csv_output: click.Path | str,
    encoding_fix: bool = False,
    teamcity: bool = False,
    image_name: str | None = None,
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

    csv_path: Path = Path(csv_output)
    if csv_export:
        if csv_output is None:
            print(
                "{0} The path to the output CSV file must be specified.".format(
                    click.style("Input parameters error:", fg="red", bold=True)
                )
            )
            sys.exit(1)
        else:
            if not csv_path.parent.exists() or not os.access(
                csv_path.parent, os.W_OK
            ):  # current dir: Path(".")
                print(
                    "{0} Output directory '{1}' does not exist or not writable.".format(
                        click.style("Error:", fg="red", bold=True), csv_path.parent
                    )
                )
                sys.exit(1)

    if encoding_fix:
        if importlib.util.find_spec("ftfy") is None:
            print(
                "{0} {1} {2}".format(
                    click.style(f"Error:", fg="red", bold=True, reset=True),
                    f"Bad {click.style("'-f / --fix-encoding'", italic=True, reset=True)} option usage.",
                    "Extended validation of the 'description' field require 'ftfy' package.",
                )
            )
            print(
                "To fix this error, install 'ftfy' package via {0} command.".format(
                    click.style(
                        "pip install --upgrade 'grypereport[encoding]'",
                        fg="green",
                        italic=True,
                        underline=True,
                        reset=True,
                    )
                )
            )
            raise click.Abort

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
            tag_text = "{0} | vulnerabilities: {1} (critical: {2})".format(
                image_name, len(data.get("matches", list())), critical
            ) if image_name is not None else "vulnerabilities: {0} (critical: {1})".format(
                len(data.get("matches", list())), critical
            )
            print(f"##teamcity[addBuildTag '{tag_text}']")
        print("")
    else:
        print("Nothing to process.")
        return 1

    return build(data.get("matches", list()), csv_export, csv_path, encoding_fix)


if __name__ == "__main__":
    sys.exit(main())
