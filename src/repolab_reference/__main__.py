"""Command-line entrypoint for the safe reference harness."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from .falsification import check_fixture, iter_fixture_paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m repolab_reference")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check-fixtures",
        help="verify that fixture expectations match falsification results",
    )
    check_parser.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.command == "check-fixtures":
        return _check_fixtures(arguments.directory)
    parser.error(f"unsupported command: {arguments.command}")
    return 2


def _check_fixtures(directory: Path) -> int:
    paths = tuple(iter_fixture_paths(directory))
    if not paths:
        print(f"No JSON fixtures found in {directory}", file=sys.stderr)
        return 2

    records = []
    success = True
    for path in paths:
        try:
            fixture, result = check_fixture(path)
            expected = tuple(code.value for code in fixture.expected_failures)
            actual = tuple(code.value for code in result.codes)
            matched = actual == expected
            records.append(
                {
                    "fixture": fixture.name,
                    "path": str(path),
                    "expected": list(expected),
                    "actual": list(actual),
                    "matched": matched,
                }
            )
            success = success and matched
        except (OSError, ValueError, json.JSONDecodeError) as error:
            records.append(
                {
                    "fixture": path.stem,
                    "path": str(path),
                    "matched": False,
                    "error": str(error),
                }
            )
            success = False

    print(
        json.dumps(
            {
                "passed": success,
                "fixture_count": len(paths),
                "records": records,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
