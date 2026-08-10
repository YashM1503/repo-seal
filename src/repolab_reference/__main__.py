"""Command-line entrypoint for the safe reference harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .agent_boundary import AgentBoundaryError
from .controlled import build_controlled_repository, write_trusted_verifier
from .controlled_agent import replay_controlled_agent_suite
from .falsification import check_fixture, iter_fixture_paths
from .replay import ReplayError, replay_suite


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m repolab_reference")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check-fixtures",
        help="verify that fixture expectations match falsification results",
    )
    check_parser.add_argument("directory", type=Path)

    replay_parser = subparsers.add_parser(
        "controlled-replay",
        help="build and replay the controlled ten-task M1 repository",
    )
    replay_parser.add_argument("output_directory", type=Path)

    agent_parser = subparsers.add_parser(
        "controlled-agent-replay",
        help="run the trusted M2a mock adapter across the controlled tasks",
    )
    agent_parser.add_argument("output_directory", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.command == "check-fixtures":
        return _check_fixtures(arguments.directory)
    if arguments.command == "controlled-replay":
        return _controlled_replay(arguments.output_directory)
    if arguments.command == "controlled-agent-replay":
        return _controlled_agent_replay(arguments.output_directory)
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


def _controlled_replay(output_directory: Path) -> int:
    if output_directory.exists():
        print("output_directory must not already exist", file=sys.stderr)
        return 2
    try:
        controlled = build_controlled_repository(output_directory / "repository")
        verifier = write_trusted_verifier(
            output_directory / "trusted" / "trusted_verifier.py"
        )
        receipt = replay_suite(
            repository=controlled.path,
            tasks=controlled.tasks,
            verifier_source=verifier,
            work_root=output_directory / "replay",
        )
        rendered = receipt.to_json()
        (output_directory / "receipt.json").write_text(
            rendered + "\n", encoding="utf-8"
        )
        print(rendered)
        return 0 if receipt.gate_passed and len(receipt.receipts) == 10 else 1
    except (OSError, ReplayError, ValueError) as error:
        print(f"controlled replay failed: {error}", file=sys.stderr)
        return 1


def _controlled_agent_replay(output_directory: Path) -> int:
    if output_directory.exists():
        print("output_directory must not already exist", file=sys.stderr)
        return 2
    try:
        controlled = build_controlled_repository(output_directory / "repository")
        verifier = write_trusted_verifier(
            output_directory / "trusted" / "trusted_verifier.py"
        )
        receipt = replay_controlled_agent_suite(
            repository=controlled.path,
            tasks=controlled.tasks,
            verifier_source=verifier,
            work_root=output_directory / "agent-replay",
        )
        rendered = receipt.to_json()
        (output_directory / "receipt.json").write_text(
            rendered + "\n", encoding="utf-8"
        )
        print(rendered)
        expected_outcome = (
            receipt.contract_gate_passed
            and not receipt.security_gate_passed
            and len(receipt.receipts) == 10
        )
        return 0 if expected_outcome else 1
    except (AgentBoundaryError, OSError, ReplayError, ValueError) as error:
        print(f"controlled agent replay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
