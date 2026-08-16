"""Command-line entrypoint for RepoSeal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .agent_boundary import AgentBoundaryError
from .controlled import build_controlled_repository, write_trusted_verifier
from .controlled_agent import replay_controlled_agent_suite
from .docker_backend import (
    DockerBackendError,
    DockerIsolationPolicy,
    docker_isolation_plan,
    run_docker_isolation_preflight,
)
from .evidence import validate_evidence_path, write_evidence_draft
from .falsification import check_fixture, iter_fixture_paths
from .isolation import IsolationProbeError, run_host_process_negative_control
from .replay import ReplayError, replay_suite
from .review_bundle import create_security_review_bundle
from .version import __version__


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reposeal",
        description="Fail-closed checks for coding-agent benchmark evidence.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    draft_parser = subparsers.add_parser(
        "new-evidence",
        help="create a fail-closed evidence draft with every observation unset",
    )
    draft_parser.add_argument("output_file", type=Path)
    draft_parser.add_argument("--task-id", required=True)

    validate_parser = subparsers.add_parser(
        "validate",
        help="validate an evidence JSON file or directory and explain the decision",
    )
    validate_parser.add_argument("evidence_path", type=Path)
    validate_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="print the deterministic JSON receipt instead of the human report",
    )
    validate_parser.add_argument(
        "--output",
        type=Path,
        help="also save the JSON receipt to a new file",
    )

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

    isolation_parser = subparsers.add_parser(
        "isolation-preflight",
        help="run the M2b host-process negative-control isolation probes",
    )
    isolation_parser.add_argument("output_directory", type=Path)

    docker_plan_parser = subparsers.add_parser(
        "docker-isolation-plan",
        help="render the pinned M2b Docker policy without running a container",
    )
    docker_plan_parser.add_argument("output_directory", type=Path)

    docker_probe_parser = subparsers.add_parser(
        "docker-isolation-preflight",
        help="run the trusted M2b probe in the pinned local Docker image",
    )
    docker_probe_parser.add_argument("output_directory", type=Path)

    review_parser = subparsers.add_parser(
        "security-review-bundle",
        help="create a deterministic handoff for independent M2b review",
    )
    review_parser.add_argument("repository_root", type=Path)
    review_parser.add_argument("output_directory", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.command == "new-evidence":
        return _new_evidence(arguments.output_file, arguments.task_id)
    if arguments.command == "validate":
        return _validate_evidence(
            arguments.evidence_path,
            json_output=arguments.json_output,
            output=arguments.output,
        )
    if arguments.command == "check-fixtures":
        return _check_fixtures(arguments.directory)
    if arguments.command == "controlled-replay":
        return _controlled_replay(arguments.output_directory)
    if arguments.command == "controlled-agent-replay":
        return _controlled_agent_replay(arguments.output_directory)
    if arguments.command == "isolation-preflight":
        return _isolation_preflight(arguments.output_directory)
    if arguments.command == "docker-isolation-plan":
        return _docker_isolation_plan(arguments.output_directory)
    if arguments.command == "docker-isolation-preflight":
        return _docker_isolation_preflight(arguments.output_directory)
    if arguments.command == "security-review-bundle":
        return _security_review_bundle(
            arguments.repository_root,
            arguments.output_directory,
        )
    parser.error(f"unsupported command: {arguments.command}")
    return 2


def _new_evidence(output_file: Path, task_id: str) -> int:
    try:
        write_evidence_draft(output_file, task_id)
        print(f"Created evidence draft: {_terminal_text(str(output_file))}")
        print("Replace every null with a measured observation, then run:")
        print(f"  reposeal validate {_terminal_text(str(output_file))}")
        return 0
    except (OSError, ValueError) as error:
        print(
            f"RepoSeal could not create evidence: {_terminal_text(str(error))}",
            file=sys.stderr,
        )
        return 2


def _validate_evidence(
    evidence_path: Path,
    *,
    json_output: bool,
    output: Optional[Path],
) -> int:
    try:
        report = validate_evidence_path(evidence_path)
        receipt = report.to_json()
        if output is not None:
            _write_new_text(output, receipt + "\n")
        print(receipt if json_output else report.to_text())
        return 0 if report.eligible else 1
    except (OSError, TypeError, ValueError) as error:
        print(
            f"RepoSeal could not validate evidence: {_terminal_text(str(error))}",
            file=sys.stderr,
        )
        return 2


def _terminal_text(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _write_new_text(path: Path, content: str) -> None:
    """Write UTF-8 text without ever replacing an existing directory entry."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)
    except FileExistsError as error:
        raise ValueError("output file must not already exist") from error


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


def _isolation_preflight(output_directory: Path) -> int:
    if output_directory.exists():
        print("output_directory must not already exist", file=sys.stderr)
        return 2
    try:
        receipt = run_host_process_negative_control(
            output_directory / "host-negative-control"
        )
        rendered = receipt.to_json()
        (output_directory / "receipt.json").write_text(
            rendered + "\n", encoding="utf-8"
        )
        print(rendered)
        expected_outcome = (
            receipt.probe_harness_passed
            and not receipt.security_gate_passed
            and not receipt.safe_for_real_agents
        )
        return 0 if expected_outcome else 1
    except (IsolationProbeError, OSError, ValueError) as error:
        print(f"isolation preflight failed: {error}", file=sys.stderr)
        return 1


def _docker_isolation_plan(output_directory: Path) -> int:
    if output_directory.exists():
        print("output_directory must not already exist", file=sys.stderr)
        return 2
    try:
        output_directory.mkdir(parents=True)
        receipt = docker_isolation_plan(DockerIsolationPolicy())
        rendered = receipt.to_json()
        (output_directory / "receipt.json").write_text(
            rendered + "\n", encoding="utf-8"
        )
        print(rendered)
        expected_outcome = (
            receipt.live_integration_status == "NOT_RUN"
            and not receipt.security_gate_passed
            and not receipt.safe_for_real_agents
        )
        return 0 if expected_outcome else 1
    except (DockerBackendError, OSError, ValueError) as error:
        print(f"Docker isolation plan failed: {error}", file=sys.stderr)
        return 1


def _docker_isolation_preflight(output_directory: Path) -> int:
    if output_directory.exists():
        print("output_directory must not already exist", file=sys.stderr)
        return 2
    try:
        receipt = run_docker_isolation_preflight(
            output_directory / "docker-probe",
            policy=DockerIsolationPolicy(),
        )
        rendered = receipt.to_json()
        (output_directory / "receipt.json").write_text(
            rendered + "\n", encoding="utf-8"
        )
        print(rendered)
        expected_outcome = (
            receipt.backend_gate_passed
            and not receipt.security_gate_passed
            and not receipt.safe_for_real_agents
        )
        return 0 if expected_outcome else 1
    except (DockerBackendError, OSError, ValueError) as error:
        print(f"Docker isolation preflight failed: {error}", file=sys.stderr)
        return 1


def _security_review_bundle(
    repository_root: Path,
    output_directory: Path,
) -> int:
    try:
        receipt = create_security_review_bundle(repository_root, output_directory)
        rendered = receipt.to_json()
        print(rendered)
        expected_outcome = (
            receipt.independent_review_status == "NOT_PERFORMED"
            and not receipt.security_gate_passed
            and not receipt.safe_for_real_agents
        )
        return 0 if expected_outcome else 1
    except (OSError, ValueError) as error:
        print(f"security review bundle failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
