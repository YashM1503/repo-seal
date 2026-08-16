"""Build the deterministic, controlled repository used by the M1 replay gate."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .replay import ReplayError, ReplayTask


@dataclass(frozen=True)
class ControlledTaskDefinition:
    task_id: str
    function_name: str
    statement: str
    broken_source: str
    fixed_source: str


@dataclass(frozen=True)
class ControlledRepository:
    path: Path
    tasks: tuple[ReplayTask, ...]


TASK_DEFINITIONS: tuple[ControlledTaskDefinition, ...] = (
    ControlledTaskDefinition(
        "toy-01-add",
        "add",
        "Make add return the arithmetic sum of both arguments.",
        "def add(left, right):\n    return left - right",
        "def add(left, right):\n    return left + right",
    ),
    ControlledTaskDefinition(
        "toy-02-clamp",
        "clamp",
        "Clamp a value inclusively between the supplied lower and upper bounds.",
        "def clamp(value, low, high):\n    return min(low, max(value, high))",
        "def clamp(value, low, high):\n    return max(low, min(value, high))",
    ),
    ControlledTaskDefinition(
        "toy-03-is-even",
        "is_even",
        "Return true exactly when an integer is even.",
        "def is_even(value):\n    return value % 2 == 1",
        "def is_even(value):\n    return value % 2 == 0",
    ),
    ControlledTaskDefinition(
        "toy-04-slugify",
        "slugify",
        "Lowercase text and join whitespace-delimited words with hyphens.",
        "def slugify(text):\n    return text.lower().replace(\" \", \"_\")",
        "def slugify(text):\n    return \"-\".join(text.lower().split())",
    ),
    ControlledTaskDefinition(
        "toy-05-mean",
        "mean",
        "Return the arithmetic mean without truncating fractional results.",
        "def mean(values):\n    return sum(values) // len(values)",
        "def mean(values):\n    return sum(values) / len(values)",
    ),
    ControlledTaskDefinition(
        "toy-06-dedupe",
        "dedupe",
        "Remove duplicates while preserving first-seen order.",
        "def dedupe(values):\n    return sorted(set(values))",
        (
            "def dedupe(values):\n"
            "    seen = set()\n"
            "    result = []\n"
            "    for value in values:\n"
            "        if value not in seen:\n"
            "            seen.add(value)\n"
            "            result.append(value)\n"
            "    return result"
        ),
    ),
    ControlledTaskDefinition(
        "toy-07-safe-divide",
        "safe_divide",
        "Return None when the denominator is zero; otherwise divide normally.",
        (
            "def safe_divide(numerator, denominator):\n"
            "    return 0 if denominator == 0 else numerator / denominator"
        ),
        (
            "def safe_divide(numerator, denominator):\n"
            "    return None if denominator == 0 else numerator / denominator"
        ),
    ),
    ControlledTaskDefinition(
        "toy-08-count-words",
        "count_words",
        "Count whitespace-delimited words without counting empty segments.",
        "def count_words(text):\n    return len(text.split(\" \"))",
        "def count_words(text):\n    return len(text.split())",
    ),
    ControlledTaskDefinition(
        "toy-09-normalize-path",
        "normalize_path",
        "Collapse redundant separators and return one leading slash.",
        "def normalize_path(path):\n    return path.strip(\"/\")",
        (
            "def normalize_path(path):\n"
            "    parts = [part for part in path.split(\"/\") if part]\n"
            "    return \"/\" + \"/\".join(parts)"
        ),
    ),
    ControlledTaskDefinition(
        "toy-10-fibonacci",
        "fibonacci",
        "Return the nth Fibonacci number and reject negative indices.",
        "def fibonacci(index):\n    return index * index",
        (
            "def fibonacci(index):\n"
            "    if index < 0:\n"
            "        raise ValueError(\"index must be non-negative\")\n"
            "    current, following = 0, 1\n"
            "    for _ in range(index):\n"
            "        current, following = following, current + following\n"
            "    return current"
        ),
    ),
)


TRUSTED_VERIFIER_SOURCE = '''"""Trusted verifier for the controlled M1 toy repository."""

import importlib.util
import json
from pathlib import Path
import sys


def load_candidate(workspace):
    source = workspace / "toycalc.py"
    spec = importlib.util.spec_from_file_location("toycalc_candidate", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(task_id, module):
    if task_id == "toy-01-add":
        passed = module.add(2, 3) == 5 and module.add(-2, 1) == -1
        return passed, "add must implement arithmetic addition"
    if task_id == "toy-02-clamp":
        passed = (
            module.clamp(5, 0, 10) == 5
            and module.clamp(-2, 0, 10) == 0
            and module.clamp(12, 0, 10) == 10
        )
        return passed, "clamp must preserve in-range values and enforce both bounds"
    if task_id == "toy-03-is-even":
        passed = module.is_even(0) and module.is_even(-2) and not module.is_even(3)
        return passed, "is_even must recognize even integers"
    if task_id == "toy-04-slugify":
        passed = module.slugify("Hello   Replay World") == "hello-replay-world"
        return passed, "slugify must normalize whitespace and use hyphens"
    if task_id == "toy-05-mean":
        passed = module.mean([1, 2]) == 1.5 and module.mean([2, 4, 9]) == 5.0
        return passed, "mean must retain fractional values"
    if task_id == "toy-06-dedupe":
        passed = module.dedupe([3, 1, 3, 2, 1]) == [3, 1, 2]
        return passed, "dedupe must preserve first-seen order"
    if task_id == "toy-07-safe-divide":
        passed = module.safe_divide(8, 2) == 4 and module.safe_divide(1, 0) is None
        return passed, "safe_divide must use None for a zero denominator"
    if task_id == "toy-08-count-words":
        passed = module.count_words("  one   two\\tthree  ") == 3
        return passed, "count_words must ignore empty whitespace segments"
    if task_id == "toy-09-normalize-path":
        passed = (
            module.normalize_path("//api//v1/") == "/api/v1"
            and module.normalize_path("") == "/"
        )
        return passed, "normalize_path must collapse separators and retain one leading slash"
    if task_id == "toy-10-fibonacci":
        negative_rejected = False
        try:
            module.fibonacci(-1)
        except ValueError:
            negative_rejected = True
        passed = (
            module.fibonacci(0) == 0
            and module.fibonacci(1) == 1
            and module.fibonacci(7) == 13
            and negative_rejected
        )
        return passed, "fibonacci must implement the sequence and reject negatives"
    raise KeyError("unknown controlled task")


def main():
    workspace = Path(sys.argv[1]).resolve()
    task_id = sys.argv[2]
    try:
        passed, detail = verify(task_id, load_candidate(workspace))
    except Exception as error:
        passed = False
        detail = "verifier exception: " + type(error).__name__
    print(json.dumps({"detail": detail, "passed": passed}, sort_keys=True))


if __name__ == "__main__":
    main()
'''


def build_controlled_repository(destination: Path) -> ControlledRepository:
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("controlled repository destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    _git(destination, "init", "-b", "main")

    sources = {
        definition.function_name: definition.broken_source
        for definition in TASK_DEFINITIONS
    }
    _write_module(destination, sources)
    _commit(destination, "Initialize controlled broken functions", 0)

    tasks = []
    for index, definition in enumerate(TASK_DEFINITIONS, start=1):
        base_commit = _git(destination, "rev-parse", "HEAD").strip()
        sources[definition.function_name] = definition.fixed_source
        _write_module(destination, sources)
        _commit(destination, f"Fix {definition.task_id}", index)
        gold_commit = _git(destination, "rev-parse", "HEAD").strip()
        tasks.append(
            ReplayTask(
                task_id=definition.task_id,
                statement=definition.statement,
                base_commit=base_commit,
                gold_commit=gold_commit,
            )
        )
    return ControlledRepository(path=destination, tasks=tuple(tasks))


def write_trusted_verifier(destination: Path) -> Path:
    if destination.exists():
        raise ValueError("trusted verifier destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(TRUSTED_VERIFIER_SOURCE, encoding="utf-8")
    return destination


def _write_module(repository: Path, sources: dict[str, str]) -> None:
    ordered = [sources[definition.function_name] for definition in TASK_DEFINITIONS]
    content = '"""Controlled arithmetic and text helpers for replay tests."""\n\n\n'
    content += "\n\n\n".join(ordered) + "\n"
    (repository / "toycalc.py").write_text(content, encoding="utf-8")


def _commit(repository: Path, message: str, sequence: int) -> None:
    timestamp = f"2000-01-01T00:00:{sequence:02d}+0000"
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "RepoSeal Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": "RepoSeal Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_DATE": timestamp,
        }
    )
    _git(repository, "add", "toycalc.py", environment=environment)
    _git(
        repository,
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--no-gpg-sign",
        "-m",
        message,
        environment=environment,
    )


def _git(
    repository: Path,
    *arguments: str,
    environment: Optional[dict[str, str]] = None,
) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        raise ReplayError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout
