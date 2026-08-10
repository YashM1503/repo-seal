"""Trusted M2a test double that emits one controlled replacement artifact.

This script intentionally contains the known toy fixes.  It is an integration
fixture for the protocol, not an evaluation subject or a real agent adapter.
"""

import json
import sys

ADAPTER_ID = "controlled-mock/0.1"

REPLACEMENTS = {
    "toy-01-add": ("return left - right", "return left + right"),
    "toy-02-clamp": (
        "return min(low, max(value, high))",
        "return max(low, min(value, high))",
    ),
    "toy-03-is-even": ("return value % 2 == 1", "return value % 2 == 0"),
    "toy-04-slugify": (
        'return text.lower().replace(" ", "_")',
        'return "-".join(text.lower().split())',
    ),
    "toy-05-mean": (
        "return sum(values) // len(values)",
        "return sum(values) / len(values)",
    ),
    "toy-06-dedupe": (
        "return sorted(set(values))",
        (
            "seen = set()\n    result = []\n    for value in values:\n"
            "        if value not in seen:\n            seen.add(value)\n"
            "            result.append(value)\n    return result"
        ),
    ),
    "toy-07-safe-divide": (
        "return 0 if denominator == 0 else numerator / denominator",
        "return None if denominator == 0 else numerator / denominator",
    ),
    "toy-08-count-words": (
        'return len(text.split(" "))',
        "return len(text.split())",
    ),
    "toy-09-normalize-path": (
        'return path.strip("/")',
        (
            'parts = [part for part in path.split("/") if part]\n'
            '    return "/" + "/".join(parts)'
        ),
    ),
    "toy-10-fibonacci": (
        "return index * index",
        (
            'if index < 0:\n        raise ValueError("index must be non-negative")\n'
            "    current, following = 0, 1\n    for _ in range(index):\n"
            "        current, following = following, current + following\n"
            "    return current"
        ),
    ),
}


def main():
    request = json.load(sys.stdin)
    task_id = request["task_id"]
    source = next(item for item in request["files"] if item["path"] == "toycalc.py")
    broken, fixed = REPLACEMENTS[task_id]
    if source["content_utf8"].count(broken) != 1:
        raise ValueError(
            "controlled source did not contain exactly one expected defect"
        )
    replacement = source["content_utf8"].replace(broken, fixed)
    artifact = {
        "artifact_version": "0.1",
        "adapter_id": ADAPTER_ID,
        "task_id": task_id,
        "base_snapshot_sha256": request["base_snapshot_sha256"],
        "replacements": [
            {
                "path": source["path"],
                "expected_sha256": source["sha256"],
                "content_utf8": replacement,
            }
        ],
    }
    json.dump(artifact, sys.stdout, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    main()
