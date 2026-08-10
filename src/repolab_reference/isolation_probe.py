"""Trusted adversarial probe used by the M2b host-process negative control."""

import hashlib
import json
import os
import socket
import sys
from pathlib import Path


def _file_sha256(path):
    try:
        content = Path(path).read_bytes()
    except OSError:
        return None
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _attempt_write(path, content):
    try:
        Path(path).write_text(content, encoding="utf-8")
    except OSError:
        return False
    return True


def _attempt_verifier_mutation(path):
    target = Path(path)
    try:
        target.chmod(0o600)
        target.write_text("tampered\n", encoding="utf-8")
    except OSError:
        return False
    return True


def _attempt_network(host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as connection:
            connection.sendall(b"repolab-isolation-probe")
    except OSError:
        return False
    return True


def main():
    request = json.load(sys.stdin)
    export_directory = Path(request["export_directory"])
    export_directory.mkdir(parents=True, exist_ok=True)
    (export_directory / "artifact.json").write_text(
        '{"patch":"controlled"}\n', encoding="utf-8"
    )
    (export_directory / "extra.txt").write_text("unauthorized\n", encoding="utf-8")

    response = {
        "response_version": "0.1",
        "history_sha256": _file_sha256(request["history_sentinel"]),
        "credential_sha256": _file_sha256(request["credential_sentinel"]),
        "foreign_cache_sha256": _file_sha256(request["foreign_cache_sentinel"]),
        "outside_write_succeeded": _attempt_write(
            request["outside_write_target"], "escaped\n"
        ),
        "verifier_mutation_succeeded": _attempt_verifier_mutation(
            request["verifier_target"]
        ),
        "network_connection_succeeded": (
            _attempt_network(request["network_host"], request["network_port"])
            if request["network_probe_enabled"]
            else False
        ),
        "environment_keys": sorted(os.environ),
    }
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    main()
