"""Trusted adversarial probe used by the M2b host-process negative control."""

import hashlib
import json
import os
import resource
import socket
import sys
from pathlib import Path


def _file_sha256(path):
    try:
        content = Path(path).read_bytes()
    except OSError:
        return None
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _proc_status_value(name):
    content = _read_text("/proc/self/status")
    if content is None:
        return None
    prefix = name + ":"
    for line in content.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None


def _proc_status_integer(name):
    value = _proc_status_value(name)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _mount_options(target):
    content = _read_text("/proc/self/mountinfo")
    if content is None:
        return None
    for line in content.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[4] == target:
            return sorted(set(fields[5].split(",")))
    return None


def _mount_has_option(target, option):
    options = _mount_options(target)
    return option in options if options is not None else None


def _visible_sensitive_paths():
    candidates = {
        "docker_socket": "/var/run/docker.sock",
        "docker_socket_run": "/run/docker.sock",
        "docker_desktop_backend": "/run/host-services/backend.sock",
        "docker_desktop_ssh": "/run/host-services/ssh-auth.sock",
        "runtime_secrets": "/run/secrets",
    }
    return sorted(label for label, path in candidates.items() if os.path.lexists(path))


def _network_interfaces():
    try:
        interfaces = []
        for path in Path("/sys/class/net").iterdir():
            state = path / "operstate"
            if state.is_file() and state.read_text(encoding="utf-8").strip() != "down":
                interfaces.append(path.name)
        return sorted(interfaces)
    except OSError:
        return []


def _limit(resource_name):
    soft, hard = resource.getrlimit(resource_name)
    return [soft, hard]


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
            connection.sendall(b"reposeal-isolation-probe")
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
        "response_version": "0.2",
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
        "network_interfaces": _network_interfaces(),
        "root_write_succeeded": _attempt_write(
            "/reposeal-root-write-sentinel", "root changed\n"
        ),
        "workspace_write_succeeded": _attempt_write(
            "/workspace/reposeal-workspace-write-sentinel", "workspace changed\n"
        ),
        "root_mount_read_only": _mount_has_option("/", "ro"),
        "probe_mount_read_only": _mount_has_option("/reposeal-isolation-probe.py", "ro"),
        "workspace_mount_read_only": _mount_has_option("/workspace", "ro"),
        "export_mount_read_only": _mount_has_option("/export", "ro"),
        "tmp_noexec": _mount_has_option("/tmp", "noexec"),
        "tmp_nosuid": _mount_has_option("/tmp", "nosuid"),
        "tmp_nodev": _mount_has_option("/tmp", "nodev"),
        "identity_uid": os.getuid(),
        "identity_gid": os.getgid(),
        "capability_effective": _proc_status_value("CapEff"),
        "no_new_privileges": _proc_status_integer("NoNewPrivs"),
        "seccomp_mode": _proc_status_integer("Seccomp"),
        "seccomp_filters": _proc_status_integer("Seccomp_filters"),
        "sensitive_paths_visible": _visible_sensitive_paths(),
        "cgroup_memory_max": _read_text("/sys/fs/cgroup/memory.max"),
        "cgroup_pids_max": _read_text("/sys/fs/cgroup/pids.max"),
        "cgroup_cpu_max": _read_text("/sys/fs/cgroup/cpu.max"),
        "limit_nofile": _limit(resource.RLIMIT_NOFILE),
        "limit_fsize": _limit(resource.RLIMIT_FSIZE),
        "limit_core": _limit(resource.RLIMIT_CORE),
        "environment_keys": sorted(os.environ),
    }
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    main()
