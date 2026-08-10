import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from repolab_reference.docker_backend import (
    DEFAULT_DOCKER_PROBE_IMAGE,
    DockerBackendError,
    DockerBackendUnavailable,
    DockerIsolationPolicy,
    _CommandResult,
    _docker_cli_environment,
    _engine_lsm_supported,
    _engine_version_at_least,
    _engine_version_supported,
    _inspect_image,
    _run_bounded_command,
    build_docker_command,
    docker_isolation_plan,
    run_docker_isolation_preflight,
)
from repolab_reference.isolation import (
    ControlStatus,
    IsolationControl,
)

EXPECTED_POLICY_SHA256 = (
    "sha256:fc77873cea7f9c4afa53a41a93fdb1554f8ffa2deb6c39deac79ad2a641d52fc"
)
EXPECTED_COMMAND_TEMPLATE_SHA256 = (
    "sha256:a9902c7c08d4423e5af4726c88d59e19045ced82454f544795d33fbe25f07201"
)


class DockerPolicyTests(unittest.TestCase):
    def test_default_policy_and_command_plan_are_pinned(self) -> None:
        policy = DockerIsolationPolicy()
        plan = docker_isolation_plan(policy)

        self.assertEqual(policy.image_ref, DEFAULT_DOCKER_PROBE_IMAGE)
        self.assertEqual(policy.required_engine_major, 29)
        self.assertEqual(policy.minimum_engine_version, "29.4.3")
        self.assertEqual(policy.policy_sha256, EXPECTED_POLICY_SHA256)
        self.assertEqual(
            plan.command_template_sha256,
            EXPECTED_COMMAND_TEMPLATE_SHA256,
        )
        self.assertEqual(plan.live_integration_status, "NOT_RUN")
        self.assertFalse(plan.security_gate_passed)
        self.assertFalse(plan.safe_for_real_agents)

    def test_unpinned_images_and_invalid_limits_are_rejected(self) -> None:
        for image in (
            "python:3.13-alpine",
            "python@sha256:short",
            "https://registry.example/image@sha256:" + "a" * 64,
        ):
            with (
                self.subTest(image=image),
                self.assertRaisesRegex(ValueError, "image_ref"),
            ):
                DockerIsolationPolicy(image_ref=image)

        with self.assertRaisesRegex(ValueError, "cpu_quota"):
            DockerIsolationPolicy(cpu_period=100, cpu_quota=101)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            DockerIsolationPolicy(memory_bytes=0)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            DockerIsolationPolicy(image_environment_keys=("PATH", "GPG_KEY"))
        with self.assertRaisesRegex(ValueError, "engine version"):
            DockerIsolationPolicy(minimum_engine_version="latest")
        with self.assertRaisesRegex(ValueError, "required_engine_major"):
            DockerIsolationPolicy(required_engine_major=30)

    def test_command_has_exact_mounts_and_required_security_flags(self) -> None:
        with tempfile.TemporaryDirectory(prefix="repolab-docker-plan-") as directory:
            root = Path(directory)
            probe = root / "probe.py"
            workspace = root / "workspace"
            export = root / "export"
            for path in (workspace, export):
                path.mkdir()
            probe.write_text("pass\n", encoding="utf-8")
            command = build_docker_command(
                DockerIsolationPolicy(),
                probe_source=probe,
                workspace=workspace,
                export_directory=export,
                container_name="repolab-probe-" + "a" * 32,
            )

        required = {
            "--pull=never",
            "--interactive",
            "--read-only",
            "--network=none",
            "--ipc=none",
            "--cgroupns=private",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--security-opt=seccomp=builtin",
            "--user=65532:65532",
            "--memory=268435456",
            "--memory-swap=268435456",
            "--pids-limit=32",
            "--cpu-period=100000",
            "--cpu-quota=50000",
        }
        self.assertTrue(required.issubset(command))
        self.assertEqual(
            len([argument for argument in command if argument.startswith("--mount=")]),
            3,
        )
        self.assertEqual(command[0:3], ("docker", "--host=<local-unix-socket>", "run"))
        mounts = [argument for argument in command if argument.startswith("--mount=")]
        self.assertTrue(all("bind-propagation=rprivate" in mount for mount in mounts))
        self.assertEqual(
            len([mount for mount in mounts if "bind-recursive=disabled" in mount]),
            2,
        )
        self.assertIn("dst=/repolab-isolation-probe.py,readonly", mounts[0])
        rendered = "\n".join(command)
        for forbidden in (
            "--privileged",
            "--network=host",
            "--pid=host",
            "--use-api-socket",
            "docker.sock",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_command_rejects_relative_paths_commas_and_arbitrary_names(self) -> None:
        policy = DockerIsolationPolicy()
        root = Path("/tmp/repolab-docker-policy")

        with self.assertRaisesRegex(ValueError, "absolute"):
            build_docker_command(
                policy,
                probe_source=Path("relative"),
                workspace=root / "workspace",
                export_directory=root / "export",
                container_name="repolab-probe-" + "a" * 32,
            )
        with self.assertRaisesRegex(ValueError, "unsafe for Docker mounts"):
            build_docker_command(
                policy,
                probe_source=Path("/tmp/with,comma"),
                workspace=root / "workspace",
                export_directory=root / "export",
                container_name="repolab-probe-" + "a" * 32,
            )
        with self.assertRaisesRegex(ValueError, "controlled format"):
            build_docker_command(
                policy,
                probe_source=root / "probe",
                workspace=root / "workspace",
                export_directory=root / "export",
                container_name="user-controlled",
            )

        with self.assertRaisesRegex(ValueError, "local Unix socket"):
            build_docker_command(
                policy,
                probe_source=root / "probe",
                workspace=root / "workspace",
                export_directory=root / "export",
                container_name="repolab-probe-" + "a" * 32,
                docker_host="tcp://remote.example:2376",
            )
        with self.assertRaisesRegex(ValueError, "absolute safe path"):
            build_docker_command(
                policy,
                probe_source=root / "probe",
                workspace=root / "workspace",
                export_directory=root / "export",
                container_name="repolab-probe-" + "a" * 32,
                docker_executable="relative/docker",
            )

    def test_engine_floor_and_docker_environment_fail_closed(self) -> None:
        self.assertFalse(_engine_version_at_least("29.2.1", "29.4.3"))
        self.assertTrue(_engine_version_at_least("29.4.3", "29.4.3"))
        self.assertTrue(_engine_version_at_least("30.0.0", "29.4.3"))
        self.assertFalse(_engine_version_at_least("unknown", "29.4.3"))
        policy = DockerIsolationPolicy()
        self.assertFalse(_engine_version_supported("29.2.1", policy))
        self.assertTrue(_engine_version_supported("29.5.3", policy))
        self.assertFalse(_engine_version_supported("30.0.0", policy))
        self.assertTrue(_engine_lsm_supported("arm64", ()))
        self.assertFalse(_engine_lsm_supported("amd64", ()))
        self.assertTrue(_engine_lsm_supported("amd64", ("name=apparmor",)))

        with patch.dict(
            os.environ,
            {
                "DOCKER_CONTEXT": "remote",
                "DOCKER_HOST": "tcp://remote.example:2376",
                "REPOLAB_CONTROL": "kept",
            },
            clear=True,
        ):
            environment = _docker_cli_environment()
        self.assertEqual(environment, {"REPOLAB_CONTROL": "kept"})

    def test_image_declared_volumes_are_rejected(self) -> None:
        policy = DockerIsolationPolicy()
        digest = policy.image_ref.rsplit("@", 1)[1]
        payload = [
            {
                "Id": "sha256:" + "a" * 64,
                "Os": "linux",
                "Architecture": "arm64",
                "RepoDigests": ["docker.io/library/python@" + digest],
                "Config": {
                    "Env": [
                        f"{key}=controlled" for key in policy.image_environment_keys
                    ],
                    "Volumes": {"/uncontrolled": {}},
                },
            }
        ]
        result = _CommandResult(0, json.dumps(payload).encode("utf-8"), b"")

        with (
            patch(
                "repolab_reference.docker_backend._run_metadata_command",
                return_value=result,
            ),
            self.assertRaisesRegex(DockerBackendError, "uncontrolled volumes"),
        ):
            _inspect_image(
                policy,
                Path("/usr/bin/docker"),
                "unix:///var/run/docker.sock",
                {},
            )

    def test_below_floor_engine_is_rejected_before_work_root_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="repolab-engine-floor-") as directory:
            work_root = Path(directory) / "must-not-exist"
            with (
                patch(
                    "repolab_reference.docker_backend._resolve_docker_cli",
                    return_value=Path(__file__),
                ),
                patch(
                    "repolab_reference.docker_backend._inspect_local_docker_endpoint",
                    return_value="unix:///var/run/docker.sock",
                ),
                patch(
                    "repolab_reference.docker_backend._inspect_image",
                    return_value={},
                ),
                patch(
                    "repolab_reference.docker_backend._inspect_engine",
                    return_value={"version": "29.2.1"},
                ),
                self.assertRaisesRegex(
                    DockerBackendUnavailable,
                    "security range not met",
                ),
            ):
                run_docker_isolation_preflight(
                    work_root,
                    policy=DockerIsolationPolicy(),
                )
            self.assertFalse(work_root.exists())

    def test_streaming_output_and_wall_time_are_actively_bounded(self) -> None:
        output_command = (
            sys.executable,
            "-c",
            "import sys; sys.stdin.read(); sys.stdout.write('x' * 8192)",
        )
        with self.assertRaisesRegex(DockerBackendError, "streaming output limit"):
            _run_bounded_command(
                output_command,
                input_bytes=b"request",
                max_output_bytes=1024,
                timeout_seconds=2,
            )

        timeout_command = (
            sys.executable,
            "-c",
            "import sys, time; sys.stdin.read(); time.sleep(30)",
        )
        with self.assertRaisesRegex(DockerBackendError, "wall-clock limit"):
            _run_bounded_command(
                timeout_command,
                input_bytes=b"request",
                max_output_bytes=1024,
                timeout_seconds=0.1,
            )


@unittest.skipUnless(
    os.environ.get("REPOLAB_RUN_DOCKER_INTEGRATION") == "1",
    "set REPOLAB_RUN_DOCKER_INTEGRATION=1 with the pinned image available",
)
class DockerLiveIntegrationTests(unittest.TestCase):
    def test_pinned_backend_passes_every_control_except_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="repolab-docker-live-") as directory:
            root = Path(directory)
            receipt = run_docker_isolation_preflight(
                root / "run",
                policy=DockerIsolationPolicy(),
            )
            rendered = receipt.to_json()

        self.assertTrue(receipt.backend_gate_passed)
        self.assertFalse(receipt.security_gate_passed)
        self.assertFalse(receipt.safe_for_real_agents)
        statuses = {finding.control: finding.status for finding in receipt.findings}
        for control, status in statuses.items():
            with self.subTest(control=control.value):
                expected = (
                    ControlStatus.UNAVAILABLE
                    if control is IsolationControl.INDEPENDENT_REVIEW
                    else ControlStatus.PASS
                )
                self.assertIs(status, expected)
        self.assertNotIn(str(root), rendered)


if __name__ == "__main__":
    unittest.main()
