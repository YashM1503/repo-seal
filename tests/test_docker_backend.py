import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from repolab_reference.docker_backend import (
    DEFAULT_DOCKER_PROBE_IMAGE,
    DockerBackendError,
    DockerIsolationPolicy,
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
    "sha256:063e37d8b681adc943030b3991563c38a9fd48a7f90d40e49236198fe8055b24"
)
EXPECTED_COMMAND_TEMPLATE_SHA256 = (
    "sha256:f54751edfb36726951319db13376601e37c753cd7880d413731ffd9665c55afd"
)


class DockerPolicyTests(unittest.TestCase):
    def test_default_policy_and_command_plan_are_pinned(self) -> None:
        policy = DockerIsolationPolicy()
        plan = docker_isolation_plan(policy)

        self.assertEqual(policy.image_ref, DEFAULT_DOCKER_PROBE_IMAGE)
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

    def test_command_has_exact_mounts_and_required_security_flags(self) -> None:
        with tempfile.TemporaryDirectory(prefix="repolab-docker-plan-") as directory:
            root = Path(directory)
            probe = root / "probe"
            workspace = root / "workspace"
            export = root / "export"
            for path in (probe, workspace, export):
                path.mkdir()
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
