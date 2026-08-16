import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from reposeal.isolation import (
    REQUIRED_CONTROLS,
    ControlStatus,
    IsolationControl,
    IsolationProbeError,
    evaluate_export,
    parse_probe_response,
    run_host_process_negative_control,
)


class HostProcessNegativeControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="reposeal-isolation-")
        cls.root = Path(cls.temporary.name)
        cls.first = run_host_process_negative_control(cls.root / "run-a")
        cls.second = run_host_process_negative_control(cls.root / "run-b")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_negative_control_detects_the_missing_boundary(self) -> None:
        self.assertTrue(self.first.probe_harness_passed)
        self.assertFalse(self.first.security_gate_passed)
        self.assertFalse(self.first.safe_for_real_agents)
        self.assertEqual(len(self.first.findings), len(REQUIRED_CONTROLS))

        statuses = {finding.control: finding.status for finding in self.first.findings}
        for control in (
            IsolationControl.WORKSPACE_CONFINEMENT,
            IsolationControl.HISTORY_HIDDEN,
            IsolationControl.VERIFIER_PROTECTED,
            IsolationControl.CREDENTIAL_SENTINEL_HIDDEN,
            IsolationControl.CACHE_ISOLATED,
        ):
            with self.subTest(control=control.value):
                self.assertIs(statuses[control], ControlStatus.FAIL)
        self.assertIn(
            statuses[IsolationControl.NETWORK_DENIED],
            {ControlStatus.FAIL, ControlStatus.UNAVAILABLE},
        )

    def test_orchestrator_controls_pass_without_claiming_os_isolation(self) -> None:
        statuses = {finding.control: finding.status for finding in self.first.findings}

        self.assertIs(
            statuses[IsolationControl.PARENT_ENVIRONMENT_REPLACED],
            ControlStatus.PASS,
        )
        self.assertIs(statuses[IsolationControl.EXPORT_ALLOWLIST], ControlStatus.PASS)
        self.assertIs(statuses[IsolationControl.WALL_TIMEOUT], ControlStatus.PASS)
        self.assertIs(
            statuses[IsolationControl.INDEPENDENT_REVIEW], ControlStatus.UNAVAILABLE
        )

    def test_two_fresh_preflights_are_identical_in_one_environment(self) -> None:
        self.assertEqual(self.first.to_dict(), self.second.to_dict())
        self.assertEqual(self.first.receipt_sha256, self.second.receipt_sha256)

    def test_receipt_contains_no_temporary_paths_or_sentinel_contents(self) -> None:
        rendered = self.first.to_json()

        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("reposeal-secret-credential-value", rendered)
        self.assertNotIn("reposeal-secret-history-value", rendered)
        self.assertNotIn("reposeal-secret-cache-value", rendered)

    def test_existing_work_root_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not already exist"):
            run_host_process_negative_control(self.root / "run-a")


class ExportPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="reposeal-export-")
        self.root = Path(self.temporary.name)
        self.export = self.root / "export"
        self.export.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_bounded_artifact_is_accepted(self) -> None:
        (self.export / "artifact.json").write_text("{}\n", encoding="utf-8")

        decision = evaluate_export(
            self.export,
            allowed_paths=("artifact.json",),
        )

        self.assertTrue(decision.accepted)
        self.assertEqual(len(decision.artifacts), 1)
        self.assertEqual(decision.artifacts[0].path, "artifact.json")

    def test_unauthorized_missing_and_oversized_outputs_are_rejected(self) -> None:
        (self.export / "artifact.json").write_text("{}\n", encoding="utf-8")
        (self.export / "extra.txt").write_text("extra\n", encoding="utf-8")
        self.assertEqual(
            evaluate_export(self.export, allowed_paths=("artifact.json",)).detail,
            "unauthorized export path rejected",
        )

        (self.export / "extra.txt").unlink()
        (self.export / "artifact.json").unlink()
        self.assertEqual(
            evaluate_export(self.export, allowed_paths=("artifact.json",)).detail,
            "required export artifact missing",
        )

        (self.export / "artifact.json").write_bytes(b"x" * 17)
        self.assertEqual(
            evaluate_export(
                self.export,
                allowed_paths=("artifact.json",),
                max_file_bytes=16,
            ).detail,
            "export byte limit exceeded",
        )

    def test_traversal_git_and_symlink_exports_are_rejected(self) -> None:
        for path in ("../escape", ".git/config", "nested/../../escape", "bad\nname"):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "unsafe export path"),
            ):
                evaluate_export(self.export, allowed_paths=(path,))

        outside = self.root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        os.symlink(outside, self.export / "artifact.json")
        decision = evaluate_export(
            self.export,
            allowed_paths=("artifact.json",),
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.detail, "unsafe export entry rejected")

        (self.export / "artifact.json").unlink()
        os.link(outside, self.export / "artifact.json")
        decision = evaluate_export(
            self.export,
            allowed_paths=("artifact.json",),
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.detail, "hard-linked export entry rejected")

        (self.export / "artifact.json").unlink()
        (self.export / "artifact.json").write_text("{}\n", encoding="utf-8")
        (self.export / "artifact.json").chmod(0o755)
        decision = evaluate_export(
            self.export,
            allowed_paths=("artifact.json",),
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.detail, "executable export entry rejected")


class ProbeResponseParsingTests(unittest.TestCase):
    def valid_payload(self):
        return {
            "response_version": "0.2",
            "history_sha256": "sha256:" + "a" * 64,
            "credential_sha256": "sha256:" + "b" * 64,
            "foreign_cache_sha256": None,
            "outside_write_succeeded": True,
            "verifier_mutation_succeeded": True,
            "network_connection_succeeded": False,
            "network_interfaces": ["lo"],
            "root_write_succeeded": False,
            "workspace_write_succeeded": True,
            "root_mount_read_only": True,
            "probe_mount_read_only": True,
            "workspace_mount_read_only": False,
            "export_mount_read_only": False,
            "tmp_noexec": True,
            "tmp_nosuid": True,
            "tmp_nodev": True,
            "identity_uid": 65532,
            "identity_gid": 65532,
            "capability_effective": "0000000000000000",
            "no_new_privileges": 1,
            "seccomp_mode": 2,
            "seccomp_filters": 1,
            "sensitive_paths_visible": [],
            "cgroup_memory_max": "268435456",
            "cgroup_pids_max": "32",
            "cgroup_cpu_max": "50000 100000",
            "limit_nofile": [64, 64],
            "limit_fsize": [1048576, 1048576],
            "limit_core": [0, 0],
            "environment_keys": ["HOME", "TZ"],
        }

    def parse(self, payload):
        return parse_probe_response(json.dumps(payload, sort_keys=True).encode("utf-8"))

    def test_valid_response_is_parsed(self) -> None:
        response = self.parse(self.valid_payload())

        self.assertTrue(response.outside_write_succeeded)
        self.assertEqual(response.environment_keys, ("HOME", "TZ"))

    def test_schema_boolean_digest_and_environment_errors_fail_closed(self) -> None:
        payload = self.valid_payload()
        payload["unexpected"] = True
        with self.assertRaisesRegex(IsolationProbeError, "fields"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["outside_write_succeeded"] = "true"
        with self.assertRaisesRegex(IsolationProbeError, "boolean"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["history_sha256"] = "latest"
        with self.assertRaisesRegex(IsolationProbeError, "SHA-256"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["environment_keys"] = ["TZ", "HOME"]
        with self.assertRaisesRegex(IsolationProbeError, "sorted unique"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["capability_effective"] = "CAP_SYS_ADMIN"
        with self.assertRaisesRegex(IsolationProbeError, "lowercase hex"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["root_mount_read_only"] = "true"
        with self.assertRaisesRegex(IsolationProbeError, "null or a boolean"):
            self.parse(payload)

        payload = self.valid_payload()
        payload["sensitive_paths_visible"] = ["/var/run/docker.sock"]
        with self.assertRaisesRegex(IsolationProbeError, "unique labels"):
            self.parse(payload)

    def test_duplicate_json_fields_are_rejected(self) -> None:
        raw = json.dumps(self.valid_payload(), sort_keys=True).encode("utf-8")
        duplicate = raw[:-1] + b',"response_version":"0.2"}'

        with self.assertRaisesRegex(IsolationProbeError, "duplicate"):
            parse_probe_response(duplicate)


if __name__ == "__main__":
    unittest.main()
