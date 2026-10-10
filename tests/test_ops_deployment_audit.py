"""Independent policy fixtures; no Docker, capture, or target execution."""
import copy
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_ops", ROOT / "scripts/defense_ops.py")
ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ops)
IMAGE = "example.invalid/fixture@sha256:" + "1" * 64


def fixture():
    model = {"schema": ops.DEPLOYMENT_MODEL_SCHEMA, "source_sha256": "2" * 64,
             "platform": {"os": "linux", "architecture": "amd64", "runtime": "docker-engine"},
             "services": [{"id": "web", "role": "ui", "image": IMAGE,
                           "architectures": ["amd64", "arm64"], "mode": "none",
                           "ports": [{"host_ip": "192.0.2.10", "host_port": 8080,
                                      "container_port": 8000, "protocol": "tcp"}],
                           "mounts": [{"kind": "bind", "target": "/config",
                                       "source_scope": "approved-config", "read_only": True}],
                           "privileged": False, "network_mode": "bridge", "capabilities": [],
                           "nonroot": True, "healthcheck": True, "memory_limit_mb": 256,
                           "cpu_limit": 0.5, "restart": "unless-stopped"}]}
    policy = {"schema": ops.DEPLOYMENT_POLICY_SCHEMA, "team_lan": True,
              "approved_bind_addresses": ["192.0.2.10"],
              "approved_publications": [{"service": "web", "host_port": 8080,
                                         "container_port": 8000, "protocol": "tcp"}],
              "approved_images": [IMAGE], "require_healthcheck": True,
              "require_resource_limits": True, "require_nonroot": True,
              "require_restart": True, "allow_amd64_emulation": False, "approved_live_capture": []}
    return model, policy


class DeploymentAuditTests(unittest.TestCase):
    def setUp(self):
        self.model, self.policy = fixture()
        self.service = self.model["services"][0]

    def audit(self):
        return ops.deployment_audit(self.model, self.policy, checked_at="2026-01-01T00:00:00Z")

    def checks(self):
        result = self.audit()
        return {f["check"] for f in result["findings"] + result["issues"]}

    def test_clean_model_deterministic_and_no_execution_or_network(self):
        original = copy.deepcopy((self.model, self.policy))
        with patch("subprocess.run", side_effect=AssertionError("execution")), \
                patch("socket.socket", side_effect=AssertionError("network")):
            report = self.audit()
            self.assertEqual(report, self.audit())
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["scope"], "declared-model-only")
        self.assertEqual(original, (self.model, self.policy))
        self.assertEqual(ops._validate_deployment_audit_report(report), report)
        self.assertNotIn("192.0.2.10", json.dumps(report))
        self.assertNotIn(IMAGE, json.dumps(report))

    def test_backend_publishing_is_not_authorized_by_ui_allowlist(self):
        self.service["role"] = "backend"
        self.assertIn("internal_service_published", self.checks())

    def test_local_build_identity_is_not_misrepresented_as_registry_digest(self):
        identity = "sha256:" + "b" * 64
        self.service["image"] = identity
        self.policy["approved_images"] = [identity]
        self.assertEqual(self.audit()["exit_code"], 0)

    def test_unapproved_and_missing_ports_distinguished(self):
        self.service["ports"][0]["host_port"] = 8081
        self.assertTrue({"publication_unapproved", "required_publication_missing"} <= self.checks())

    def test_loopback_is_availability_not_security_when_explicitly_approved(self):
        self.service["ports"][0]["host_ip"] = "127.0.0.1"
        self.policy["approved_bind_addresses"] = ["127.0.0.1"]
        report = self.audit()
        self.assertEqual(report["findings"][0]["kind"], "availability")
        self.policy["team_lan"] = False
        self.assertEqual(self.audit()["exit_code"], 0)

    def test_ipv6_bind_and_wildcards(self):
        self.service["ports"][0]["host_ip"] = "2001:db8::1"
        self.policy["approved_bind_addresses"] = ["2001:db8::1"]
        self.assertEqual(self.audit()["exit_code"], 0)
        for address in ("::", "0.0.0.0"):
            self.service["ports"][0]["host_ip"] = address
            self.policy["approved_bind_addresses"] = [address]
            self.assertIn("bind_unapproved_or_wildcard", self.checks())

    def test_host_container_ports_and_protocols_are_not_confused(self):
        for field, value in (("container_port", 8080), ("protocol", "udp")):
            with self.subTest(field=field):
                model, policy = fixture()
                model["services"][0]["ports"][0][field] = value
                result = ops.deployment_audit(model, policy)
                self.assertEqual(result["exit_code"], 1)

    def test_conflicting_publications_are_availability_failures_for_both_services(self):
        for address in ("192.0.2.10", "0.0.0.0", "::", "::ffff:c000:20a", "::ffff:192.0.2.10"):
            with self.subTest(address=address):
                model, policy = fixture()
                second = copy.deepcopy(model["services"][0])
                second["id"] = "another-ui"
                second["ports"][0]["host_ip"] = address
                model["services"].append(second)
                policy["approved_bind_addresses"].append(address)
                policy["approved_publications"].append({**policy["approved_publications"][0], "service": second["id"]})
                report = ops.deployment_audit(model, policy)
                conflicts = [row for row in report["findings"] if row["check"] == "publication_bind_conflict"]
                self.assertEqual(len(conflicts), 2)
                self.assertEqual({row["kind"] for row in conflicts}, {"availability"})
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(ops._validate_deployment_audit_report(report), report)
                encoded = json.dumps(report)
                self.assertNotIn(address, encoded)
                self.assertNotIn("another-ui", encoded)

    def test_same_port_on_distinct_addresses_or_protocols_is_not_a_collision(self):
        for field, value in (("host_ip", "192.0.2.11"), ("protocol", "udp"), ("host_port", 8081)):
            with self.subTest(field=field):
                model, policy = fixture()
                second = copy.deepcopy(model["services"][0])
                second["id"] = "another-ui"
                second["ports"][0][field] = value
                model["services"].append(second)
                policy["approved_bind_addresses"].append(second["ports"][0]["host_ip"])
                policy["approved_publications"].append(dict(service=second["id"], **{
                    key: item for key, item in second["ports"][0].items() if key != "host_ip"}))
                self.assertEqual(ops.deployment_audit(model, policy)["exit_code"], 0)

    def test_conflicting_targets_within_one_service_and_duplicate_identity(self):
        port = copy.deepcopy(self.service["ports"][0])
        self.service["ports"].append(port)
        self.assertEqual(self.audit()["exit_code"], 0)  # Identical repeated metadata is idempotent.
        port["container_port"] = 9000
        self.policy["approved_publications"].append(dict(service="web", **{
            key: item for key, item in port.items() if key != "host_ip"}))
        self.assertIn("publication_bind_conflict", self.checks())

    def test_ports_with_none_or_host_network_cannot_claim_valid_publication(self):
        for mode in ("none", "host"):
            with self.subTest(mode=mode):
                model, policy = fixture()
                model["services"][0]["network_mode"] = mode
                result = ops.deployment_audit(model, policy)
                finding = next(row for row in result["findings"] if row["check"] == "publication_network_mode_incompatible")
                self.assertEqual(finding["kind"], "availability")
                self.assertEqual(result["exit_code"], 1)
                self.assertEqual(ops._validate_deployment_audit_report(result), result)
        self.service.update(network_mode="none", ports=[])
        self.policy["approved_publications"] = []
        self.assertEqual(self.audit()["exit_code"], 0)

    def test_mount_scope_and_read_only(self):
        self.service["mounts"][0]["read_only"] = False
        self.assertIn("mount_outside_policy", self.checks())
        for scope, check in (("socket", "sensitive_host_mount"), ("host-root", "sensitive_host_mount"),
                             ("outside", "mount_outside_policy"), ("unknown", "mount_scope_unknown")):
            self.service["mounts"][0]["source_scope"] = scope
            self.assertIn(check, self.checks())

    def test_socket_target_cannot_be_hidden_by_scope(self):
        self.service["mounts"][0]["target"] = "/var/run/docker.sock"
        self.assertIn("sensitive_host_mount", self.checks())

    def test_image_pins_unknown_and_incompatible_architectures(self):
        self.service["image"] = "fixture:latest"
        self.assertIn("image_unpinned", self.checks())
        self.service["image"] = IMAGE.replace("1" * 64, "3" * 64)
        self.assertIn("image_lock_mismatch", self.checks())
        self.service["architectures"] = []
        self.assertIn("image_architecture_unknown", self.checks())
        self.assertEqual(self.audit()["exit_code"], 2)
        self.service["architectures"] = ["arm64"]
        self.assertIn("image_architecture_incompatible", self.checks())

    def test_emulation_approval_does_not_claim_runtime_validation(self):
        self.model["platform"].update(os="darwin", architecture="arm64", runtime="docker-desktop")
        self.service["architectures"] = ["amd64"]
        self.policy["allow_amd64_emulation"] = True
        self.assertIn("emulation_runtime_unverified", self.checks())
        self.assertEqual(self.audit()["exit_code"], 2)

    def test_file_mode_cannot_request_capture_capabilities(self):
        self.service.update(mode="file", capabilities=["NET_RAW"], network_mode="host", privileged=True)
        self.assertTrue({"capability_not_minimal", "host_network_unapproved", "privileged_container"} <= self.checks())

    def test_linux_live_is_explicit_and_never_claims_visibility_from_metadata(self):
        self.service.update(mode="live", role="capture", capabilities=["CAP_NET_RAW"], network_mode="host")
        self.assertIn("live_capture_not_approved", self.checks())
        self.policy["approved_live_capture"] = ["web"]
        self.assertNotIn("live_capture_not_approved", self.checks())
        self.assertNotIn("capability_not_minimal", self.checks())
        self.assertEqual(self.audit()["exit_code"], 2)
        self.model["platform"].update(os="darwin", runtime="docker-desktop")
        self.assertIn("live_capture_not_approved", self.checks())

    def test_resource_and_health_policy(self):
        self.service.update(nonroot=False, healthcheck=False, memory_limit_mb=None, cpu_limit=None, restart="no")
        self.assertTrue({"service_runs_as_root", "healthcheck_missing", "resource_limits_missing",
                         "restart_policy_missing"} <= self.checks())

    def test_nonroot_unknown_is_partial(self):
        self.service["nonroot"] = None
        self.assertEqual(self.audit()["exit_code"], 2)

    def test_forbidden_values_rejected_not_echoed(self):
        mutations = [("environment", {"PASSWORD": "CANARY"}), ("cpu_limit", float("nan")),
                     ("cpu_limit", True), ("memory_limit_mb", -1), ("privileged", "false"),
                     ("image", "https://user:CANARY@example.invalid/image"), ("architectures", ["mips"])]
        for key, value in mutations:
            with self.subTest(key=key):
                model, policy = fixture()
                model["services"][0][key] = value
                with self.assertRaises(ops.DefenseError) as error:
                    ops.deployment_audit(model, policy)
                self.assertNotIn("CANARY", str(error.exception))

    def test_malformed_or_unresolved_model_cannot_be_clean(self):
        for model in ({}, [], {**self.model, "services": []}, {**self.model, "anchors": {}}):
            with self.subTest(model=type(model).__name__), self.assertRaises(ops.DefenseError):
                ops.deployment_audit(model, self.policy)
        self.model["services"].append(copy.deepcopy(self.service))
        with self.assertRaises(ops.DefenseError):
            self.audit()

    def test_report_tampering_is_rejected(self):
        self.service["privileged"] = True
        report = self.audit()
        report.update(status="pass", exit_code=0)
        with self.assertRaises(ops.DefenseError):
            ops._validate_deployment_audit_report(report)

    def test_cli_preserves_inputs_and_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ("model.json", "policy.json")]
            for path, value in zip(paths, (self.model, self.policy)):
                path.write_text(json.dumps(value), encoding="utf-8")
            before = [path.read_bytes() for path in paths]
            output = io.StringIO()
            with redirect_stdout(output):
                code = ops.main(["audit-deployment", "--model", str(paths[0]), "--policy", str(paths[1])])
            self.assertEqual(code, 0)
            self.assertEqual(before, [path.read_bytes() for path in paths])
            self.assertEqual(json.loads(output.getvalue())["scope"], "declared-model-only")
            paths[0].write_text('{"schema":1,"schema":2}', encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(ops.main(["audit-deployment", "--model", str(paths[0]), "--policy", str(paths[1])]), 2)

    def test_v2_scanner_scope_is_preserved_and_old_scope_still_supported(self):
        base = {"schema": ops.SCANNER_SCOPE_SCHEMA, "root": "sha256:" + "1" * 64,
                "rules_sha256": "2" * 64, "exclude": [],
                "limits": {"max_bytes": 1024, "max_files": 32, "max_findings": 32},
                "path_semantics": ops.SCANNER_PATH_SEMANTICS}
        for version in (1, 2):
            body = dict(base)
            if version == 2:
                body.update(schema=ops.SCANNER_SCOPE_V2, semantic_revision="bounded-source-signals.v2", context_sha256="3" * 64)
            body["sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=True, sort_keys=True,
                                                      separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(ops._validate_scanner_scope(body), body)
            body["context_sha256"] = "4" * 64
            with self.assertRaises(ops.DefenseError):
                ops._validate_scanner_scope(body)


if __name__ == "__main__":
    unittest.main()
