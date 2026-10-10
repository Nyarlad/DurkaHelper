"""Offline deployment contract tests; these do not claim Docker runtime evidence."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("deployment_test", ROOT / "deployment/toolkit.py")
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / "deployment/profile.example.json").read_text())
        self.credentials = {name: "safe-generated-value-123456" for name in ("farm_password", "database_password", "neo_key", "packmate_password")}
        self.credentials["packmate_user"] = "operator"
        self.images = json.loads((ROOT / "config/integration-images.lock.json").read_text())
        self.project = "dh-deploy-" + "a" * 12

    def spec(self):
        return kit.compose_spec(self.profile, self.credentials, self.project, self.images)

    def test_profile_accepts_bounded_explicit_values(self):
        self.assertEqual(kit.validate_profile(self.profile), self.profile)

    def test_neo_advertises_farm_lan_address_not_internal_compose_name(self):
        profile = copy.deepcopy(self.profile)
        profile["bind_address"] = "192.0.2.25"
        profile["ports"]["farm"] = 18080
        self.assertEqual(kit.neo_farm_url(profile), "http://192.0.2.25:18080")

    def test_loopback_demo_keeps_in_stack_worker_route(self):
        self.assertEqual(kit.neo_farm_url(self.profile), "http://front")

    def test_profile_rejects_wildcard_multicast_invalid_ports(self):
        for address in ("0.0.0.0", "224.0.0.1", "::"):
            with self.subTest(address=address), self.assertRaises(kit.Error):
                kit.validate_profile(dict(self.profile, bind_address=address))
        for ports in ({"farm": 8080, "neo": 8080, "packmate": 65000}, {"farm": True, "neo": 5005, "packmate": 65000}):
            with self.assertRaises(kit.Error):
                kit.validate_profile(dict(self.profile, ports=ports))

    def test_credentials_reject_shell_delimiters_and_placeholders(self):
        for value in ("short", "x" * 20 + "\n", "x" * 20 + "$()", "x" * 20 + '"'):
            with self.assertRaises(kit.Error):
                kit.validate_credentials(dict(self.credentials, neo_key=value))

    def test_unknown_adapter_and_profile_fields_fail_closed(self):
        with self.assertRaises(kit.Error):
            kit.validate_profile(dict(self.profile, shell="id"))
        profile = copy.deepcopy(self.profile)
        profile["farm"]["protocol"] = "forcad_tcp"
        with self.assertRaises(kit.Error):
            kit.validate_profile(profile)

    def test_no_mock_receiver_or_unapproved_publications(self):
        spec = self.spec()
        self.assertNotIn("receiver", spec["services"])
        published = {name for name, svc in spec["services"].items() if svc.get("ports")}
        self.assertEqual(published, {"front", "neo-server", "packmate"})
        self.assertEqual(spec["services"]["celery"]["profiles"], ["submission"])
        self.assertEqual(spec["services"]["neo-worker"]["profiles"], ["worker"])

    def test_backends_not_published_and_exact_resource_labels(self):
        spec = self.spec()
        for name in ("postgres", "redis", "neo-redis", "packmate-db"):
            svc = spec["services"][name]
            self.assertNotIn("ports", svc)
            self.assertEqual(svc["networks"], ["fixture"])
        for svc in spec["services"].values():
            self.assertEqual(svc["labels"], {kit.LABEL: self.project})
        for network in spec["networks"].values():
            self.assertEqual(network["labels"], {kit.LABEL: self.project})

    def test_neo_launcher_digest_nonroot_no_host_namespace(self):
        svc = self.spec()["services"]["neo-worker"]
        self.assertEqual(svc["image"], kit.LIGHT)
        self.assertEqual(svc["entrypoint"], ["/usr/local/bin/neo"])
        self.assertEqual(svc["user"], "65534:65534")
        self.assertEqual(svc["cap_drop"], ["ALL"])
        self.assertNotIn("privileged", svc)
        self.assertNotIn("network_mode", svc)
        self.assertNotIn("docker.sock", json.dumps(svc))

    def test_packmate_upstream_image_and_exact_logger_suppression(self):
        spec = self.spec()
        self.assertEqual(spec["services"]["packmate"]["image"], kit.PACKMATE)
        self.assertEqual(spec["services"]["packmate"]["platform"], "linux/amd64")
        properties = kit.properties(self.profile, self.credentials)
        self.assertIn("logging.level." + kit.LOGGER + "=OFF\n", properties)
        self.assertIn("packmate.capture-mode=FILE\n", properties)
        self.assertIn("packmate.cleanup.enabled=false", properties)
        self.assertNotIn("logging.level.root", properties)

    def test_model_sanitized_and_source_hash_matches_private_bytes(self):
        spec = self.spec()
        model = kit.model(spec, self.profile)
        self.assertEqual(model["source_sha256"], kit.hashlib.sha256(kit.shared.canonical(spec)).hexdigest())
        serialized = json.dumps(model)
        for secret in self.credentials.values():
            self.assertNotIn(secret, serialized)
        for forbidden in ("environment", "command", "receiver.example", "SYSTEM_TOKEN", "./data", "./sources"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(model["schema"], "durkahelper.deployment-model.v1")

    def test_policy_does_not_auto_approve_unpinned_build_tags(self):
        model = kit.model(self.spec(), self.profile)
        policy = kit.policy(self.profile, model)
        self.assertTrue(all("@sha256:" in image for image in policy["approved_images"]))
        self.assertEqual(len(policy["approved_publications"]), 3)
        self.assertFalse(policy["team_lan"])
        self.assertTrue(policy["require_healthcheck"])

    def test_runtime_compose_uses_exact_local_ids_not_mutable_tags(self):
        spec = self.spec()
        identities = {name: "sha256:" + "a" * 64 for name in spec["services"]}
        runtime = kit.runtime_spec(spec, identities)
        for name in spec["services"]:
            self.assertEqual(runtime["services"][name]["image"], identities[name])
            self.assertNotIn("build", runtime["services"][name])
            if name in kit.BUILD_SERVICES:
                self.assertIn("build", spec["services"][name])
        self.assertIn("sha256:" + "a" * 64, kit.policy(self.profile, kit.model(runtime, self.profile))["approved_images"])

    def test_runtime_compose_rejects_tag_or_invented_registry_digest(self):
        identities = {name: "sha256:" + "a" * 64 for name in self.spec()["services"]}
        for invalid in ("fake:latest", "fake@sha256:" + "a" * 64):
            with self.assertRaises(kit.Error):
                kit.runtime_spec(self.spec(), dict(identities, farm=invalid))

    def test_runtime_compose_rejects_incomplete_old_build_only_inventory(self):
        identities = {name: "sha256:" + "a" * 64 for name in kit.BUILD_SERVICES}
        with self.assertRaisesRegex(kit.Error, "every runtime service"):
            kit.runtime_spec(self.spec(), identities)

    def test_receipt_v2_checks_all_image_ids_and_exact_runtime_bytes(self):
        spec = self.spec()
        identities = {name: "sha256:" + "a" * 64 for name in spec["services"]}
        runtime = kit.runtime_spec(spec, identities)
        payload = kit.shared.canonical(runtime)
        receipt = {"schema": "durkahelper.deployment-build.v2", "compose_sha256": kit.hashlib.sha256(kit.shared.canonical(spec)).hexdigest(),
                   "runtime_sha256": kit.hashlib.sha256(payload).hexdigest(), "images": identities}
        with mock.patch.object(kit, "load", side_effect=[receipt, runtime]), mock.patch.object(kit, "read", return_value=payload):
            self.assertEqual(kit.check_build_receipt(Path("/fixture"), spec, identities), runtime)
        with mock.patch.object(kit, "load", side_effect=[receipt, runtime]), mock.patch.object(kit, "read", return_value=payload):
            with self.assertRaisesRegex(kit.Error, "runtime image identities"):
                kit.check_build_receipt(Path("/fixture"), spec, dict(identities, redis="sha256:" + "b" * 64))

    def test_legacy_receipt_has_actionable_fail_closed_result(self):
        with mock.patch.object(kit, "load", return_value={"schema": "durkahelper.deployment-build.v1"}):
            with self.assertRaisesRegex(kit.Error, "prepare and build a new"):
                kit.check_build_receipt(Path("/fixture"), self.spec())

    def test_start_waits_for_authenticated_farm_before_neo(self):
        spec = self.spec()
        runtime = kit.runtime_spec(spec, {name: "sha256:" + "a" * 64 for name in spec["services"]})
        state = {"project": self.project}
        args = type("Args", (), {"workspace": "fixture", "action": "up", "apply": True})()
        events = []
        with mock.patch.object(kit, "workspace", return_value=(Path("/fixture"), state, spec, self.profile)), mock.patch.object(kit, "owned_resources"), \
                mock.patch.object(kit, "check_build_receipt", return_value=runtime), mock.patch.object(kit, "image_preflight", return_value={}), \
                mock.patch.object(kit, "safe_path", return_value=mock.Mock(is_file=lambda: True, is_symlink=lambda: False)), \
                mock.patch.object(kit.os, "name", "posix"), mock.patch.object(kit.shared, "checked", side_effect=lambda argv, **kw: events.append(argv) or b""), \
                mock.patch.object(kit, "wait_farm", side_effect=lambda *a: events.append("farm-authenticated")), \
                mock.patch.object(kit, "wait_neo", side_effect=lambda *a: events.append("neo-authenticated")):
            result = kit.execute(args)
        starts = [event for event in events if isinstance(event, list) and "up" in event]
        self.assertEqual(len(starts), 2)
        self.assertNotIn("neo-server", starts[0])
        self.assertEqual(starts[1][-1], "neo-server")
        self.assertLess(events.index("farm-authenticated"), events.index(starts[1]))
        self.assertEqual(result["readiness"]["farm_authenticated"], "PASS")
        self.assertEqual(result["readiness"]["packmate"], "NOT_RUN")

    def test_farm_readiness_authenticates_without_secret_output(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = json.dumps({"TEAMS": self.profile["farm"]["teams"], "SYSTEM_PROTOCOL": "ructf_http"}).encode()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(kit.urllib.request, "build_opener", return_value=opener), contextlib.redirect_stdout(io.StringIO()) as output:
            kit.wait_farm(self.profile, self.spec())
        self.assertEqual(opener.open.call_args.args[0].get_header("Authorization"), self.credentials["farm_password"])
        self.assertEqual(output.getvalue(), "")

    def test_neo_readiness_probe_is_nonroot_and_cleaned(self):
        spec = self.spec()
        runtime = kit.runtime_spec(spec, {name: "sha256:" + "a" * 64 for name in spec["services"]})
        calls = []
        def checked(argv, **kwargs):
            calls.append(argv)
            if "ps" in argv:
                return b"a" * 64
            if "inspect" in argv:
                return json.dumps({"id": "a" * 64, "name": "/" + self.project + "-readiness-12345678", "owner": self.project, "purpose": "neo"}).encode()
            return b""
        with mock.patch.object(kit.shared, "checked", side_effect=checked), mock.patch.object(kit.secrets, "token_hex", return_value="12345678"):
            kit.wait_neo(Path("/fixture"), {"project": self.project}, runtime)
        self.assertIn("--user", calls[0])
        self.assertIn("65534:65534", calls[0])
        self.assertIn("--log-driver=none", calls[0])
        self.assertEqual(calls[0][-1], "info")
        self.assertEqual(calls[-1][1:3], ["rm", "--force"])
        self.assertEqual(calls[-1][-1], "a" * 64)

    def test_neo_uncertain_create_reconciles_known_name(self):
        spec = self.spec()
        runtime = kit.runtime_spec(spec, {name: "sha256:" + "a" * 64 for name in spec["services"]})
        for failure in (kit.Error("create timed out"), KeyboardInterrupt()):
            with self.subTest(error=type(failure).__name__), mock.patch.object(kit.shared, "checked", side_effect=failure), mock.patch.object(kit, "cleanup_readiness_probes") as cleanup, mock.patch.object(kit.secrets, "token_hex", return_value="12345678"):
                with self.assertRaises(type(failure)):
                    kit.wait_neo(Path("/fixture"), {"project": self.project}, runtime)
            cleanup.assert_called_once_with({"project": self.project}, self.project + "-readiness-12345678")

    def test_neo_cleanup_rejects_foreign_name_labels_and_identity(self):
        base = {"id": "a" * 64, "name": "/" + self.project + "-readiness-12345678", "owner": self.project, "purpose": "neo"}
        for key, value in (("id", "b" * 64), ("name", "/foreign"), ("owner", "foreign"), ("purpose", "other")):
            with self.subTest(key=key), mock.patch.object(kit.shared, "checked", side_effect=[b"a" * 64, json.dumps(dict(base, **{key: value})).encode()]) as command, self.assertRaises(kit.Error):
                kit.cleanup_readiness_probes({"project": self.project}, self.project + "-readiness-12345678")
            self.assertFalse(any("rm" in call.args[0] for call in command.call_args_list))

    def test_neo_cleanup_down_discovery_is_both_label_scoped(self):
        with mock.patch.object(kit.shared, "checked", return_value=b"") as command:
            kit.cleanup_readiness_probes({"project": self.project})
        argv = command.call_args.args[0]
        self.assertIn("label=" + kit.LABEL + "=" + self.project, argv)
        self.assertIn("label=" + kit.PROBE_LABEL + "=neo", argv)
        self.assertNotIn("rm", argv)

    def test_neo_cleanup_rejects_multiple_or_truncated_ids(self):
        for output in (b"a" * 12, b"a" * 64 + b"\n" + b"b" * 64):
            with mock.patch.object(kit.shared, "checked", return_value=output), self.assertRaises(kit.Error):
                kit.cleanup_readiness_probes({"project": self.project}, self.project + "-readiness-12345678")

    def test_ownership_mismatch_blocks_cleanup(self):
        with mock.patch.object(kit.shared, "checked", side_effect=[b"a" * 64, b"another-project"]):
            with self.assertRaisesRegex(kit.Error, "ownership mismatch"):
                kit.owned_resources({"project": self.project})

    def test_ownership_empty_does_not_delete_anything(self):
        with mock.patch.object(kit.shared, "checked", return_value=b"") as checked:
            kit.owned_resources({"project": self.project})
        self.assertEqual(checked.call_count, 2)
        self.assertNotIn("rm", repr(checked.call_args_list))

    def test_runtime_architecture_mismatch_rejected(self):
        with mock.patch.object(kit.shared, "checked", return_value=("sha256:" + "a" * 64 + ";linux;amd64").encode()):
            with self.assertRaisesRegex(kit.Error, "architecture"):
                kit.image_preflight(self.spec(), self.profile)

    def test_prepare_preview_never_executes_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials.json"
            credentials.write_text(json.dumps(self.credentials))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(kit.shared, "checked", side_effect=AssertionError("executed")):
                code = kit.main(["prepare", "--workspace", str(root / "new"), "--profile", str(ROOT / "deployment/profile.example.json"),
                                 "--credentials", str(credentials), "--s4dfarm-source", "missing", "--neo-source", "missing"])
            self.assertEqual(code, 0)
            self.assertFalse((root / "new").exists())
            self.assertNotIn(self.credentials["farm_password"], output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "NOT_RUN")

    def test_apply_without_approval_fails_before_io(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(kit.main(["up", "--workspace", "missing", "--apply"]), 2)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"x": 1, "x": 2}')
            with self.assertRaisesRegex(kit.Error, "duplicate"):
                kit.load(path)

    @unittest.skipIf(os.name == "nt", "POSIX leaf-link test")
    def test_regular_reads_allow_ancestor_alias_reject_leaf_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "real").mkdir()
            path = root / "real" / "input.json"
            path.write_text("{}")
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            self.assertEqual(kit.read(root / "alias" / "input.json"), b"{}")
            (root / "leaf.json").symlink_to(path)
            with self.assertRaises(kit.Error):
                kit.read(root / "leaf.json")

    def test_read_rejects_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b"x" * 100)
            with self.assertRaises(kit.Error):
                kit.read(path, 99)


if __name__ == "__main__":
    unittest.main()
