import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("offline_test", ROOT / "integration/offline_runtime_smoke.py")
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)


def state():
    return {"schema": offline.SCHEMA, "project": "dh-offline-012345abcdef", "daemon_id": "synthetic-daemon",
            "images": {name: "sha256:" + format(index, "064x") for index, name in enumerate(sorted(offline.ROLES), 1)},
            "credentials": {name: "a" * 24 for name in ("farm_password", "database_password", "neo_key", "packmate_user", "packmate_password")},
            "marker": "b" * 24, "flag": "A" * 31 + "=", "bundle": str(ROOT / "synthetic-private-bundle"),
            "bundle_manifest_sha256": "c" * 64, "template_receipt_sha256": "d" * 64, "files": {}}


def manifest(value=None):
    images = (value or state())["images"]
    return {"artifacts": [{"kind": "image", "architecture": "linux/amd64", "image_ids": [identity], "size": 100} for identity in sorted(set(images.values()))]}


class OfflineTests(unittest.TestCase):
    def test_fixed_profile_never_uses_operator_competition_endpoint(self):
        value = offline.synthetic_profile()
        offline.kit.validate_profile(value)
        self.assertEqual(value["farm"]["teams"], {"Synthetic": "192.0.2.1"})
        self.assertEqual(value["farm"]["protocol_settings"]["SYSTEM_URL"], "http://offline-no-submission.invalid/flags")
        self.assertEqual(value["packmate"]["mode"], "FILE")

    def test_bundle_covers_every_image_including_helpers(self):
        offline.image_closure(manifest(), state()["images"])
        missing = manifest()
        missing["artifacts"].pop()
        with self.assertRaises(offline.Error):
            offline.image_closure(missing, state()["images"])
        extra = manifest()
        extra["artifacts"].append({"kind": "image", "architecture": "linux/amd64", "image_ids": ["sha256:" + "f" * 64], "size": 10})
        with self.assertRaises(offline.Error):
            offline.image_closure(extra, state()["images"])

    def test_bundle_architecture_and_size_are_bounded(self):
        for key, value in (("architecture", "linux/arm64"), ("size", 5 * 1024 ** 3)):
            doc = manifest()
            doc["artifacts"][0][key] = value
            with self.assertRaises(offline.Error):
                offline.image_closure(doc, state()["images"])

    def test_mutable_or_incomplete_runtime_receipts_rejected(self):
        for images in ({}, dict(state()["images"], farm="farm:latest")):
            with self.assertRaises(offline.Error):
                offline.image_closure(manifest(), images)

    def test_all_apps_single_isolated_network_no_publications_or_builds(self):
        value = offline.compose_spec(state())
        self.assertEqual(set(value["services"]), set(offline.APPS) | {"witness"})
        for name, service in value["services"].items():
            self.assertNotIn("ports", service)
            self.assertNotIn("build", service)
            self.assertNotIn("privileged", service)
            self.assertEqual(service["networks"], ["witness" if name == "witness" else "offline"])
            self.assertEqual(service["restart"], "no")
            self.assertTrue(service["image"].startswith("sha256:"))
            self.assertEqual(service["labels"], {offline.LABEL: state()["project"]})
        for network in value["networks"].values():
            self.assertTrue(network["internal"])
            self.assertFalse(network["enable_ipv6"])
            self.assertEqual(network["driver_opts"], {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"})

    def test_witness_uses_already_required_farm_image_nonroot_no_caps(self):
        value = offline.compose_spec(state())["services"]["witness"]
        self.assertEqual(value["image"], state()["images"]["farm"])
        self.assertEqual(value["cap_drop"], ["ALL"])
        self.assertEqual(value["user"], "65534:65534")
        self.assertEqual(value["volumes"], ["./probe.py:/probe.py:ro"])
        self.assertNotIn("environment", value)

    def test_generated_files_are_deterministic_and_only_synthetic(self):
        first, second = offline.generated_files(state()), offline.generated_files(state())
        self.assertEqual(first, second)
        self.assertIn(b"offline-no-submission.invalid", first["config/farm.py"])
        self.assertIn(b"packmate.capture-mode=FILE", first["config/packmate.properties"])
        self.assertIn(b"synthetic-offline", first["probe.py"])
        self.assertEqual(first["pcaps/synthetic.pcap"], offline.pcap.make_pcap(state()["marker"]))
        self.assertNotIn(b"run", first["synthetic.sh"])

    def test_helper_program_compiles_and_has_fixed_endpoints(self):
        compile(offline.PROBE, "probe.py", "exec")
        self.assertIn(b"http://front", offline.PROBE)
        self.assertIn(b"http://packmate:65000", offline.PROBE)
        self.assertIn(b"ProxyHandler({})", offline.PROBE)
        self.assertNotIn(b"subprocess", offline.PROBE)
        self.assertNotIn(b"urlopen(sys.argv", offline.PROBE)

    def test_state_rejects_unknown_fields_and_nonabsolute_bundle(self):
        offline.validate_state(state())
        for value in (dict(state(), project="default"), dict(state(), bundle="relative"), dict(state(), command="unsafe")):
            with self.assertRaises(offline.Error):
                offline.validate_state(value)

    def test_rehashed_fixture_cannot_enable_ports_or_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            value = state()
            generated = offline.generated_files(value)
            compose = json.loads(generated["compose.json"])
            compose["services"]["farm"]["ports"] = ["8080:5000"]
            generated["compose.json"] = offline.shared.canonical(compose)
            for name, data in generated.items():
                offline.shared.write(root / name, data)
                value["files"][name] = offline.digest(data)
            for name in ("postgres", "redis", "neo-redis", "neo", "packmate-db"):
                (root / "data" / name).mkdir(parents=True)
            offline.shared.write(root / "fixture.json", offline.shared.canonical(value))
            with self.assertRaises(offline.Error):
                offline.fixture(root)

    def test_prepare_preview_does_not_contact_daemon_or_copy(self):
        value = state()
        runtime = {"services": {name: {"image": identity} for name, identity in value["images"].items()}}
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(workspace=Path(directory) / "new", template="template", image_bundle="bundle", daemon_id=value["daemon_id"], apply=False)
            with mock.patch.object(offline.kit, "workspace", return_value=(Path(directory), {"files": {}}, {}, offline.synthetic_profile())), mock.patch.object(offline.kit, "check_build_receipt", return_value=runtime), mock.patch.object(offline.bundle, "verify", return_value=manifest()), mock.patch.object(offline.shared, "checked") as command:
                result = offline.prepare(args)
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertFalse(args.workspace.exists())
            command.assert_not_called()

    def test_run_preview_does_not_contact_daemon(self):
        args = argparse.Namespace(workspace="fixture", action="run", apply=False)
        with mock.patch.object(offline, "fixture", return_value=(Path("fixture"), state())), mock.patch.object(offline.shared, "checked") as command:
            result = offline.execute(args)
        self.assertFalse(result["daemon_contacted"])
        command.assert_not_called()

    def test_approval_gate_precedes_input_lookup(self):
        with redirect_stdout(io.StringIO()), mock.patch.object(offline, "fixture") as fixture:
            result = offline.main(["run", "--workspace", "missing", "--apply", "--snapshot-confirmed"])
        self.assertEqual(result, 2)
        fixture.assert_not_called()

    def test_snapshot_gate_before_image_import_or_service_change(self):
        with mock.patch.object(offline, "fixture", return_value=(Path("fixture"), state())), mock.patch.object(offline.sys, "platform", "linux"), mock.patch.object(offline.os, "getuid", return_value=1000, create=True), mock.patch.object(offline, "daemon"), mock.patch.object(offline.bundle, "import_images") as imported, mock.patch.object(offline.shared, "checked") as command, self.assertRaises(offline.Error):
            offline.execute(argparse.Namespace(workspace="fixture", action="run", apply=True, snapshot_confirmed=False))
        imported.assert_not_called()
        command.assert_not_called()

    def test_daemon_rejects_different_identity_desktop_and_arch(self):
        for raw in (b"other;linux;amd64;Ubuntu", b"synthetic-daemon;linux;arm64;Ubuntu", b"synthetic-daemon;linux;x86_64;Docker Desktop"):
            with mock.patch.object(offline.shared, "checked", return_value=raw), self.assertRaises(offline.Error):
                offline.daemon(state())

    def test_helper_uncertain_create_still_reconciles_ownership(self):
        for error in (offline.Error("timeout"), KeyboardInterrupt()):
            with mock.patch.object(offline.shared, "checked", side_effect=error), mock.patch.object(offline, "cleanup_helpers") as cleanup, mock.patch.object(offline.secrets, "token_hex", return_value="12345678"), self.assertRaises(type(error)):
                offline.helper(Path("fixture"), state(), "ready")
            cleanup.assert_called_once_with(state(), state()["project"] + "-helper-12345678")

    def test_helper_cannot_run_arbitrary_action(self):
        with mock.patch.object(offline.shared, "checked") as command, self.assertRaises(offline.Error):
            offline.helper(Path("fixture"), state(), "shell")
        command.assert_not_called()

    def test_helper_commands_drop_caps_and_do_not_mount_socket(self):
        with mock.patch.object(offline.shared, "checked") as command, mock.patch.object(offline.shared, "capture_probe", return_value=(0, b'{"packmate_ready":true}')), mock.patch.object(offline, "cleanup_helpers"):
            result = offline.helper(Path("fixture"), state(), "ready")
        argv = command.call_args.args[0]
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--pull=never", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("docker.sock", " ".join(argv))
        self.assertEqual(result, {"packmate_ready": True})

    def test_wrong_neo_key_requires_unauthenticated_not_any_failure(self):
        for raw, expected in ((b"Unauthenticated", True), (b"connection refused", False)):
            with mock.patch.object(offline.shared, "checked"), mock.patch.object(offline.shared, "capture_probe", return_value=(1, raw)), mock.patch.object(offline, "cleanup_helpers"):
                self.assertEqual(offline.helper(Path("fixture"), state(), "neo-denied"), {"neo_wrong_key_rejected": expected})

    def test_neo_parser_rejects_enabled_or_non_synthetic_task(self):
        for raw in (b'exploit_id:"other" disabled:true version:1', ("exploit_id:" + state()["project"] + " disabled:false version:1").encode()):
            with mock.patch.object(offline.shared, "checked"), mock.patch.object(offline.shared, "capture_probe", return_value=(0, raw)), mock.patch.object(offline, "cleanup_helpers"), self.assertRaises(offline.Error):
                offline.helper(Path("fixture"), state(), "neo-info")

    def test_cleanup_foreign_helper_never_deleted(self):
        name = state()["project"] + "-helper-12345678"
        value = {"id": "a" * 64, "name": "/" + name, "owner": "foreign", "helper": "true"}
        with mock.patch.object(offline.shared, "checked", side_effect=[b"a" * 64, json.dumps(value).encode()]) as command, self.assertRaises(offline.Error):
            offline.cleanup_helpers(state(), name)
        self.assertFalse(any("rm" in call.args[0] for call in command.call_args_list))

    def test_cleanup_removes_by_exact_id_after_both_labels_and_name(self):
        name = state()["project"] + "-helper-12345678"
        value = {"id": "a" * 64, "name": "/" + name, "owner": state()["project"], "helper": "true"}
        with mock.patch.object(offline.shared, "checked", side_effect=[b"a" * 64, json.dumps(value).encode(), b""]) as command:
            offline.cleanup_helpers(state(), name)
        self.assertEqual(command.call_args.args[0], ["docker", "rm", "--force", "a" * 64])

    def test_actual_network_requires_isolated_gateway_and_internal(self):
        base = {"id": "a" * 64, "internal": True, "ipv6": False, "driver": "bridge", "owner": state()["project"], "options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}
        for key, value in (("internal", False), ("ipv6", True), ("driver", "host"), ("options", {}), ("owner", "foreign")):
            with mock.patch.object(offline.shared, "checked", return_value=json.dumps(dict(base, **{key: value})).encode()), self.assertRaises(offline.Error):
                offline.isolation(Path("fixture"), state())

    def test_actual_endpoints_reject_publication_extra_network_and_privilege(self):
        network = {"id": "a" * 64, "internal": True, "ipv6": False, "driver": "bridge", "owner": state()["project"],
                   "options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}
        endpoint = {"running": True, "ports": {}, "networks": {"owned": {"NetworkID": "a" * 64, "IPAddress": "172.30.0.2"}},
                    "privileged": False, "owner": state()["project"]}
        changes = ({"ports": {"80/tcp": [{"HostPort": "80"}]}}, {"privileged": True},
                   {"networks": dict(endpoint["networks"], outside={"NetworkID": "b" * 64})}, {"owner": "unrelated"})
        for change in changes:
            with mock.patch.object(offline, "container_id", return_value="c" * 64), mock.patch.object(offline.shared, "checked", side_effect=[json.dumps(network).encode(), json.dumps(network).encode(), json.dumps(dict(endpoint, **change)).encode()]), mock.patch.object(offline, "helper") as helper, self.assertRaises(offline.Error):
                offline.isolation(Path("fixture"), state())
            helper.assert_not_called()

    def test_stopped_witness_does_not_prove_network_denial(self):
        network = {"id": "a" * 64, "internal": True, "ipv6": False, "driver": "bridge", "owner": state()["project"],
                   "options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}
        endpoint = {"running": True, "ports": {}, "networks": {"owned": {"NetworkID": "a" * 64, "IPAddress": "172.30.0.2"}},
                    "privileged": False, "owner": state()["project"]}
        results = [json.dumps(network).encode()] * 2 + [json.dumps(endpoint).encode()] * (len(offline.APPS) + 1)
        with mock.patch.object(offline, "container_id", return_value="c" * 64), mock.patch.object(offline.shared, "checked", side_effect=results), mock.patch.object(offline, "helper", return_value={"owned_witness_reachable": False}) as helper, self.assertRaises(offline.Error):
            offline.isolation(Path("fixture"), state())
        self.assertEqual(helper.call_count, 1)

    def test_import_timeout_is_sanitized_and_owned_cleanup_runs(self):
        value = state()
        manifest_bytes = b"verified synthetic manifest"
        value["bundle_manifest_sha256"] = offline.digest(manifest_bytes)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("postgres", "redis", "neo-redis", "neo", "packmate-db"):
                (root / "data" / name).mkdir(parents=True)
            args = argparse.Namespace(workspace=root, action="run", apply=True, snapshot_confirmed=True, approval_id="synthetic-approval")
            with mock.patch.object(offline, "fixture", return_value=(root, value)), mock.patch.object(offline.sys, "platform", "linux"), mock.patch.object(offline.os, "getuid", return_value=1000, create=True), mock.patch.object(offline, "daemon"), mock.patch.object(offline.bundle, "verify", return_value=manifest(value)), mock.patch.object(offline.kit, "read", return_value=manifest_bytes), mock.patch.object(offline.bundle, "import_images", side_effect=offline.subprocess.TimeoutExpired(["private-sensitive-command"], 600)), mock.patch.object(offline, "cleanup_helpers") as cleanup, mock.patch.object(offline, "ownership") as ownership, mock.patch.object(offline.shared, "checked") as command:
                report = offline.execute(args)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["error_type"], "TimeoutExpired")
            self.assertEqual(report["cleanup"], {"helpers": True, "owned_project": True})
            self.assertNotIn("private-sensitive-command", json.dumps(report))
            cleanup.assert_called_once_with(value)
            ownership.assert_called_once_with(value)
            self.assertIn("down", command.call_args.args[0])
            self.assertTrue((root / "result.json").is_file())

    def test_probe_route_check_ignores_kernel_unreachable_ipv6_default(self):
        source = offline.PROBE.split(b"try:\n    action=sys.argv[1]")[0]
        namespace = {}
        exec(compile(source, "probe-library.py", "exec"), namespace)
        routes = {"/proc/net/route": "Iface Destination Gateway Flags\neth0 00001FAC 00000000 0001\n",
                  "/proc/net/ipv6_route": "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32 + " ffffffff 00000001 00000000 00200200 lo\n"}
        namespace["Path"] = lambda path: SimpleNamespace(read_text=lambda: routes[path])
        namespace["sys"] = SimpleNamespace(argv=["probe", "network", "172.30.0.2"])
        with mock.patch.object(namespace["socket"], "create_connection", side_effect=OSError("no route")):
            self.assertEqual(namespace["main"]("network"), {"no_default_ipv4": True, "no_default_ipv6": True, "owned_witness_denied": True})
        routes["/proc/net/route"] += "eth0 00000000 01001FAC 0003\n"
        with mock.patch.object(namespace["socket"], "create_connection", side_effect=OSError("denied")):
            self.assertFalse(namespace["main"]("network")["no_default_ipv4"])

    def test_start_orders_farm_readiness_before_neo(self):
        calls = []
        with mock.patch.object(offline, "ownership"), mock.patch.object(offline.shared, "checked", side_effect=lambda argv, **kwargs: calls.append(argv)), mock.patch.object(offline, "wait_helper", side_effect=lambda root, value, action, timeout: calls.append(action)):
            offline.start(Path("fixture"), state())
        self.assertNotIn("neo-server", calls[0])
        self.assertEqual(calls[1], "farm-ready")
        self.assertEqual(calls[2][-1], "neo-server")
        self.assertEqual(calls[3:], ["neo-info", "ready"])
        self.assertNotIn("celery", repr(calls))
        self.assertNotIn("neo-worker", repr(calls))

    def test_down_uses_no_volume_or_global_prune(self):
        with mock.patch.object(offline, "fixture", return_value=(Path("fixture"), state())), mock.patch.object(offline.sys, "platform", "linux"), mock.patch.object(offline.os, "getuid", return_value=1000, create=True), mock.patch.object(offline, "daemon"), mock.patch.object(offline, "cleanup_helpers"), mock.patch.object(offline, "ownership"), mock.patch.object(offline.shared, "checked") as command:
            result = offline.execute(argparse.Namespace(workspace="fixture", action="down", apply=True))
        argv = command.call_args.args[0]
        self.assertIn("down", argv)
        self.assertNotIn("--volumes", argv)
        self.assertNotIn("prune", argv)
        self.assertTrue(result["data_retained"])


if __name__ == "__main__":
    unittest.main()
