"""Operator routing and state ownership; external services are not contacted."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("durka_test", ROOT / "durka.py")
durka = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(durka)


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # macOS exposes its system temp directory through the stock /var alias.
        self.root = Path(self.temporary.name).resolve()
        self.config = self.root / "durka.json"
        self.value = json.loads((ROOT / "config/durka.example.json").read_text())
        self.value["credentials"] = {key: "operator-secret-value-0123456789" for key in self.value["credentials"]}
        self.value["credentials"]["packmate_user"] = "operator"
        self.value["paths"] = {"sources": str(self.root / "sources"), "workspace": str(self.root / "workspace")}
        self.paths = {key: Path(value) for key, value in self.value["paths"].items()}

    def write_config(self):
        self.config.write_text(json.dumps(self.value), encoding="utf-8")

    def quiet(self, function, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = function(*args)
        return result, output.getvalue()

    def test_init_generates_valid_distinct_credentials_without_printing_them(self):
        code, output = self.quiet(durka.init, self.config)
        created = durka.kit.load(self.config)
        self.assertEqual(code, 0)
        durka.kit.validate_credentials(created["credentials"])
        passwords = [value for name, value in created["credentials"].items() if name != "packmate_user"]
        self.assertEqual(len(set(passwords)), 4)
        self.assertTrue(all(value not in output for value in passwords))
        self.assertNotIn("approval", created)
        self.assertNotIn("sha256", created)
        if os.name != "nt":
            self.assertEqual(self.config.stat().st_mode & 0o077, 0)

    def test_init_never_overwrites_existing_config(self):
        self.config.write_bytes(b"private-existing-content")
        with self.assertRaises(durka.Error):
            durka.init(self.config)
        self.assertEqual(self.config.read_bytes(), b"private-existing-content")

    def test_platform_detection_for_mac_and_linux(self):
        for system, machine, expected in (("darwin", "arm64", "docker-desktop"),
                                          ("linux", "x86_64", "docker-engine"),
                                          ("linux", "aarch64", "docker-engine")):
            with mock.patch.object(durka.sys, "platform", system), mock.patch.object(durka.platform, "machine", return_value=machine):
                self.assertEqual(durka.target_platform()["runtime"], expected)

    def test_missing_config_gives_next_command(self):
        with self.assertRaisesRegex(durka.Error, "durka.py init"):
            durka.load_config(self.config)

    def test_config_validates_without_network_and_rejects_unknown_fields(self):
        self.write_config()
        with mock.patch.object(durka.kit.shared, "checked") as external:
            value, paths = durka.load_config(self.config)
        self.assertEqual(value, self.value)
        self.assertEqual(paths, self.paths)
        external.assert_not_called()
        self.value["shell"] = "echo forbidden"
        self.write_config()
        with self.assertRaises(durka.Error):
            durka.load_config(self.config)

    def test_overlapping_and_repository_root_paths_rejected(self):
        for paths in ({"sources": str(self.root), "workspace": str(self.root / "inside")},
                      {"sources": str(ROOT), "workspace": str(self.root / "workspace")}):
            self.value["paths"] = paths
            self.write_config()
            with self.assertRaises(durka.Error):
                durka.load_config(self.config)

    def test_scan_forwards_options_in_original_order_and_without_config(self):
        scanner = SimpleNamespace(main=mock.Mock(return_value=1))
        with mock.patch.object(durka, "module", return_value=scanner), mock.patch.object(durka, "load_config") as config:
            self.assertEqual(durka.main(["--config", str(self.config), "scan", "--json", "source tree", "--exclude", "vendor/*"]), 1)
        scanner.main.assert_called_once_with(["--json", "source tree", "--exclude", "vendor/*"])
        config.assert_not_called()

    def test_scan_help_and_version_are_forwarded(self):
        scanner = SimpleNamespace(main=mock.Mock(return_value=0))
        with mock.patch.object(durka, "module", return_value=scanner):
            self.assertEqual(durka.main(["scan", "--version"]), 0)
        scanner.main.assert_called_once_with(["--version"])

    def test_remote_live_routes_without_local_farm_config(self):
        helper = SimpleNamespace(main=mock.Mock(return_value=0))
        with mock.patch.object(durka, "module", return_value=helper), mock.patch.object(durka, "load_config") as config:
            self.assertEqual(durka.main(["traffic", "live", "doctor", "--host", "tester@fixture.example"]), 0)
        helper.main.assert_called_once_with(["doctor", "--host", "tester@fixture.example"])
        config.assert_not_called()

    def test_remote_live_help_is_forwarded(self):
        helper = SimpleNamespace(main=mock.Mock(return_value=0))
        with mock.patch.object(durka, "module", return_value=helper):
            self.assertEqual(durka.main(["traffic", "live", "--help"]), 0)
        helper.main.assert_called_once_with(["--help"])

    def test_missing_deployment_explains_setup(self):
        with self.assertRaisesRegex(durka.Error, "durka.py setup"):
            durka.check_config(self.paths["workspace"], self.value)

    def test_changed_credentials_require_new_workspace(self):
        root = self.paths["workspace"]
        root.mkdir()
        profile = self.value["profile"]
        state = {"project": "dh-deploy-" + "a" * 12}
        images = durka.kit.shared.image_map(ROOT / "config/integration-images.lock.json")
        spec = durka.kit.compose_spec(profile, self.value["credentials"], state["project"], images)

        def read(path):
            if path.name == "packmate.properties":
                return durka.kit.properties(profile, self.value["credentials"]).encode("ascii")
            return ('grpc_auth_key: "' + self.value["credentials"]["neo_key"] + '"\n').encode("ascii")

        with mock.patch.object(durka.kit, "workspace", return_value=(root, state, spec, profile)), mock.patch.object(durka.kit, "read", side_effect=read):
            durka.check_config(root, self.value)
            changed = copy.deepcopy(self.value)
            changed["credentials"]["neo_key"] = "different-secret-value-0123456789"
            with self.assertRaisesRegex(durka.Error, "configuration changed"):
                durka.check_config(root, changed)

    def test_empty_capture_is_valid_and_existing_capture_is_retained(self):
        root = self.paths["workspace"]
        (root / "pcaps").mkdir(parents=True)
        durka.empty_capture(root, self.value["profile"])
        path = root / "pcaps/capture.pcap"
        helper = durka.module("durka_test_capture", "deployment/packmate_file.py")
        _, _, summary = helper.inspect_file(path)
        self.assertEqual(summary["packet_records"], 0)
        self.assertEqual(summary["bytes"], 24)
        before = path.read_bytes()
        durka.empty_capture(root, self.value["profile"])
        self.assertEqual(path.read_bytes(), before)

    def test_setup_already_built_is_offline_and_resumable(self):
        root = self.paths["workspace"]
        root.mkdir()
        (root / "deployment.json").touch()
        (root / "build-receipt.json").touch()
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config"), \
                mock.patch.object(durka, "bind_paths"), mock.patch.object(durka, "source_checkout") as fetch, \
                mock.patch.object(durka.kit, "execute") as execute:
            code, output = self.quiet(durka.setup, self.value, self.paths)
        self.assertEqual(code, 0)
        self.assertIn("already complete", output)
        self.assertEqual(execute.call_args.args[0].action, "preflight")
        self.assertTrue(execute.call_args.args[0].runtime)
        fetch.assert_not_called()

    def test_setup_preserves_unknown_incomplete_workspace(self):
        root = self.paths["workspace"]
        root.mkdir()
        marker = root / "existing.data"
        marker.write_bytes(b"retained")
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka.kit.shared, "checked") as external:
            with self.assertRaisesRegex(durka.Error, "incomplete workspace"):
                durka.setup(self.value, self.paths)
        self.assertEqual(marker.read_bytes(), b"retained")
        external.assert_not_called()

    def test_setup_uses_pinned_images_and_explicit_platforms(self):
        root = self.paths["workspace"]

        def prepare(args):
            (root / "pcaps").mkdir(parents=True)

        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "source_checkout", return_value=self.root), \
                mock.patch.object(durka, "bind_paths"), \
                mock.patch.object(durka.kit, "prepare", side_effect=prepare) as prepare_mock, \
                mock.patch.object(durka.kit, "execute") as execute, mock.patch.object(durka.kit.shared, "checked") as external:
            self.quiet(durka.setup, self.value, self.paths)
        self.assertTrue(prepare_mock.call_args.args[0].apply)
        calls = [call.args[0] for call in external.call_args_list]
        self.assertEqual(len(calls), 10)
        self.assertTrue(all(argv[:2] == ["docker", "pull"] and "@sha256:" in argv[-1] for argv in calls))
        packmate = next(argv for argv in calls if argv[-1] == durka.kit.PACKMATE)
        self.assertEqual(packmate[3], "linux/amd64")
        database = next(argv for argv in calls if argv[-1] == durka.kit.PACKMATE_DB)
        self.assertEqual(database[3], "linux/arm64")
        self.assertTrue(execute.call_args.args[0].connected_preparation)
        self.assertTrue((root / "pcaps/capture.pcap").is_file())

    def test_source_cache_rejects_unknown_directory_before_git(self):
        root = self.paths["sources"]
        root.mkdir(mode=0o700)
        with mock.patch.object(durka.kit.shared, "checked") as external:
            with self.assertRaisesRegex(durka.Error, "not this operator cache"):
                durka.source_checkout(root, "neo", {"neo": {"repository": "https://example.invalid/repo", "commit": "a" * 40}})
        external.assert_not_called()

    def test_source_cache_rejects_changed_origin_before_fetch(self):
        root = self.paths["sources"]
        root.mkdir(mode=0o700)
        source = {"neo": {"repository": "https://example.invalid/repo", "commit": "a" * 40}}
        durka.kit.shared.write(root / ".durka-sources.json", durka.kit.shared.canonical(
            {"schema": "durkahelper.operator-sources.v1", "sources": source}))
        (root / "neo/.git").mkdir(parents=True)
        with mock.patch.object(durka.kit.shared, "checked", return_value=b"https://different.example.invalid/repo\n") as external:
            with self.assertRaisesRegex(durka.Error, "origin differs"):
                durka.source_checkout(root, "neo", source)
        self.assertEqual(external.call_count, 1)
        self.assertNotIn("fetch", external.call_args.args[0])

    def context(self):
        root = self.paths["workspace"]
        profile = self.value["profile"]
        return root, {"project": "dh-deploy-" + "a" * 12}, {"services": {"farm": {}, "neo-server": {}}}, profile

    def test_status_prints_only_states_and_addresses_not_secrets(self):
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                mock.patch.object(durka.kit, "owned_resources"), mock.patch.object(durka.kit.shared, "checked", return_value=
                b'{"Service":"farm","State":"running","Password":"SHOULD_NOT_PRINT"}\n'):
            code, output = self.quiet(durka.run_operator, "status", self.value, self.paths)
        self.assertEqual(code, 0)
        self.assertIn("S4DFarm: http://127.0.0.1:8080", output)
        self.assertIn("task API, not a website", output)
        self.assertNotIn("SHOULD_NOT_PRINT", output)
        self.assertNotIn(self.value["credentials"]["farm_password"], output)

    def test_worker_and_shutdown_reuse_project_actions_without_confirmation_flags(self):
        for action in ("worker", "down"):
            with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                    mock.patch.object(durka.kit, "workspace", return_value=self.context()), \
                    mock.patch.object(durka.kit, "execute") as execute:
                self.quiet(durka.run_operator, action, self.value, self.paths)
            self.assertEqual(execute.call_args.args[0].action, action)
            self.assertTrue(execute.call_args.args[0].apply)
            self.assertTrue(execute.call_args.args[0].approval_id.startswith("operator-"))

    def test_submit_rejects_placeholder_endpoint_and_token(self):
        for endpoint, token in (("http://receiver.example.invalid/flags", "real-token"),
                                ("http://192.0.2.2/flags", "REPLACE_WITH_TOKEN")):
            self.value["profile"]["farm"]["protocol_settings"] = {"SYSTEM_URL": endpoint, "SYSTEM_TOKEN": token}
            with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                    mock.patch.object(durka.kit, "execute") as execute:
                with self.assertRaisesRegex(durka.Error, "real competition endpoint"):
                    durka.run_operator("submit", self.value, self.paths)
            execute.assert_not_called()

    def test_submit_is_explicit_consent_and_routes_to_existing_queue_helper(self):
        self.value["profile"]["farm"]["protocol_settings"] = {"SYSTEM_URL": "http://192.0.2.2/flags", "SYSTEM_TOKEN": "actual-token"}
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                mock.patch.object(durka.kit, "execute") as execute:
            self.quiet(durka.run_operator, "submit", self.value, self.paths)
        args = execute.call_args.args[0]
        self.assertEqual(args.action, "enable-submission")
        self.assertTrue(args.protocol_reviewed and args.queue_reviewed and args.apply)

    def test_traffic_import_derives_hash_and_daemon_without_printing_values(self):
        helper = SimpleNamespace(Error=durka.Error, inspect_file=mock.Mock(return_value=(None, None, {"sha256": "a" * 64})),
                                 replace=mock.Mock(return_value={"status": "PASS"}))
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                mock.patch.object(durka, "module", return_value=helper), \
                mock.patch.object(durka.kit.shared, "checked", return_value=b"private-daemon-id\n"):
            code, output = self.quiet(durka.import_traffic, self.value, self.paths, "closed.pcap")
        args = helper.replace.call_args.args[0]
        self.assertEqual(args.expected_sha256, "a" * 64)
        self.assertEqual(args.daemon_id, "private-daemon-id")
        self.assertTrue(args.apply and args.closed_pcap_confirmed and args.maintenance_confirmed)
        self.assertEqual(code, 0)
        self.assertNotIn("a" * 64, output)
        self.assertNotIn("private-daemon-id", output)
        self.assertIn("yellow downward-arrow FILE-processing button", output)
        self.assertNotIn("press Start", output)

    def test_traffic_import_translates_helper_error_to_sanitized_cli_error(self):
        class OtherError(Exception):
            pass
        helper = SimpleNamespace(Error=OtherError, inspect_file=mock.Mock(side_effect=OtherError("capture framing is invalid")))
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "check_config", return_value=self.context()), \
                mock.patch.object(durka, "module", return_value=helper):
            with self.assertRaisesRegex(durka.Error, "capture framing is invalid"):
                durka.import_traffic(self.value, self.paths, "closed.pcap")

    def test_cli_unknown_exception_never_discloses_payload(self):
        output = io.StringIO()
        with mock.patch.object(durka, "load_config", side_effect=ValueError("secret-from-invalid-config")), contextlib.redirect_stderr(output):
            self.assertEqual(durka.main(["status"]), 2)
        self.assertNotIn("secret-from-invalid-config", output.getvalue())
        self.assertIn("ValueError", output.getvalue())

    def configured_workspace(self):
        """Small valid owned deployment; sources and live data are not rewritten."""
        root = self.paths["workspace"]
        root.mkdir(mode=0o700)
        for folder in ("postgres", "redis", "neo-redis", "neo", "packmate-db"):
            (root / "data" / folder).mkdir(parents=True, mode=0o700)
        (root / "pcaps").mkdir()
        project = "dh-deploy-" + "a" * 12
        images = durka.kit.shared.image_map(ROOT / "config/integration-images.lock.json")
        spec = durka.kit.compose_spec(self.value["profile"], self.value["credentials"], project, images)
        base = {"config/farm.py": b"CONFIG = {}\n", "config/packmate.properties": durka.kit.properties(self.value["profile"], self.value["credentials"]).encode(),
                "config/neo-server.yml": ('grpc_auth_key: "' + self.value["credentials"]["neo_key"] + '"\n').encode(),
                "profile.json": durka.kit.shared.canonical(self.value["profile"]), "compose.json": durka.kit.shared.canonical(spec),
                "model.json": durka.kit.shared.canonical(durka.kit.model(spec, self.value["profile"])),
                "policy.json": durka.kit.shared.canonical(durka.kit.policy(self.value["profile"], durka.kit.model(spec, self.value["profile"]))),
                "operator-paths.json": durka.kit.shared.canonical({"schema": "durkahelper.operator-paths.v1",
                    "paths": {name: str(path) for name, path in self.paths.items()}})}
        for name, data in base.items():
            durka.kit.shared.write(root / name, data)
        state = {"schema": durka.kit.SCHEMA, "project": project, "files": {name: durka.checksum(data) for name, data in base.items()},
                 "source_pins": durka.kit.shared.PINS, "approval_id": "test-operator"}
        durka.kit.shared.write(root / "deployment.json", durka.kit.shared.canonical(state))
        identities = {name: "sha256:" + durka.checksum(name.encode()) for name in spec["services"]}
        runtime = durka.kit.runtime_spec(spec, identities)
        runtime_model = durka.kit.model(runtime, self.value["profile"])
        receipt = {"schema": "durkahelper.deployment-build.v2", "images": identities,
                   "compose_sha256": durka.checksum(durka.kit.shared.canonical(spec)),
                   "runtime_sha256": durka.checksum(durka.kit.shared.canonical(runtime))}
        for name, value in (("runtime-compose.json", runtime), ("runtime-model.json", runtime_model),
                            ("runtime-policy.json", durka.kit.policy(self.value["profile"], runtime_model)), ("build-receipt.json", receipt)):
            durka.kit.shared.write(root / name, durka.kit.shared.canonical(value))
        (root / "data/neo/retained.txt").write_bytes(b"previous-task-state")
        return root, identities

    def change_event_settings(self):
        self.value["profile"]["bind_address"] = "192.0.2.10"
        self.value["profile"]["ports"] = {"farm": 8081, "neo": 5006, "packmate": 65001}
        self.value["profile"]["farm"]["teams"] = {"Red": "192.0.2.20", "Blue": "192.0.2.21"}
        self.value["profile"]["farm"]["protocol_settings"] = {"SYSTEM_URL": "http://192.0.2.30/flags", "SYSTEM_TOKEN": "actual-event-token"}
        self.value["profile"]["packmate"]["local_ip"] = "192.0.2.20"

    @unittest.skipIf(os.name == "nt", "configuration replacement is a POSIX deployment operation")
    def test_configure_rebinds_event_settings_offline_and_retains_images_data(self):
        root, identities = self.configured_workspace()
        self.change_event_settings()
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "stopped"), \
                mock.patch.object(durka.kit, "image_preflight", return_value=identities), \
                mock.patch.object(durka.kit.shared, "checked") as external:
            code, output = self.quiet(durka.configure, self.value, self.paths)
        self.assertEqual(code, 0)
        external.assert_not_called()
        root, state, spec, profile = durka.kit.workspace(root)
        durka.kit.check_build_receipt(root, spec, identities)
        self.assertEqual(profile, self.value["profile"])
        self.assertEqual((root / "data/neo/retained.txt").read_bytes(), b"previous-task-state")
        self.assertEqual(spec["services"]["front"]["ports"][0]["host_ip"], "192.0.2.10")
        self.assertIn("actual-event-token", (root / "config/farm.py").read_text())
        self.assertIn('url: "http://192.0.2.10:8081"', (root / "config/neo-server.yml").read_text())
        self.assertNotIn("actual-event-token", output)
        self.assertNotIn(identities["farm"], output)
        self.assertEqual(durka.kit.load(root / durka.CONFIG_JOURNAL)["phase"], "committed")

    @unittest.skipIf(os.name == "nt", "configuration replacement is a POSIX deployment operation")
    def test_configure_rollback_restores_previous_metadata_and_keeps_data(self):
        root, identities = self.configured_workspace()
        before = {name: durka.kit.read(root / name) for name in durka.CONFIG_FILES}
        self.change_event_settings()
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "stopped"), \
                mock.patch.object(durka.kit, "image_preflight", return_value=identities):
            self.quiet(durka.configure, self.value, self.paths)
            code, output = self.quiet(durka.configure, self.value, self.paths, True)
        self.assertEqual(code, 0)
        self.assertEqual({name: durka.kit.read(root / name) for name in durka.CONFIG_FILES}, before)
        self.assertIn("over the private operator config", output)
        self.assertEqual((root / "data/neo/retained.txt").read_bytes(), b"previous-task-state")

    @unittest.skipIf(os.name == "nt", "configuration replacement is a POSIX deployment operation")
    def test_configure_automatically_rolls_back_a_failed_file_update(self):
        root, identities = self.configured_workspace()
        before = {name: durka.kit.read(root / name) for name in durka.CONFIG_FILES}
        self.change_event_settings()
        original = durka.replace_file
        failed = False

        def fail_once(path, payload, expected):
            nonlocal failed
            if path.name == "policy.json" and not failed:
                failed = True
                raise durka.Error("injected configuration failure")
            return original(path, payload, expected)

        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "stopped"), \
                mock.patch.object(durka.kit, "image_preflight", return_value=identities), \
                mock.patch.object(durka, "replace_file", side_effect=fail_once):
            with self.assertRaisesRegex(durka.Error, "injected configuration failure"):
                durka.configure(self.value, self.paths)
        self.assertEqual({name: durka.kit.read(root / name) for name in durka.CONFIG_FILES}, before)
        self.assertEqual(durka.kit.load(root / durka.CONFIG_JOURNAL)["phase"], "rolled-back")

    def test_configure_rejects_credential_and_runtime_rotation(self):
        root, identities = self.configured_workspace()
        for name in ("credentials", "runtime"):
            altered = copy.deepcopy(self.value)
            if name == "credentials":
                altered["credentials"]["neo_key"] = "different-generated-key-0123456789"
            else:
                altered["profile"]["allow_amd64_emulation"] = False
            with mock.patch.object(durka, "require_host"), mock.patch.object(durka.kit.shared, "checked") as external:
                with self.assertRaises(durka.Error):
                    durka.configure(altered, self.paths)
            external.assert_not_called()
        self.assertFalse((root / "configuration-backups").exists())

    def test_configure_rejects_changed_operator_paths(self):
        self.configured_workspace()
        changed = dict(self.paths, sources=self.root / "other-sources")
        with mock.patch.object(durka, "require_host"):
            with self.assertRaisesRegex(durka.Error, "cannot change operator paths"):
                durka.configure(self.value, changed)

    def test_stopped_check_includes_running_submission_or_worker(self):
        with mock.patch.object(durka.kit, "owned_resources"), \
                mock.patch.object(durka.kit.shared, "checked", side_effect=[b"aabbccddeeff\n", b"true;false\n"]):
            with self.assertRaisesRegex(durka.Error, "stop the entire deployment"):
                durka.stopped({"project": "dh-deploy-" + "a" * 12})

    @unittest.skipIf(os.name == "nt", "configuration replacement is a POSIX deployment operation")
    def test_rollback_refuses_tampered_private_backup(self):
        root, identities = self.configured_workspace()
        self.change_event_settings()
        with mock.patch.object(durka, "require_host"), mock.patch.object(durka, "stopped"), \
                mock.patch.object(durka.kit, "image_preflight", return_value=identities):
            self.quiet(durka.configure, self.value, self.paths)
        journal = durka.kit.load(root / durka.CONFIG_JOURNAL)
        (root / journal["backup"] / "profile.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(durka.Error, "recovery files changed"):
            durka.configuration_rollback(root)


if __name__ == "__main__":
    unittest.main()
