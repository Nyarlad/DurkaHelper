"""Offline clean-deployment routing: no downloads, builds or source-data writes."""
import contextlib
import io
import os
from pathlib import Path
from unittest import mock
import unittest

import test_durka

d = test_durka.durka


class PrepareCleanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_durka.OperatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.value["profile"]["farm"]["teams"] = {"Training": "192.0.2.33"}
        self.fixture.value["profile"]["farm"]["protocol_settings"] = {
            "SYSTEM_URL": "http://192.0.2.44/flags", "SYSTEM_TOKEN": "training-only-token"}
        self.old_root, self.images = self.fixture.configured_workspace()
        self.old_config = self.fixture.config
        d.kit.shared.write(self.old_config, d.kit.shared.canonical(self.fixture.value))
        self.target = self.fixture.root / "competition.json"
        self.before = {p: p.read_bytes() for p in self.old_root.rglob("*") if p.is_file()}
        self.config_before = self.old_config.read_bytes()

    def run_clean(self, apply=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = d.prepare_clean(self.target, self.old_config, apply)
        return code, output.getvalue()

    def prepare(self, args):
        # Generate a valid, empty candidate; Docker and Git are mocked separately.
        previous = self.fixture.value, self.fixture.paths
        try:
            self.fixture.value = dict(self.fixture.value,
                profile=d.kit.load(args.profile), credentials=d.kit.load(args.credentials))
            self.fixture.paths = dict(self.fixture.paths, workspace=Path(args.workspace))
            root, _ = self.fixture.configured_workspace()
            # prepare itself does not produce runtime receipts or task data.
            for name in ("runtime-compose.json", "runtime-model.json", "runtime-policy.json", "build-receipt.json"):
                (root / name).unlink()
            (root / "data/neo/retained.txt").unlink()
        finally:
            self.fixture.value, self.fixture.paths = previous

    def git(self, path, args):
        return (d.kit.shared.PINS[path.name] + "\n").encode() if args[0] == "rev-parse" else b""

    def mocks(self, stack):
        stack.enter_context(mock.patch.object(d, "require_host"))
        stack.enter_context(mock.patch.object(d, "stopped"))
        stack.enter_context(mock.patch.object(d.kit, "image_preflight", return_value=self.images))
        stack.enter_context(mock.patch.object(d.kit.shared, "git_read", side_effect=self.git))
        stack.enter_context(mock.patch.object(d.kit, "prepare", side_effect=self.prepare))
        stack.enter_context(mock.patch.object(d.kit, "execute"))
        return stack.enter_context(mock.patch.object(d.kit.shared, "checked", return_value=b"unix:///var/run/docker.sock\n"))

    def assert_original_retained(self):
        self.assertEqual(self.old_config.read_bytes(), self.config_before)
        self.assertEqual({p: p.read_bytes() for p in self.old_root.rglob("*") if p.is_file()}, self.before)

    def test_preview_is_read_only_without_docker_git_or_directory_creation(self):
        with mock.patch.object(d.kit.shared, "checked") as external, \
                mock.patch.object(d.kit.shared, "write", side_effect=AssertionError("write")), \
                mock.patch.object(d, "private_directory", side_effect=AssertionError("mkdir")):
            code, output = self.run_clean()
        self.assertEqual(code, 0)
        self.assertIn("Preview", output)
        external.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.target.with_name("competition-workspace").exists())
        self.assert_original_retained()

    def test_apply_fresh_state_new_secrets_placeholders_and_same_images(self):
        with contextlib.ExitStack() as stack:
            external = self.mocks(stack)
            code, output = self.run_clean(True)
        self.assertEqual(code, 0)
        value, paths = d.load_config(self.target)
        root, _, spec, _ = d.check_config(paths["workspace"], value)
        d.kit.check_build_receipt(root, spec, self.images)
        self.assertEqual(value["profile"]["bind_address"], "127.0.0.1")
        self.assertEqual(value["profile"]["farm"]["teams"], {"Example": "192.0.2.1"})
        self.assertTrue(value["profile"]["farm"]["protocol_settings"]["SYSTEM_TOKEN"].startswith("REPLACE_"))
        self.assertTrue(value["profile"]["farm"]["protocol_settings"]["SYSTEM_URL"].endswith(".invalid/flags"))
        for name in ("farm_password", "database_password", "neo_key", "packmate_password"):
            self.assertNotEqual(value["credentials"][name], self.fixture.value["credentials"][name])
            self.assertNotIn(value["credentials"][name], output)
        self.assertNotIn("training-only-token", output)
        self.assertTrue(all(not list(folder.iterdir()) for folder in (root / "data").iterdir()))
        native = (root / "config/neo-native.yml").read_text()
        self.assertIn(value["credentials"]["neo_key"], native)
        self.assertNotIn(self.fixture.value["credentials"]["neo_key"], native)
        self.assertIn("data/native-worker", native.replace("\\\\", "/"))
        helper = d.module("clean_pcap_test", "deployment/packmate_file.py")
        self.assertEqual(helper.inspect_file(root / "pcaps/capture.pcap")[2]["packet_records"], 0)
        self.assertEqual(spec["services"]["celery"]["profiles"], ["submission"])
        self.assertEqual(spec["services"]["neo-worker"]["profiles"], ["worker"])
        self.assertEqual([c.args[0][:3] for c in external.call_args_list], [["docker", "context", "inspect"]])
        self.assert_original_retained()

    def test_existing_targets_never_overwritten(self):
        for is_config in (True, False):
            path = self.target if is_config else self.target.with_name("competition-workspace")
            path.write_bytes(b"existing")
            try:
                with self.assertRaises(d.Error):
                    self.run_clean(True)
                self.assertEqual(path.read_bytes(), b"existing")
            finally:
                path.unlink()
        self.assert_original_retained()

    def test_missing_cache_or_running_source_stops_before_candidate_writes(self):
        for function in ("stopped", "image_preflight"):
            with contextlib.ExitStack() as stack:
                self.mocks(stack)
                owner = d if function == "stopped" else d.kit
                stack.enter_context(mock.patch.object(owner, function, side_effect=d.Error("blocked")))
                with self.assertRaises(d.Error):
                    self.run_clean(True)
            self.assertFalse(self.target.exists())
            self.assertFalse(self.target.with_name("competition-workspace").exists())
        self.assert_original_retained()

    def test_remote_daemon_and_dirty_source_rejected_before_writes(self):
        for problem in ("remote", "dirty"):
            with contextlib.ExitStack() as stack:
                self.mocks(stack)
                if problem == "remote":
                    stack.enter_context(mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://example.invalid:2375", "DOCKER_CONTEXT": ""}))
                else:
                    stack.enter_context(mock.patch.object(d.kit.shared, "git_read", return_value=b"changed"))
                with self.assertRaises(d.Error):
                    self.run_clean(True)
            self.assertFalse(self.target.exists())
            self.assertFalse(self.target.with_name("competition-workspace").exists())
        self.assert_original_retained()

    def test_interrupted_preparation_retains_original_and_does_not_publish_config(self):
        with contextlib.ExitStack() as stack:
            self.mocks(stack)
            stack.enter_context(mock.patch.object(d.kit, "execute", side_effect=d.Error("failed preflight")))
            with self.assertRaises(d.Error):
                self.run_clean(True)
        self.assertFalse(self.target.exists())
        self.assertTrue(self.target.with_name("competition-workspace").exists())
        self.assert_original_retained()

    def test_cli_routes_before_loading_new_missing_config(self):
        with mock.patch.object(d, "prepare_clean", return_value=0) as prepare:
            self.assertEqual(d.main(["--config", str(self.target), "prepare-clean",
                                    "--from-config", str(self.old_config), "--apply"]), 0)
        prepare.assert_called_once_with(str(self.target), str(self.old_config), True)

    @unittest.skipIf(os.name == "nt", "real private prepare requires POSIX permissions")
    def test_actual_prepare_generates_isolated_files_without_copying_old_runtime_data(self):
        original_prepare = d.kit.prepare

        def export(source, target, name):
            if name == "s4dfarm":
                for role, image in (("server", "python:3.9-slim"), ("celery", "python:3.9-slim"), ("front", "node:20-slim")):
                    d.kit.shared.write(target / "server/docker" / role / "Dockerfile", "FROM " + image + "\n")
                d.kit.shared.write(target / "server/app/fixture.txt", "pinned-source-fixture\n")
            else:
                d.kit.shared.write(target / "Dockerfile", "FROM golang:1.21-alpine\nENV CGO_ENABLED=0\n")

        with contextlib.ExitStack() as stack:
            self.mocks(stack)
            stack.enter_context(mock.patch.object(d.kit, "prepare", side_effect=original_prepare))
            stack.enter_context(mock.patch.object(d.kit.shared, "export_source", side_effect=export))
            self.run_clean(True)
        value, paths = d.load_config(self.target)
        root, _, spec, _ = d.check_config(paths["workspace"], value)
        d.kit.check_build_receipt(root, spec, self.images)
        self.assertEqual(self.target.stat().st_mode & 0o077, 0)
        self.assertTrue(all(not list(folder.iterdir()) for folder in (root / "data").iterdir()))
        self.assert_original_retained()


if __name__ == "__main__":
    unittest.main()
