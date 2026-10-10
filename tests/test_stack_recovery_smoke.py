"""Whole-stack recovery safety contracts; not application runtime evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stack_recovery_test", ROOT / "integration/stack_recovery_smoke.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


def archive(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as result:
        for name, data, kind in members:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            item.linkname = "outside" if kind == tarfile.SYMTYPE else ""
            result.addfile(item, io.BytesIO(data) if item.isfile() else None)
    return stream.getvalue()


class WholeStackRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.project = "dh-whole-" + "a" * 12
        self.state = {"id": self.project, "projects": {role: self.project + "-" + role for role in recovery.ROLES}}
        self.spec = {"services": {
            "farm": {"image": "mutable:farm", "build": {"context": "."}, "depends_on": {"receiver": {"condition": "service_started"}}},
            "celery": {"image": "mutable:celery"}, "receiver": {"image": "python@sha256:" + "b" * 64},
            "redis": {"image": "redis:fixture", "command": ["redis-server", "--appendonly", "yes"]},
            "neo-redis": {"image": "redis:fixture"}, "neo-client": {"image": "neo:fixture"}},
            "networks": {"fixture": {"internal": True}, "edge": {}}}
        self.images = {name: "sha256:" + "b" * 64 for name in self.spec["services"]}

    def test_restore_profiles_disable_queue_consumers_and_receiver(self):
        spec = recovery.owned_spec(self.spec, self.project, self.images, restored=True)
        for name in ("celery", "receiver", "neo-client"):
            self.assertEqual(spec["services"][name]["profiles"], ["disabled-recovery"])
        self.assertNotIn("receiver", spec["services"]["farm"]["depends_on"])
        for name in ("redis", "neo-redis"):
            self.assertEqual(spec["services"][name]["command"], ["redis-server", "--appendonly", "no", "--save", ""])

    def test_owned_spec_immutable_images_and_exact_labels(self):
        result = recovery.owned_spec(self.spec, self.project, self.images)
        for name, service in result["services"].items():
            self.assertEqual(service["image"], self.images[name])
            self.assertNotIn("build", service)
            self.assertEqual(service["labels"], {recovery.LABEL: self.project})
            self.assertEqual(service["restart"], "no")
        self.assertIn("build", self.spec["services"]["farm"])
        self.assertTrue(result["networks"]["fixture"]["internal"])
        self.assertTrue(all(net["labels"] == {recovery.LABEL: self.project} for net in result["networks"].values()))

    def test_neo_starts_only_after_farm_readiness_on_source_and_restore(self):
        for source, role in ((True, "source-farm"), (False, "target-farm")):
            events = []
            state = dict(self.state, task={"id": "synthetic"}, helper_image="sha256:" + "a" * 64)
            with mock.patch.object(recovery, "compose", side_effect=lambda *a: events.append(a[3])), \
                    mock.patch.object(recovery.stack, "farm_port", return_value=12345), \
                    mock.patch.object(recovery.stack, "wait_ready", side_effect=lambda port: events.append("farm-ready")), \
                    mock.patch.object(recovery.life, "run_client", return_value=b"ready"):
                recovery.start_farm_apps(Path("/synthetic"), state, role, source=source)
            self.assertNotIn("neo-server", events[0])
            self.assertEqual(events[1], "farm-ready")
            self.assertEqual(events[2][-2:], ["--no-deps", "neo-server"])
            if not source:
                self.assertNotIn("celery", events[0])
                self.assertNotIn("receiver", events[0])

    def test_neo_readiness_retries_without_executing_a_task(self):
        state = dict(self.state, task={"id": "synthetic"}, helper_image="sha256:" + "a" * 64)
        with mock.patch.object(recovery, "compose"), mock.patch.object(recovery.stack, "farm_port", return_value=12345), \
                mock.patch.object(recovery.stack, "wait_ready"), mock.patch.object(recovery.time, "sleep"), \
                mock.patch.object(recovery.life, "run_client", side_effect=[recovery.life.Error("not ready"), b"ready"]) as client:
            recovery.start_farm_apps(Path("/synthetic"), state, "source-farm", source=True)
        self.assertEqual(client.call_count, 2)
        self.assertTrue(all(c.args[-1] == "info" for c in client.call_args_list))

    def test_cold_archive_valid_files(self):
        data = archive([(".", b"", tarfile.DIRTYPE), ("./db.db", b"bbolt-bytes", tarfile.REGTYPE),
                        ("./exploits", b"", tarfile.DIRTYPE), ("./exploits/123", b"synthetic", tarfile.REGTYPE)])
        self.assertEqual(recovery.archive_files(data), {"db.db": b"bbolt-bytes", "exploits/123": b"synthetic"})

    def test_cold_archive_rejects_traversal_links_and_duplicates(self):
        cases = [[("../escape", b"bad", tarfile.REGTYPE)], [("/absolute", b"bad", tarfile.REGTYPE)],
                 [("linked", b"", tarfile.SYMTYPE)], [("device", b"", tarfile.CHRTYPE)],
                 [("file", b"first", tarfile.REGTYPE), ("file", b"second", tarfile.REGTYPE)],
                 [("dir", b"", tarfile.DIRTYPE), ("dir", b"", tarfile.DIRTYPE)]]
        for members in cases:
            with self.subTest(members=members), self.assertRaises(recovery.Error):
                recovery.archive_files(archive(members))

    def test_cold_archive_bound(self):
        with mock.patch.object(recovery, "MAX_BACKUP", 20), self.assertRaises(recovery.Error):
            recovery.archive_files(b"x" * 21)

    def test_template_copy_never_accepts_database_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for member in ("data/postgres/base/1", "../outside", "/absolute", "a\\b"):
                with self.assertRaises(recovery.Error):
                    recovery.copy_immutable(root, root / "new", [member])
            self.assertFalse((root / "new").exists())

    def test_template_copy_only_explicit_immutable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/config.yml").write_bytes(b"synthetic-config")
            (root / "source/unlisted.txt").write_bytes(b"unrelated-data")
            recovery.copy_immutable(root / "source", root / "target", ["config.yml", "compose.json", "fixture.json"])
            self.assertEqual((root / "target/config.yml").read_bytes(), b"synthetic-config")
            self.assertFalse((root / "target/unlisted.txt").exists())

    def test_ownership_mismatch_stops_before_mutation(self):
        with mock.patch.object(recovery, "checked", side_effect=[b"b" * 64, b"another-owner"]) as checked:
            with self.assertRaisesRegex(recovery.Error, "ownership"):
                recovery.ownership(self.state, "source-farm")
            self.assertEqual(checked.call_count, 2)
            self.assertTrue(all("rm" not in call.args[0] for call in checked.call_args_list))

    def test_empty_ownership_only_lists(self):
        with mock.patch.object(recovery, "checked", return_value=b"") as checked:
            recovery.ownership(self.state, "target-packmate")
            self.assertEqual(checked.call_count, 2)
            self.assertNotIn("prune", repr(checked.call_args_list))

    def test_image_identity_rejects_wrong_architecture_and_mutable_tags(self):
        for raw in (b"sha256:" + b"a" * 64 + b";linux;arm64", b"mutable:tag;linux;amd64"):
            with mock.patch.object(recovery, "checked", return_value=raw), self.assertRaises(recovery.Error):
                recovery.image_id("image")

    def test_prepare_preview_never_invokes_docker_or_creates_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(workspace=str(root / "new"), stack_workspace="farm", packmate_workspace="packmate", release_workspace="release", apply=False)
            with mock.patch.object(recovery.stack, "fixture", return_value=(root / "farm", {})), mock.patch.object(recovery, "validate_synthetic_template"), mock.patch.object(recovery.pm, "fixture", return_value=(root / "pm", {})), mock.patch.object(recovery.life.release, "fixture", return_value=(root / "release", {})), mock.patch.object(recovery, "checked", side_effect=AssertionError("runtime invoked")):
                self.assertEqual(recovery.prepare(args)["status"], "NOT_RUN")
            self.assertFalse((root / "new").exists())

    def test_rehashed_real_target_template_still_rejected(self):
        with mock.patch.object(recovery, "read", return_value=b"CONFIG = {'SYSTEM_URL': 'http://real.example/flags'}\n"):
            with self.assertRaisesRegex(recovery.Error, "synthetic"):
                recovery.validate_synthetic_template(Path("fixture"))

    def test_executable_template_never_evaluated(self):
        with mock.patch.object(recovery, "read", return_value=b"import os\nos.system('echo unsafe')\n"):
            with self.assertRaisesRegex(recovery.Error, "literal"):
                recovery.validate_synthetic_template(Path("fixture"))

    def test_restore_snapshot_gate_precedes_docker(self):
        args = SimpleNamespace(workspace="fixture", apply=True, snapshot_confirmed=False)
        with mock.patch.object(recovery, "fixture", return_value=(Path("/fixture"), self.state)), mock.patch.object(recovery, "checked", side_effect=AssertionError("runtime invoked")):
            with self.assertRaisesRegex(recovery.Error, "snapshot"):
                recovery.run(args)

    def test_nonempty_database_blocks_restore(self):
        with mock.patch.object(recovery, "psql", return_value=b"1"), mock.patch.object(recovery.subprocess, "run", side_effect=AssertionError("restore invoked")):
            with self.assertRaisesRegex(recovery.Error, "not empty"):
                recovery.restore_pg([], "db", "packmate", Path("missing"), {})

    def test_tampered_dump_blocks_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dump"
            path.write_bytes(b"PGDMPcontent")
            with mock.patch.object(recovery, "psql", return_value=b"0"), mock.patch.object(recovery.subprocess, "run", side_effect=AssertionError("restore invoked")):
                with self.assertRaisesRegex(recovery.Error, "checksum"):
                    recovery.restore_pg([], "db", "packmate", path, {"bytes": 12, "sha256": "0" * 64})

    def test_bounded_capture_returns_small_result(self):
        self.assertEqual(recovery.checked([sys.executable, "-c", "print('bounded')"]).strip(), b"bounded")

    def test_bounded_capture_overflow_suppressed(self):
        with mock.patch.object(recovery, "MAX_BACKUP", 100), self.assertRaises(recovery.Error) as error:
            recovery.checked([sys.executable, "-c", "print('secret' * 10000)"])
        self.assertNotIn("secret", str(error.exception))

    def test_missing_approval_fails_before_lookup(self):
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(recovery, "fixture", side_effect=AssertionError("lookup")):
            self.assertEqual(recovery.main(["run", "--workspace", "missing", "--apply"]), 2)

    def test_untrusted_exception_payload_is_suppressed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(recovery, "run", side_effect=ValueError("private-token-canary")):
            self.assertEqual(recovery.main(["run", "--workspace", "missing"]), 2)
        self.assertNotIn("private-token-canary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
