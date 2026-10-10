"""Offline contract tests for a new synthetic native Redis recovery drill."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("redis_recovery_test", ROOT / "integration/component_recovery_smoke.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


class ComponentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.state = {"id": "dh-redis-recovery-" + "a" * 12, "uid": 1000, "gid": 1000,
                      "image": "redis:7.2.0-alpine@sha256:" + "b" * 64}

    def test_isolated_native_container_no_ports_or_privileges(self):
        argv = recovery.arguments(Path("/fixture"), self.state, "source")
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--pull=never", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("-p", argv)
        self.assertNotIn("--publish", argv)
        self.assertEqual(argv[argv.index("--user") + 1], "1000:1000")
        self.assertIn("redis-server", argv)

    def test_restore_has_separate_directory_and_name(self):
        argv = recovery.arguments(Path("/fixture"), self.state, "restore")
        self.assertIn(self.state["id"] + "-restore", argv)
        self.assertTrue(any("restore" in value and "dst=/data" in value for value in argv))
        with self.assertRaises(recovery.Error):
            recovery.arguments(Path("/fixture"), self.state, "../../existing")

    def test_cleanup_never_deletes_foreign_container(self):
        with mock.patch.object(recovery.shared, "checked", return_value=b"foreign") as checked:
            with self.assertRaises(recovery.Error):
                recovery.cleanup(self.state, "source")
            self.assertEqual(checked.call_count, 1)

    def test_redis_command_allowlist_rejects_flushall(self):
        with self.assertRaises(recovery.Error):
            recovery.cli(self.state, "source", "FLUSHALL")

    def test_preview_no_files_or_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new"
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(recovery.shared, "checked", side_effect=AssertionError("executed")):
                self.assertEqual(recovery.main(["prepare", "--workspace", str(path)]), 0)
            self.assertFalse(path.exists())

    def test_apply_without_approval_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(recovery.main(["prepare", "--workspace", "missing", "--apply"]), 2)

    def test_snapshot_required_before_runtime_checks(self):
        args = type("Args", (), {"workspace": "fixture", "apply": True, "snapshot_confirmed": False})()
        with mock.patch.object(recovery, "fixture", return_value=(Path("/fixture"), self.state)), mock.patch.object(recovery.shared, "checked", side_effect=AssertionError("executed")):
            with self.assertRaisesRegex(recovery.Error, "snapshot"):
                recovery.smoke(args)


if __name__ == "__main__":
    unittest.main()
