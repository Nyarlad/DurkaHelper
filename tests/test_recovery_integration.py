"""Offline contracts for the explicitly authorized synthetic recovery drill."""
import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recovery_test", ROOT / "integration/recovery_smoke.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
IMAGE = "postgres:14.1-alpine@sha256:" + "a" * 64


class DumpProcess:
    def __init__(self, payload, code=0, timed_out=False):
        self.stdout = io.BytesIO(payload)
        self.code = code
        self.timed_out = timed_out
        self.killed = False

    def wait(self, timeout=None):
        if self.timed_out and not self.killed:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return self.code

    def kill(self):
        self.killed = True

    def poll(self):
        return self.code


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # /var on macOS is an ancestor symlink; the public harness requires a
        # canonical, explicitly owned directory, without weakening link checks.
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.original = {"project": "dh-smoke-012345abcdef", "images": {"postgres": IMAGE}}
        self.workspace = self.root / "recovery"

    def args(self, apply=False, action="prepare"):
        return argparse.Namespace(action=action, workspace=str(self.workspace),
            source_workspace=str(self.source), apply=apply, approval_id="qa-approved", snapshot_confirmed=True)

    def prepare(self):
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)):
            recovery.prepare(self.args(True))
        return recovery.fixture(self.workspace)

    def test_prepare_preview_has_no_mutations_or_subprocess(self):
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)), \
             patch.object(recovery.shared, "checked", side_effect=AssertionError("no commands")):
            self.assertEqual(recovery.prepare(self.args())["status"], "NOT_RUN")
        self.assertFalse(self.workspace.exists())

    def test_apply_requires_approval_before_access(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(recovery.main(["run", "--workspace", "unused", "--apply"]), 2)
        self.assertIn("approval", output.getvalue())

    def test_prepared_isolation_and_permissions(self):
        workspace, state = self.prepare()
        spec = recovery.compose_spec(state)
        service = spec["services"]["postgres"]
        self.assertEqual(set(spec["services"]), {"postgres"})
        self.assertTrue(spec["networks"]["recovery"]["internal"])
        self.assertNotIn("ports", service)
        self.assertNotIn("privileged", service)
        self.assertEqual(service["cpus"], 1.0)
        self.assertEqual(service["mem_limit"], "512m")
        self.assertEqual(service["logging"], {"driver": "none"})
        self.assertEqual(service["volumes"], ["./data/postgres:/var/lib/postgresql/data"])
        if os.name == "posix":
            self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
            self.assertEqual((workspace / "fixture.json").stat().st_mode & 0o777, 0o600)

    def test_prepare_refuses_existing_or_inside_source(self):
        self.workspace.mkdir()
        marker = self.workspace / "keep"
        marker.write_text("preserve", encoding="utf-8")
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)):
            with self.assertRaises(recovery.FixtureError):
                recovery.prepare(self.args(True))
            args = self.args(True)
            args.workspace = str(self.source / "nested")
            with self.assertRaises(recovery.FixtureError):
                recovery.prepare(args)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_floating_or_wrong_postgres_version_refused(self):
        for image in ("postgres:latest", "postgres:15@sha256:" + "a" * 64):
            self.original["images"]["postgres"] = image
            with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)):
                with self.assertRaises(recovery.FixtureError):
                    recovery.prepare(self.args(True))

    def test_compose_mutation_fails_closed(self):
        workspace, state = self.prepare()
        spec = recovery.compose_spec(state)
        spec["services"]["postgres"]["ports"] = ["5432:5432"]
        (workspace / "compose.json").write_text(json.dumps(spec), encoding="utf-8")
        with self.assertRaises(recovery.FixtureError):
            recovery.fixture(workspace)

    def test_preview_run_has_no_docker_calls(self):
        self.prepare()
        with patch.object(recovery.shared, "checked", side_effect=AssertionError("no commands")):
            self.assertEqual(recovery.execute(self.args(action="run"))["status"], "NOT_RUN")

    def test_snapshot_gate_precedes_source_start(self):
        workspace, state = self.prepare()
        args = self.args(True, "run")
        args.snapshot_confirmed = False
        with patch.object(recovery.shared, "checked", side_effect=AssertionError("no commands")):
            with self.assertRaises(recovery.FixtureError):
                recovery.drill(args, workspace, state)

    def test_unexpected_source_or_active_project_refused(self):
        workspace, state = self.prepare()
        wrong = dict(self.original, project="dh-smoke-ffffffffffff")
        with patch.object(recovery.shared, "fixture", return_value=(self.source, wrong)), \
             patch.object(recovery.shared, "checked", side_effect=AssertionError("no commands")):
            with self.assertRaises(recovery.FixtureError):
                recovery.drill(self.args(True, "run"), workspace, state)
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)), \
             patch.object(recovery.shared, "checked", return_value=b"existing-container") as checked:
            with self.assertRaises(recovery.FixtureError):
                recovery.drill(self.args(True, "run"), workspace, state)
        self.assertEqual(len(checked.call_args_list), 1)
        self.assertNotIn("up", checked.call_args.args[0])

    def test_nonempty_target_is_never_restored(self):
        workspace, state = self.prepare()
        marker = workspace / "data/postgres/keep"
        marker.write_text("preserve", encoding="utf-8")
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)), \
             patch.object(recovery.shared, "checked", return_value=b"") as checked:
            with self.assertRaises(recovery.FixtureError):
                recovery.drill(self.args(True, "run"), workspace, state)
        self.assertTrue(all("up" not in call.args[0] for call in checked.call_args_list))
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_synthetic_summary_only_returns_counts_and_hash(self):
        row = {"flag": "A" * 31 + "=", "status": "ACCEPTED"}
        with patch.object(recovery, "psql", side_effect=[b"flags", b"1|1|0", json.dumps([row]).encode()]):
            result = recovery.summary([])
        self.assertEqual(set(result), {"tables", "flags", "accepted", "rows_sha256"})
        self.assertNotIn(row["flag"], json.dumps(result))
        self.assertEqual(result["rows_sha256"], hashlib.sha256(recovery.shared.canonical([row])).hexdigest())

    def test_readiness_waits_for_final_tcp_server_not_init_socket(self):
        with patch.object(recovery.shared, "checked", return_value=b"") as checked:
            recovery.ready(["docker"])
        argv = checked.call_args.args[0]
        self.assertEqual(argv[argv.index("-h") + 1], "127.0.0.1")

    def test_query_capture_is_stream_bounded_and_timeout_safe(self):
        with patch.object(recovery.subprocess, "Popen", return_value=DumpProcess(b"1\n")):
            self.assertEqual(recovery.psql(["docker"], "SELECT 1"), b"1")
        for process in (DumpProcess(b"too much data"), DumpProcess(b"1", timed_out=True), DumpProcess(b"", code=1)):
            with patch.object(recovery, "MAX_DUMP", 5), patch.object(recovery.subprocess, "Popen", return_value=process):
                with self.assertRaises(recovery.FixtureError):
                    recovery.psql(["docker"], "SELECT 1")

    def test_unexpected_tables_foreign_data_and_no_accepted_rows_refused(self):
        cases = ([b"users"], [b"flags", b"1|1|1"], [b"flags", b"1|0|0"],
                 [b"flags", b"1001|1|0"], [b"flags", b"invalid"], [b"flags", b"1|1|0", b"[]"])
        for values in cases:
            with self.subTest(values=values), patch.object(recovery, "psql", side_effect=values):
                with self.assertRaises(recovery.FixtureError):
                    recovery.summary([])

    def test_native_dump_bounded_private_hashed_without_overwrite(self):
        destination = self.root / "farm.dump"
        data = b"PGDMP" + b"synthetic" * 20
        process = DumpProcess(data)
        with patch.object(recovery.subprocess, "Popen", return_value=process) as popen:
            result = recovery.dump_database(["docker"], destination)
        self.assertEqual(result, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.assertEqual(destination.read_bytes(), data)
        self.assertIn("--compress=0", popen.call_args.args[0])
        if os.name == "posix":
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        with patch.object(recovery.subprocess, "Popen", side_effect=AssertionError("no overwrite")):
            with self.assertRaises(FileExistsError):
                recovery.dump_database([], destination)

    def test_oversized_dump_retains_bounded_partial_and_kills_cli(self):
        process = DumpProcess(b"PGDMP" + b"a" * 100)
        destination = self.root / "farm.dump"
        with patch.object(recovery.subprocess, "Popen", return_value=process):
            with self.assertRaises(recovery.FixtureError):
                recovery.dump_database([], destination, limit=10)
        self.assertTrue(process.killed)
        self.assertLessEqual(destination.stat().st_size, 10)

    def test_timeout_or_invalid_dump_not_accepted(self):
        for index, process in enumerate((DumpProcess(b"not a dump"), DumpProcess(b"PGDMP", timed_out=True),
                                         DumpProcess(b"PGDMP", code=1))):
            with patch.object(recovery.subprocess, "Popen", return_value=process):
                with self.assertRaises(recovery.FixtureError):
                    recovery.dump_database([], self.root / (str(index) + ".dump"))

    def test_restore_verifies_hash_and_never_clean_or_create(self):
        path = self.root / "farm.dump"
        data = b"PGDMPsynthetic"
        path.write_bytes(data)
        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        with patch.object(recovery.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            recovery.restore_database(["docker"], path, expected)
        argv = run.call_args.args[0]
        self.assertIn("pg_restore", argv)
        self.assertIn("--single-transaction", argv)
        self.assertNotIn("--clean", argv)
        self.assertNotIn("--create", argv)
        path.write_bytes(data + b"tampered")
        with patch.object(recovery.subprocess, "run", side_effect=AssertionError("no restore")):
            with self.assertRaises(recovery.FixtureError):
                recovery.restore_database([], path, expected)

    def test_restore_failure_and_timeout_are_sanitized(self):
        path = self.root / "farm.dump"
        data = b"PGDMPsynthetic"
        path.write_bytes(data)
        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for result in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired("secret", 60)):
            with patch.object(recovery.subprocess, "run", side_effect=result if isinstance(result, Exception) else None,
                              return_value=result):
                with self.assertRaises(recovery.FixtureError) as caught:
                    recovery.restore_database([], path, expected)
            self.assertNotIn("secret", str(caught.exception))

    def run_drill_mocked(self, failure=False, cleanup_fail=False):
        workspace, state = self.prepare()
        summary = {"tables": 1, "flags": 1, "accepted": 1, "rows_sha256": "b" * 64}
        calls = []

        def checked(argv, **kwargs):
            calls.append(argv)
            if "down" in argv and cleanup_fail:
                raise recovery.FixtureError("cleanup failed")
            return b""

        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)), \
             patch.object(recovery.shared, "checked", side_effect=checked), \
             patch.object(recovery, "ready"), patch.object(recovery, "summary", return_value=summary), \
             patch.object(recovery, "dump_database", return_value={"bytes": 6, "sha256": "c" * 64}), \
             patch.object(recovery, "psql", return_value=b"0"), \
             patch.object(recovery, "restore_database", side_effect=recovery.FixtureError("restore failed") if failure else None):
            if failure:
                with self.assertRaises(recovery.FixtureError):
                    recovery.drill(self.args(True, "run"), workspace, state)
                result = recovery.read_json(workspace / "result.json")
            else:
                result = recovery.drill(self.args(True, "run"), workspace, state)
        return workspace, state, result, calls

    def test_success_stops_exact_projects_retains_data_and_is_one_shot(self):
        workspace, state, result, calls = self.run_drill_mocked()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cleanup"], {"source": True, "target": True})
        self.assertTrue(all(result["checks"].values()))
        self.assertTrue((workspace / "data/postgres").exists())
        downs = [argv for argv in calls if "down" in argv]
        self.assertEqual(len(downs), 2)
        self.assertEqual({argv[argv.index("--project-name") + 1] for argv in downs},
                         {state["project"], self.original["project"]})
        self.assertTrue(all("--volumes" not in argv and "-v" not in argv and "prune" not in argv for argv in downs))
        with patch.object(recovery.shared, "fixture", return_value=(self.source, self.original)), \
             patch.object(recovery.shared, "checked", return_value=b"") as checked:
            with self.assertRaises(FileExistsError):
                recovery.drill(self.args(True, "run"), workspace, state)
        self.assertTrue(all("up" not in call.args[0] for call in checked.call_args_list))

    def test_failed_restore_also_stops_both_projects(self):
        _, _, result, calls = self.run_drill_mocked(failure=True)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["cleanup"], {"source": True, "target": True})
        self.assertEqual(len([argv for argv in calls if "down" in argv]), 2)

    def test_cleanup_failure_prevents_pass(self):
        _, _, result, _ = self.run_drill_mocked(cleanup_fail=True)
        self.assertEqual(result["status"], "BLOCKED")

    def test_state_rejects_nonregular_or_oversized_files(self):
        with self.assertRaises(recovery.FixtureError):
            recovery.read_json(self.root)
        path = self.root / "large"
        path.write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaises(recovery.FixtureError):
            recovery.read_json(path)


if __name__ == "__main__":
    unittest.main()
