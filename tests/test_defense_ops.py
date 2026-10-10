"""P0/P1 regression and safety tests for the defense operations CLI."""
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "defense_ops.py"
SPEC = importlib.util.spec_from_file_location("defense_ops_under_test", SCRIPT)
ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ops)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=True), encoding="utf-8")
    return Path(path)


def profile(name="qa-profile", **sections):
    return {"schema": ops.PROFILE_SCHEMA, "name": name, **sections}


def snapshot_document(*, root=None, profile_hash=None, partial=False,
                      files=(), adapters=None):
    profile_hash = profile_hash or "a" * 64
    root = root or "sha256:" + "1" * 64
    adapters = {"platform": {"machine": "test", "system": "Synthetic"}} if adapters is None else adapters
    files = list(files)
    limits = {"max_file_bytes": 1024, "max_files": 32, "max_total_bytes": 4096}
    scope = ops._snapshot_scope({"include": ["*"], "exclude": [], **limits}, adapters)
    return {
        "adapters": adapters,
        "created_at": "2026-01-01T00:00:00Z",
        "files": files,
        "issues": ([{"component": "files", "path": ".", "reason": "synthetic_partial"}]
                   if partial else []),
        "limits": limits,
        "partial": partial,
        "profile": {"name": "qa-profile", "sha256": profile_hash},
        "root": root,
        "schema": ops.SNAPSHOT_SCHEMA,
        "scope": scope,
        "skipped": {},
        "summary": {"files": len(files), "total_bytes": sum(item["size"] for item in files)},
        "tool": {"name": ops.TOOL, "version": ops.VERSION},
    }


def file_record(path, content=b"x", *, mode=0o600, mtime_ns=1):
    import hashlib
    return {"mode": mode, "mtime_ns": mtime_ns, "path": path,
            "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


def event(identifier, timestamp, *, severity="info", summary="Synthetic event."):
    return {"schema": ops.EVENT_SCHEMA, "id": identifier, "timestamp": timestamp,
            "source": "synthetic-test", "kind": "service_health", "severity": severity,
            "summary": summary, "attributes": {"synthetic": True}}


def validation_record(identifier, status="pass", *, timestamp="2026-01-01T00:00:00Z",
                      attributes=None):
    result = {"schema": ops.VALIDATION_SCHEMA, "id": identifier,
              "timestamp": timestamp, "check": "synthetic-check",
              "status": status, "summary": "Synthetic validation result."}
    if attributes is not None:
        result["attributes"] = attributes
    return result


def scanner_scope(**changes):
    body = {
        "schema": ops.SCANNER_SCOPE_SCHEMA,
        "root": "sha256:" + "2" * 64,
        "rules_sha256": "3" * 64,
        "exclude": [],
        "limits": {"max_bytes": 1048576, "max_files": 20000,
                   "max_findings": 10000},
        "path_semantics": ops.SCANNER_PATH_SEMANTICS,
    }
    body.update(changes)
    body["sha256"] = hashlib.sha256(json.dumps(
        {key: body[key] for key in ("schema", "root", "rules_sha256", "exclude",
                                    "limits", "path_semantics")},
        ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return body


@contextmanager
def loopback_server(testcase, handler):
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    except OSError as exc:
        testcase.skipTest(f"loopback sockets are unavailable: {type(exc).__name__}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=1):
                pass
        except OSError as exc:
            testcase.skipTest(f"loopback connections are unavailable: {type(exc).__name__}")
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class QuietHealthHandler(BaseHTTPRequestHandler):
    paths = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        type(self).paths.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/must-not-be-visited")
            body = b"SECRET_REDIRECT_BODY"
        elif self.path == "/large":
            self.send_response(200)
            body = b"x" * 64
        elif self.path == "/missing":
            self.send_response(404)
            body = b"missing"
        else:
            self.send_response(200)
            body = b'{"status":"ok"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OpsTestCase(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="qa-ops-", dir=scratch)
        self.addCleanup(self._temporary.cleanup)
        self.temp = Path(self._temporary.name)

    def path(self, relative):
        path = self.temp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_profile(self, value, name="profile.json"):
        return write_json(self.path(name), value)

    def invoke(self, *argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = ops.main([str(value) for value in argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def invoke_json(self, *argv):
        code, stdout, stderr = self.invoke(*argv)
        payload = json.loads(stdout) if stdout else None
        error = json.loads(stderr) if stderr else None
        return code, payload, error

    def symlink_or_skip(self, link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {type(exc).__name__}")


class ProfileAndPreflightTests(OpsTestCase):
    def test_profile_rejects_unknown_command_and_secret_fields(self):
        cases = (
            {**profile(), "unknown": True},
            profile(snapshot={"adapters": ["platform"], "command": "whoami"}),
            profile(health=[{"name": "local", "url": "http://127.0.0.1:1",
                             "api_token": "synthetic-do-not-use"}]),
        )
        for number, value in enumerate(cases):
            with self.subTest(case=number):
                path = self.write_profile(value, f"profile-{number}.json")
                code, output, error = self.invoke_json("preflight", "--profile", path)
                self.assertEqual(code, 2)
                self.assertIsNone(output)
                self.assertEqual(error["exit_code"], 2)
                self.assertNotIn("synthetic-do-not-use", json.dumps(error))

    def test_preflight_reports_complete_and_partial_statuses(self):
        good = self.write_profile(profile(snapshot={"adapters": ["platform"]}), "good.json")
        code, result, error = self.invoke_json("preflight", "--profile", good)
        self.assertEqual((code, error), (0, None))
        self.assertFalse(result["partial"])
        self.assertTrue(all(check["ok"] for check in result["checks"]))

        partial = self.write_profile(profile(snapshot={"adapters": ["services"]}), "partial.json")
        with patch.object(ops, "_adapter_preflight", return_value=(False, "adapter_tool_missing")):
            code, result, error = self.invoke_json("preflight", "--profile", partial)
        self.assertEqual((code, error), (2, None))
        self.assertTrue(result["partial"])
        self.assertEqual(result["checks"][-1]["reason"], "adapter_tool_missing")

    def test_compose_adapter_requires_explicit_bounded_profile(self):
        invalid_profiles = (
            profile(snapshot={"adapters": ["compose"]}),
            profile(compose={"project": "qa", "files": ["compose.yaml"],
                             "services": ["web"]}),
            profile(snapshot={"adapters": ["compose"]},
                    compose={"project": "Bad Project", "files": ["compose.yaml"],
                             "services": ["web"]}),
            profile(snapshot={"adapters": ["compose"]},
                    compose={"project": "qa", "files": ["../compose.yaml"],
                             "services": ["web"]}),
        )
        for number, value in enumerate(invalid_profiles):
            with self.subTest(number=number):
                path = self.write_profile(value, f"invalid-compose-{number}.json")
                code, result, error = self.invoke_json("preflight", "--profile", path)
                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)

    def test_state_changing_directory_staging_is_blocked_on_windows(self):
        parent = self.path("windows-staging-parent")
        parent.mkdir()
        with patch.object(ops, "DIRECTORY_STAGING_SUPPORTED", False):
            with self.assertRaises(ops.PartialError):
                ops._StagingDirectory.create(parent / "output", ".defense-test-")
            profile_path = self.write_profile(profile(backup={
                "entries": [{"path": "file.txt", "kind": "file"}],
                "exclude": [], "max_files": 4, "max_file_bytes": 4096,
                "max_total_bytes": 16384,
            }), "blocked-staging-profile.json")
            code, result, error = self.invoke_json("preflight", "--profile", profile_path)
        self.assertEqual((code, error), (2, None))
        self.assertTrue(result["partial"])
        self.assertIn("directory-staging", {check["name"] for check in result["checks"]
                                             if not check["ok"]})


@unittest.skipIf(os.name == "nt", "secure directory publication is POSIX-only")
class PublicationSafetyTests(OpsTestCase):
    def publication_tree(self, name="publication-staging"):
        staging = self.path(name)
        staging.mkdir()
        (staging / "payload.txt").write_text("payload\n", encoding="utf-8")
        (staging / "manifest.json").write_text("{}", encoding="utf-8")
        return staging

    def test_staging_creation_rejects_mkdir_open_replacement_without_deleting_it(self):
        parent = self.path("creation-race-parent")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        original_open = ops.os.open
        observed = {}

        def replace_before_open(path, flags, *args, **kwargs):
            dir_fd = kwargs.get("dir_fd")
            if (dir_fd is not None and isinstance(path, str) and
                    path.startswith(".defense-race-") and "replacement" not in observed):
                staging_path = parent / path
                moved = parent / (path + ".moved")
                staging_path.rename(moved)
                staging_path.mkdir(mode=0o700)
                sentinel = staging_path / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["replacement"] = staging_path
                observed["sentinel"] = sentinel
            return original_open(path, flags, *args, **kwargs)

        with patch.object(ops.os, "open", side_effect=replace_before_open):
            with self.assertRaises(ops.DefenseError):
                ops._StagingDirectory.create(target, ".defense-race-")

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertTrue(observed["replacement"].is_dir())
        self.assertFalse(target.exists())

    def test_bound_publication_rejects_target_mkdir_open_replacement(self):
        parent = self.path("target-creation-race")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-target-race-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        displaced = parent / "publisher-created.moved"
        original_open = ops.os.open
        observed = {}

        def replace_before_open(path, flags, *args, **kwargs):
            if (path == target.name and kwargs.get("dir_fd") == staging.parent_fd and
                    "sentinel" not in observed):
                target.rename(displaced)
                target.mkdir(mode=0o700)
                sentinel = target / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["sentinel"] = sentinel
            return original_open(path, flags, *args, **kwargs)

        try:
            with patch.object(ops.os, "open", side_effect=replace_before_open):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertFalse((target / "payload.txt").exists())
        self.assertTrue(displaced.is_dir())

    def test_bound_publication_rollback_preserves_injected_entry(self):
        parent = self.path("rollback-injection")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-rollback-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        original_copy = ops._copy_regular_to_dirfd
        observed = {}

        def inject_after_copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            if "sentinel" not in observed:
                sentinel = target / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["sentinel"] = sentinel
                raise OSError("synthetic failure after competitor injection")
            return result

        try:
            with patch.object(ops, "_copy_regular_to_dirfd", side_effect=inject_after_copy):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertTrue((target / ".INCOMPLETE").is_file())

    def test_bound_publication_rejects_untracked_staging_entry(self):
        parent = self.path("staging-ledger-injection")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-ledger-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        injected = staging.path / "competitor.txt"
        injected.write_text("keep\n", encoding="utf-8")

        try:
            with self.assertRaises(ops.DefenseError):
                ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(injected.read_text(encoding="utf-8"), "keep\n")
        self.assertFalse(target.exists())

    def test_bound_publication_revalidates_nested_target_before_commit(self):
        parent = self.path("nested-target-revalidation")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-nested-")
        staging.mkdir("nested")
        staging.write_new_bytes("nested/payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        original_copy = ops._copy_tree_to_dirfd
        observed = {}

        def replace_nested_file(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            if "replacement" not in observed:
                payload = target / "nested" / "payload.txt"
                payload.unlink()
                payload.write_text("competitor\n", encoding="utf-8")
                observed["replacement"] = payload
            return result

        try:
            with patch.object(ops, "_copy_tree_to_dirfd", side_effect=replace_nested_file):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["replacement"].read_text(encoding="utf-8"),
                         "competitor\n")
        self.assertTrue((target / ".INCOMPLETE").is_file())

    def test_bound_publication_rejects_parent_swap_during_copy(self):
        parent = self.path("late-parent-race")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-late-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        moved_parent = parent.with_name(parent.name + ".moved")
        original_copy = ops._copy_regular_to_dirfd
        observed = {}

        def swap_parent_after_copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            if "sentinel" not in observed:
                parent.rename(moved_parent)
                parent.mkdir(mode=0o700)
                sentinel = parent / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["sentinel"] = sentinel
            return result

        try:
            with patch.object(ops, "_copy_regular_to_dirfd",
                              side_effect=swap_parent_after_copy):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertFalse(target.exists())
        self.assertTrue((moved_parent / target.name / ".INCOMPLETE").is_file())

    def test_bound_publication_rechecks_named_parent_after_final_tree_validation(self):
        parent = self.path("final-validation-parent-race")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-final-race-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        moved_parent = parent.with_name(parent.name + ".moved")
        original_validate = ops._validate_tree_fd
        observed = {}

        def swap_after_final_validation(*args, **kwargs):
            result = original_validate(*args, **kwargs)
            if ("sentinel" not in observed and not staging.path.exists() and
                    (target / ".INCOMPLETE").is_file()):
                parent.rename(moved_parent)
                parent.mkdir(mode=0o700)
                sentinel = parent / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["sentinel"] = sentinel
            return result

        try:
            with patch.object(ops, "_validate_tree_fd",
                              side_effect=swap_after_final_validation):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertTrue((moved_parent / target.name / ".INCOMPLETE").is_file())

    def test_bound_publication_rechecks_named_target_after_final_tree_validation(self):
        parent = self.path("final-validation-target-race")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        displaced = parent / "publisher-created.moved"
        staging = ops._StagingDirectory.create(target, ".defense-final-target-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        original_validate = ops._validate_tree_fd
        observed = {}

        def swap_after_final_validation(*args, **kwargs):
            result = original_validate(*args, **kwargs)
            if ("sentinel" not in observed and not staging.path.exists() and
                    (target / ".INCOMPLETE").is_file()):
                target.rename(displaced)
                target.mkdir(mode=0o700)
                sentinel = target / "competitor.txt"
                sentinel.write_text("keep\n", encoding="utf-8")
                observed["sentinel"] = sentinel
            return result

        try:
            with patch.object(ops, "_validate_tree_fd",
                              side_effect=swap_after_final_validation):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "keep\n")
        self.assertTrue((displaced / ".INCOMPLETE").is_file())

    def test_bound_publication_reconciles_exception_after_marker_unlink(self):
        parent = self.path("marker-unlink-reconciliation")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-commit-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        original_unlink = ops.os.unlink
        interrupted = False

        def unlink_then_interrupt(path, *args, **kwargs):
            nonlocal interrupted
            result = original_unlink(path, *args, **kwargs)
            if path == ".INCOMPLETE" and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("synthetic post-unlink signal")
            return result

        try:
            with patch.object(ops.os, "unlink", side_effect=unlink_then_interrupt):
                result = ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertEqual(result, target)
        self.assertFalse((target / ".INCOMPLETE").exists())
        self.assertEqual((target / "payload.txt").read_text(encoding="utf-8"), "payload\n")

    def test_bound_publication_never_reconciles_partial_copy_as_committed(self):
        parent = self.path("partial-copy-reconciliation")
        parent.mkdir(mode=0o700)
        target = parent / "published"
        staging = ops._StagingDirectory.create(target, ".defense-partial-")
        staging.write_new_bytes("payload.txt", b"payload\n")
        staging.write_new_bytes("manifest.json", b"{}")
        displaced_staging = parent / "staging.moved"
        original_copy = ops._copy_regular_to_dirfd
        original_unlink = ops.os.unlink
        interrupted = False

        def hide_source_and_marker_after_partial_copy(source_directory_fd, name,
                                                      destination_fd, expected_identity):
            nonlocal interrupted
            result = original_copy(source_directory_fd, name, destination_fd,
                                   expected_identity)
            if not interrupted:
                interrupted = True
                staging.path.rename(displaced_staging)
                original_unlink(".INCOMPLETE", dir_fd=destination_fd)
                raise KeyboardInterrupt("synthetic partial-copy interruption")
            return result

        try:
            with patch.object(ops, "_copy_regular_to_dirfd",
                              side_effect=hide_source_and_marker_after_partial_copy):
                with self.assertRaises(ops.DefenseError):
                    ops._publish_directory(staging, target)
        finally:
            staging.cleanup()

        self.assertTrue((target / ".INCOMPLETE").is_file())
        self.assertTrue(displaced_staging.is_dir())

    def test_directory_publication_uses_incomplete_marker_and_manifest_last(self):
        staging = self.publication_tree()
        target = self.path("published")
        copied = []
        real_copy = ops._copy_regular_to_dirfd

        def observe_copy(source_directory_fd, name, destination_fd, expected_identity):
            if os.name != "nt":
                self.assertTrue((target / ".INCOMPLETE").is_file())
            copied.append(name)
            return real_copy(source_directory_fd, name, destination_fd, expected_identity)

        manager = (patch.object(ops, "_copy_regular_to_dirfd", side_effect=observe_copy)
                   if os.name != "nt" else nullcontext())
        with manager:
            result = ops._publish_directory(staging, target)

        self.assertEqual(result, target)
        if os.name != "nt":
            self.assertEqual(copied, ["payload.txt", "manifest.json"])
        self.assertFalse((target / ".INCOMPLETE").exists())
        self.assertEqual((target / "payload.txt").read_text(encoding="utf-8"), "payload\n")
        self.assertFalse(staging.exists())

    def test_directory_publication_race_never_deletes_or_overwrites_competitor(self):
        staging = self.publication_tree()
        target = self.path("raced-target")
        if os.name == "nt":
            def competing_rename(_source, destination):
                Path(destination).mkdir()
                (Path(destination) / "competitor.txt").write_text("keep\n", encoding="utf-8")
                raise FileExistsError("synthetic publication race")
            manager = patch.object(ops.os, "rename", side_effect=competing_rename)
        else:
            real_mkdir = ops.os.mkdir

            def competing_mkdir(name, mode=0o777, *, dir_fd=None):
                real_mkdir(name, mode, dir_fd=dir_fd)
                if name == target.name and dir_fd is not None:
                    (target / "competitor.txt").write_text("keep\n", encoding="utf-8")
                    raise FileExistsError("synthetic publication race")
            manager = patch.object(ops.os, "mkdir", side_effect=competing_mkdir)

        with manager:
            with self.assertRaises(ops.DefenseError):
                ops._publish_directory(staging, target)

        self.assertEqual((target / "competitor.txt").read_text(encoding="utf-8"), "keep\n")
        self.assertFalse((target / ".INCOMPLETE").exists())
        self.assertTrue(staging.exists())

    def test_failed_owned_publication_is_not_left_looking_complete(self):
        staging = self.publication_tree()
        target = self.path("failed-target")

        manager = (patch.object(ops.os, "rename", side_effect=OSError("synthetic rename failure"))
                   if os.name == "nt" else
                   patch.object(ops, "_copy_regular_to_dirfd",
                                side_effect=OSError("synthetic copy failure")))
        with manager:
            with self.assertRaises(ops.DefenseError):
                ops._publish_directory(staging, target)

        self.assertTrue((target / ".INCOMPLETE").is_file())
        self.assertTrue(staging.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX dirfd publication required")
    def test_directory_publication_target_swap_never_writes_to_replacement(self):
        staging = self.publication_tree("swap-staging")
        target = self.path("swap-target")
        displaced = self.path("displaced-owned-target")
        real_copy = ops._copy_regular_to_dirfd
        swapped = False

        def swap_then_copy(source_directory_fd, name, destination_fd, expected_identity):
            nonlocal swapped
            if not swapped:
                target.rename(displaced)
                target.mkdir()
                (target / "competitor.txt").write_text("keep\n", encoding="utf-8")
                swapped = True
            return real_copy(source_directory_fd, name, destination_fd, expected_identity)

        with patch.object(ops, "_copy_regular_to_dirfd", side_effect=swap_then_copy):
            with self.assertRaises(ops.DefenseError):
                ops._publish_directory(staging, target)

        self.assertEqual((target / "competitor.txt").read_text(encoding="utf-8"), "keep\n")
        self.assertFalse((target / "payload.txt").exists())


class SnapshotAndComparisonTests(OpsTestCase):
    def snapshot_profile(self, **changes):
        settings = {"adapters": ["platform"], "include": ["*.txt"], "exclude": ["skip*"],
                    "max_files": 32, "max_file_bytes": 4096, "max_total_bytes": 16384}
        settings.update(changes)
        return self.write_profile(profile(snapshot=settings))

    def take_snapshot(self, profile_path, root, output, now="2026-01-01T00:00:00Z"):
        with patch.object(ops, "_now", return_value=now), \
             patch.object(ops, "_adapter_platform", return_value={
                 "machine": "test", "python": "3.11.0", "release": "test", "system": "Synthetic"
             }):
            code, summary, error = self.invoke_json(
                "snapshot", "--profile", profile_path, "--root", root, "--output", output
            )
        return code, summary, error, json.loads(Path(output).read_text(encoding="utf-8")) if Path(output).exists() else None

    def test_snapshot_is_deterministic_bounded_and_scoped(self):
        root = self.path("service")
        root.mkdir()
        (root / "keep.txt").write_text("stable\n", encoding="utf-8")
        (root / "skip-this.txt").write_text("excluded\n", encoding="utf-8")
        (root / ".env").write_text("NOT_A_REAL_SECRET=synthetic\n", encoding="utf-8")
        (root / ".ssh").mkdir()
        (root / ".ssh" / "synthetic-key.txt").write_text("not bundled\n", encoding="utf-8")
        profile_path = self.snapshot_profile()
        first = self.path("first.json")
        second = self.path("second.json")

        one = self.take_snapshot(profile_path, root, first)
        two = self.take_snapshot(profile_path, root, second)

        self.assertEqual(one[:3], (0, one[1], None))
        self.assertEqual(two[:3], (0, two[1], None))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        document = one[3]
        self.assertEqual(document["schema"], ops.SNAPSHOT_SCHEMA)
        self.assertEqual([item["path"] for item in document["files"]], ["keep.txt"])
        self.assertFalse(document["partial"])
        self.assertEqual(document["issues"], [])
        self.assertGreaterEqual(document["skipped"].get("excluded", 0), 1)
        self.assertGreaterEqual(document["skipped"].get("excluded_directory", 0), 1)

    def test_snapshot_refuses_to_publish_oversized_serialization(self):
        root = self.path("oversized-snapshot-root")
        root.mkdir()
        (root / "keep.txt").write_text("stable\n", encoding="utf-8")
        profile_path = self.snapshot_profile()
        output = self.path("oversized-snapshot.json")

        with patch.object(ops, "MAX_JSON_BYTES", 64):
            code, result, error = self.invoke_json(
                "snapshot", "--profile", profile_path, "--root", root, "--output", output
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_explicit_compose_inventory_hashes_config_and_sanitizes_runtime_state(self):
        root = self.path("compose-root")
        root.mkdir()
        compose_file = root / "compose.yaml"
        compose_file.write_text("services:\n  web:\n    image: synthetic.invalid/web@sha256:" +
                                "a" * 64 + "\n", encoding="utf-8")
        value = profile(
            snapshot={"adapters": ["compose"], "include": ["*.yaml"], "exclude": [],
                      "max_files": 8, "max_file_bytes": 4096,
                      "max_total_bytes": 16384},
            compose={"project": "qa-project", "files": ["compose.yaml"],
                     "services": ["cache", "web", "worker"]},
        )
        profile_path = self.write_profile(value, "compose-profile.json")
        output = self.path("compose-snapshot.json")
        runtime = ("web\trunning\tUp 2 minutes (healthy)\n"
                   "worker\texited\tExited (1) 3 seconds ago\n")

        with patch.object(ops, "_docker_executable", return_value=sys.executable), \
             patch.object(ops, "_run_platform_command", return_value=runtime):
            code, summary, error = self.invoke_json(
                "snapshot", "--profile", profile_path, "--root", root, "--output", output
            )

        self.assertEqual((code, error), (0, None))
        self.assertFalse(summary["partial"])
        document = json.loads(output.read_text(encoding="utf-8"))
        compose = document["adapters"]["compose"]
        self.assertEqual(compose["config_files"][0]["path"], "compose.yaml")
        self.assertEqual(compose["config_files"][0]["sha256"],
                         hashlib.sha256(compose_file.read_bytes()).hexdigest())
        self.assertRegex(compose["project_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(compose["services"], [
            {"count": 0, "health": "none", "service": "cache", "state": "missing"},
            {"count": 1, "health": "healthy", "service": "web", "state": "running"},
            {"count": 1, "health": "none", "service": "worker", "state": "exited"},
        ])
        serialized = json.dumps(document)
        self.assertNotIn("Up 2 minutes", serialized)
        self.assertNotIn("Exited (1)", serialized)

    def test_compose_malformed_runtime_output_is_partial_not_clean(self):
        root = self.path("compose-partial-root")
        root.mkdir()
        (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
        profile_path = self.write_profile(profile(
            snapshot={"adapters": ["compose"]},
            compose={"project": "qa-project", "files": ["compose.yaml"],
                     "services": ["web"]},
        ), "compose-partial-profile.json")
        output = self.path("compose-partial.json")

        with patch.object(ops, "_docker_executable", return_value=sys.executable), \
             patch.object(ops, "_run_platform_command", return_value="malformed\n"):
            code, result, error = self.invoke_json(
                "snapshot", "--profile", profile_path, "--root", root, "--output", output
            )

        self.assertEqual((code, error), (2, None))
        self.assertTrue(result["partial"])
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(document["partial"])
        self.assertIn("observation_partial", {issue["reason"] for issue in document["issues"]})

    def test_snapshot_validates_generated_artifact_before_publication(self):
        root = self.path("invalid-produced-snapshot-root")
        root.mkdir()
        (root / "keep.txt").write_text("stable\n", encoding="utf-8")
        output = self.path("invalid-produced-snapshot.json")

        with patch.object(ops, "_now", return_value="not-a-timestamp"):
            code, result, error = self.invoke_json(
                "snapshot", "--profile", self.snapshot_profile(exclude=[]),
                "--root", root, "--output", output,
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_compare_detects_add_change_and_delete(self):
        root = self.path("service")
        root.mkdir()
        (root / "content.txt").write_text("before", encoding="utf-8")
        (root / "deleted.txt").write_text("remove", encoding="utf-8")
        profile_path = self.snapshot_profile(exclude=[])
        before = self.path("before.json")
        after = self.path("after.json")
        self.assertEqual(self.take_snapshot(profile_path, root, before)[0], 0)

        (root / "content.txt").write_text("after!", encoding="utf-8")
        (root / "deleted.txt").unlink()
        (root / "added.txt").write_text("new", encoding="utf-8")
        self.assertEqual(self.take_snapshot(profile_path, root, after, "2026-01-01T00:01:00Z")[0], 0)

        code, result, error = self.invoke_json("compare", before, after)
        self.assertEqual((code, error), (1, None))
        self.assertTrue(result["comparable"])
        self.assertEqual(result["drift"]["files_added"], ["added.txt"])
        self.assertEqual(result["drift"]["files_content_changed"], ["content.txt"])
        self.assertEqual(result["drift"]["files_removed"], ["deleted.txt"])

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits required")
    def test_compare_detects_mode_only_drift(self):
        root = self.path("mode-service")
        root.mkdir()
        source = root / "mode.txt"
        source.write_text("same", encoding="utf-8")
        source.chmod(0o600)
        profile_path = self.snapshot_profile(exclude=[])
        before = self.path("mode-before.json")
        after = self.path("mode-after.json")
        self.take_snapshot(profile_path, root, before)
        source.chmod(0o644)
        self.take_snapshot(profile_path, root, after)
        code, result, _error = self.invoke_json("compare", before, after)
        self.assertEqual(code, 1)
        self.assertEqual(result["drift"]["files_metadata_changed"], ["mode.txt"])
        self.assertEqual(result["drift"]["files_content_changed"], [])

    def test_incomparable_profile_root_and_partial_snapshots_exit_two(self):
        baseline = snapshot_document()
        changed_scope = copy.deepcopy(baseline)
        changed_scope["scope"] = ops._snapshot_scope({
            "include": ["*.json"], "exclude": [],
            "max_file_bytes": 1024, "max_files": 32, "max_total_bytes": 4096,
        }, ["platform"])
        cases = (
            (changed_scope, "snapshot_scope_changed"),
            (snapshot_document(root="sha256:" + "2" * 64), "root_changed"),
            (snapshot_document(partial=True), "current_partial"),
        )
        baseline_path = write_json(self.path("baseline.json"), baseline)
        comparable_path = write_json(self.path("comparable.json"), copy.deepcopy(baseline))
        code, result, error = self.invoke_json("compare", baseline_path, comparable_path)
        self.assertEqual((code, error), (0, None))
        self.assertTrue(result["comparable"])
        self.assertEqual(result["summary"]["drift_count"], 0)
        for number, (current, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                current_path = write_json(self.path(f"current-{number}.json"), current)
                code, result, error = self.invoke_json("compare", baseline_path, current_path)
                self.assertEqual((code, error), (2, None))
                self.assertFalse(result["comparable"])
                self.assertTrue(result["partial"])
                self.assertIn(reason, result["reasons"])

    def test_adapter_failure_makes_snapshot_partial_not_clean(self):
        root = self.path("adapter-root")
        root.mkdir()
        (root / "file.txt").write_text("data", encoding="utf-8")
        profile_path = self.write_profile(profile(snapshot={"adapters": ["processes"],
                                                            "include": ["*.txt"]}))
        output = self.path("adapter.json")
        with patch.object(ops, "_processes_adapter",
                          side_effect=ops.PartialError("adapter_execution_failed")):
            code, summary, error = self.invoke_json(
                "snapshot", "--profile", profile_path, "--root", root, "--output", output
            )
        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(document["partial"])
        self.assertIsNone(document["adapters"]["processes"])
        self.assertEqual(document["issues"][0]["reason"], "adapter_execution_failed")

    def test_included_symlink_makes_snapshot_partial_not_clean(self):
        root = self.path("symlink-snapshot-root")
        root.mkdir()
        target = root / "target.txt"
        target.write_text("safe\n", encoding="utf-8")
        self.symlink_or_skip(root / "linked.txt", target)
        output = self.path("symlink-snapshot.json")

        code, summary, error, document = self.take_snapshot(
            self.snapshot_profile(exclude=[]), root, output
        )

        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        self.assertTrue(document["partial"])
        self.assertIn("included_symlink", {item["reason"] for item in document["issues"]})
        self.assertNotIn("linked.txt", {item["path"] for item in document["files"]})

    def test_symlinked_directory_that_can_hide_included_descendants_is_partial(self):
        root = self.path("symlink-directory-snapshot-root")
        root.mkdir()
        target = self.path("symlink-directory-target")
        target.mkdir()
        (target / "hidden.json").write_text("{}\n", encoding="utf-8")
        self.symlink_or_skip(root / "sub", target, directory=True)
        output = self.path("symlink-directory-snapshot.json")

        code, summary, error, document = self.take_snapshot(
            self.snapshot_profile(include=["sub/*.json"], exclude=[]), root, output
        )

        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        self.assertEqual(document["files"], [])
        self.assertIn({"component": "files", "path": "sub", "reason": "included_symlink"},
                      document["issues"])

    def test_snapshot_rejects_symlink_supplied_as_root(self):
        target = self.path("snapshot-root-target")
        target.mkdir()
        alias = self.path("snapshot-root-alias")
        self.symlink_or_skip(alias, target, directory=True)
        output = self.path("snapshot-root-symlink.json")

        code, result, error = self.invoke_json(
            "snapshot", "--profile", self.snapshot_profile(), "--root", alias,
            "--output", output,
        )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_snapshot_accepts_regular_root_below_symlinked_ancestor(self):
        real_parent = self.path("snapshot-ancestor-real")
        root = real_parent / "service"
        root.mkdir(parents=True)
        (root / "keep.txt").write_text("stable\n", encoding="utf-8")
        alias_parent = self.path("snapshot-ancestor-alias")
        self.symlink_or_skip(alias_parent, real_parent, directory=True)
        output = self.path("snapshot-ancestor.json")

        code, summary, error, document = self.take_snapshot(
            self.snapshot_profile(exclude=[]), alias_parent / "service", output
        )

        self.assertEqual((code, error), (0, None))
        self.assertFalse(summary["partial"])
        self.assertEqual([item["path"] for item in document["files"]], ["keep.txt"])

    def test_snapshot_root_leaf_swap_during_canonicalization_is_rejected(self):
        root = self.path("snapshot-root-race")
        root.mkdir()
        regular = root.lstat()
        symlink = type("SymlinkMetadata", (), {
            "st_dev": regular.st_dev,
            "st_ino": regular.st_ino,
            "st_mode": stat.S_IFLNK | 0o777,
        })()

        with patch.object(Path, "lstat", side_effect=[regular, symlink]):
            with self.assertRaisesRegex(ops.DefenseError, "symlink"):
                ops._canonical_root_directory(root)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_included_special_file_makes_snapshot_partial_not_clean(self):
        root = self.path("special-snapshot-root")
        root.mkdir()
        os.mkfifo(root / "pipe.txt")
        output = self.path("special-snapshot.json")

        code, summary, error, document = self.take_snapshot(
            self.snapshot_profile(exclude=[]), root, output
        )

        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        self.assertIn("included_special", {item["reason"] for item in document["issues"]})

    def test_nonportable_filename_makes_snapshot_partial_not_clean(self):
        root = self.path("nonportable-snapshot-root")
        root.mkdir()
        nonportable = root / "bad|name.txt"
        try:
            nonportable.write_text("synthetic\n", encoding="utf-8")
        except OSError as exc:
            self.skipTest(f"filesystem forbids the nonportable fixture: {type(exc).__name__}")
        output = self.path("nonportable-snapshot.json")

        code, summary, error, document = self.take_snapshot(
            self.snapshot_profile(exclude=[]), root, output
        )

        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        issue = next(item for item in document["issues"] if item["reason"] == "nonportable_path")
        self.assertRegex(issue["path"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("bad|name.txt", json.dumps(document))

    def test_synthetic_special_and_nonportable_observations_cannot_be_false_clean(self):
        root = self.path("synthetic-unportable-root")
        root.mkdir()
        opaque_path = "sha256:" + "b" * 64
        observations = [
            ("skip", root / "pipe.txt", "special"),
            ("nonportable", root / "unrepresentable.txt", opaque_path),
        ]
        output = self.path("synthetic-unportable-snapshot.json")
        profile_path = self.snapshot_profile(exclude=[])

        with patch.object(ops, "_bounded_walk", return_value=observations):
            code, summary, error, document = self.take_snapshot(profile_path, root, output)

        self.assertEqual((code, error), (2, None))
        self.assertTrue(summary["partial"])
        self.assertTrue(document["partial"])
        reasons = {item["reason"] for item in document["issues"]}
        self.assertEqual(reasons, {"included_special", "nonportable_path"})
        self.assertEqual(document["skipped"]["special"], 1)
        self.assertEqual(document["skipped"]["nonportable_path"], 1)

    def test_health_only_profile_change_keeps_scope_but_blocks_comparison(self):
        root = self.path("scope-root")
        root.mkdir()
        (root / "file.txt").write_text("stable\n", encoding="utf-8")
        settings = {"adapters": ["platform"], "include": ["*.txt"], "exclude": [],
                    "max_files": 32, "max_file_bytes": 4096, "max_total_bytes": 16384}
        first_profile = self.write_profile(profile(
            snapshot=settings,
            health=[{"name": "first", "url": "http://127.0.0.1:1"}],
        ), "scope-first-profile.json")
        second_profile = self.write_profile(profile(
            snapshot=settings,
            health=[{"name": "second", "url": "http://127.0.0.1:2"}],
        ), "scope-second-profile.json")
        before = self.path("scope-before.json")
        after = self.path("scope-after.json")
        self.assertEqual(self.take_snapshot(first_profile, root, before)[0], 0)
        self.assertEqual(self.take_snapshot(second_profile, root, after)[0], 0)

        code, result, error = self.invoke_json("compare", before, after)

        self.assertEqual((code, error), (2, None))
        self.assertFalse(result["comparable"])
        self.assertIn("profile_changed", result["reasons"])
        self.assertEqual(result["summary"]["drift_count"], 0)
        first = json.loads(before.read_text(encoding="utf-8"))
        second = json.loads(after.read_text(encoding="utf-8"))
        self.assertNotEqual(first["profile"]["sha256"], second["profile"]["sha256"])
        self.assertEqual(first["scope"]["sha256"], second["scope"]["sha256"])

    def test_compare_rejects_unknown_scope_semantics_and_tool_major_incompatibility(self):
        root = self.path("compatibility-root")
        root.mkdir()
        (root / "file.txt").write_text("stable\n", encoding="utf-8")
        profile_path = self.snapshot_profile(exclude=[])
        baseline_path = self.path("compatibility-baseline.json")
        self.assertEqual(self.take_snapshot(profile_path, root, baseline_path)[0], 0)
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

        semantic = copy.deepcopy(baseline)
        semantic["scope"]["adapter_semantics"]["platform"] = "platform-observation-v999"
        payload = {key: semantic["scope"][key] for key in
                   ("adapter_config", "adapter_semantics", "files", "schema",
                    "tool_compatibility")}
        semantic["scope"]["sha256"] = ops._sha256_bytes(ops._canonical(payload))
        semantic_path = write_json(self.path("compatibility-semantic.json"), semantic)
        code, result, error = self.invoke_json("compare", baseline_path, semantic_path)
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)

        equally_corrupt = write_json(self.path("compatibility-semantic-before.json"), semantic)
        code, result, error = self.invoke_json("compare", equally_corrupt, semantic_path)
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)

        missing_scope = copy.deepcopy(baseline)
        missing_scope.pop("scope")
        missing_before = write_json(self.path("compatibility-no-scope-before.json"), missing_scope)
        missing_after = write_json(self.path("compatibility-no-scope-after.json"), missing_scope)
        code, result, error = self.invoke_json("compare", missing_before, missing_after)
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)

        incompatible = copy.deepcopy(baseline)
        incompatible["tool"]["version"] = f"{int(ops.VERSION.split('.', 1)[0]) + 1}.0.0"
        incompatible_path = write_json(self.path("compatibility-tool.json"), incompatible)
        code, result, error = self.invoke_json("compare", baseline_path, incompatible_path)
        self.assertEqual((code, error), (2, None))
        self.assertIn("tool_incompatible", result["reasons"])

    def test_process_pid_churn_is_ignored_but_semantic_change_is_drift(self):
        before = snapshot_document(adapters={"processes": [
            {"name": "synthetic-daemon", "pid": 101, "ppid": 1, "uid": 1000}
        ]})
        pid_only = snapshot_document(adapters={"processes": [
            {"name": "synthetic-daemon", "pid": 902, "ppid": 800, "uid": 1000}
        ]})
        semantic = snapshot_document(adapters={"processes": [
            {"name": "synthetic-daemon-v2", "pid": 902, "ppid": 800, "uid": 1000}
        ]})
        baseline_path = write_json(self.path("pid-baseline.json"), before)
        pid_path = write_json(self.path("pid-only.json"), pid_only)
        semantic_path = write_json(self.path("pid-semantic.json"), semantic)

        code, result, error = self.invoke_json("compare", baseline_path, pid_path)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["summary"]["drift_count"], 0)

        code, result, error = self.invoke_json("compare", baseline_path, semantic_path)
        self.assertEqual((code, error), (1, None))
        self.assertEqual(result["drift"]["adapters_changed"], ["processes"])


@unittest.skipIf(os.name == "nt", "secure backup/restore directory staging is POSIX-only")
class BackupAndRestoreTests(OpsTestCase):
    def backup_profile(self, entries, name="profile.json", **limits):
        settings = {"entries": entries, "exclude": [], "max_files": 32,
                    "max_file_bytes": 4096, "max_total_bytes": 16384}
        settings.update(limits)
        return self.write_profile(profile(backup=settings), name)

    def create_backup(self, root, profile_path=None, name="backup"):
        if profile_path is None:
            profile_path = self.backup_profile([{"path": ".", "kind": "tree"}])
        output = self.path(name)
        code, result, error = self.invoke_json(
            "backup", "create", "--profile", profile_path, "--root", root, "--output", output
        )
        return code, result, error, output

    def rewrite_manifest(self, backup, mutate):
        manifest_path = Path(backup) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutate(manifest)
        manifest["bundle_sha256"] = ops._manifest_bundle_hash(manifest["entries"])
        manifest["summary"] = {
            "files": len(manifest["entries"]),
            "total_bytes": sum(entry["size"] for entry in manifest["entries"]
                           if type(entry.get("size")) is int),
        }
        write_json(manifest_path, manifest)
        return manifest

    def test_backup_verify_restore_roundtrip_and_approval_gate(self):
        root = self.path("source")
        (root / "nested").mkdir(parents=True)
        (root / "config.json").write_text('{"enabled":true}\n', encoding="utf-8")
        (root / "nested" / "data.txt").write_text("synthetic data\n", encoding="utf-8")
        code, created, error, backup = self.create_backup(root)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(created["files"], 2)

        code, verified, error = self.invoke_json("backup", "verify", backup)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(verified["summary"]["problems"], 0)
        manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        self.assertRegex(manifest["bundle_sha256"], r"^[0-9a-f]{64}$")

        target = self.path("restore-target")
        code, dry_run, error = self.invoke_json("restore-stage", backup, "--target", target)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(dry_run["status"], "safe_to_stage")
        self.assertFalse(target.exists(), "dry-run must not create the target")

        for approval in (None, "approved"):
            argv = ["restore-stage", backup, "--target", target, "--apply"]
            if approval is not None:
                argv += ["--approval-id", approval]
            code, result, error = self.invoke_json(*argv)
            self.assertEqual(code, 2)
            self.assertIsNone(result)
            self.assertEqual(error["exit_code"], 2)
            self.assertFalse(target.exists())

        code, staged, error = self.invoke_json(
            "restore-stage", backup, "--target", target, "--apply",
            "--approval-id", "change-12345678"
        )
        self.assertEqual((code, error), (0, None))
        self.assertEqual(staged["status"], "staged")
        self.assertEqual((target / "config.json").read_bytes(), (root / "config.json").read_bytes())
        self.assertEqual((target / "nested" / "data.txt").read_bytes(),
                         (root / "nested" / "data.txt").read_bytes())

        original = (target / "config.json").read_bytes()
        code, result, error = self.invoke_json(
            "restore-stage", backup, "--target", target, "--apply",
            "--approval-id", "change-87654321"
        )
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual((target / "config.json").read_bytes(), original)

    def test_backup_tamper_and_unexpected_entries_are_reported(self):
        for case in ("tamper", "unexpected-file", "unexpected-directory"):
            with self.subTest(case=case):
                root = self.path(f"source-{case}")
                root.mkdir()
                (root / "file.txt").write_text("original", encoding="utf-8")
                code, _result, _error, backup = self.create_backup(root, name=f"backup-{case}")
                self.assertEqual(code, 0)
                if case == "tamper":
                    (backup / "files" / "000001.bin").write_text("tampered", encoding="utf-8")
                elif case == "unexpected-file":
                    (backup / "files" / "extra.bin").write_bytes(b"extra")
                else:
                    (backup / "files" / "extra").mkdir()
                code, result, error = self.invoke_json("backup", "verify", backup)
                self.assertEqual((code, error), (1, None))
                self.assertGreater(result["summary"]["problems"], 0)
                target = self.path(f"restore-{case}")
                code, result, error = self.invoke_json("restore-stage", backup, "--target", target)
                self.assertEqual((code, error), (1, None))
                self.assertFalse(target.exists())

    def test_backup_manifest_traversal_is_rejected(self):
        root = self.path("traversal-source")
        root.mkdir()
        (root / "file.txt").write_text("safe", encoding="utf-8")
        self.assertEqual(self.create_backup(root, name="traversal-backup")[0], 0)
        backup = self.path("traversal-backup")
        manifest_path = backup / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["entries"][0]["source"] = "../escape.txt"
        write_json(manifest_path, manifest)
        code, result, error = self.invoke_json("backup", "verify", backup)
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        target = self.path("must-not-exist")
        code, result, error = self.invoke_json("restore-stage", backup, "--target", target,
                                               "--apply", "--approval-id", "change-12345678")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(target.exists())
        self.assertFalse((self.temp / "escape.txt").exists())

    def test_backup_source_symlink_is_rejected(self):
        root = self.path("symlink-source")
        root.mkdir()
        target = root / "target.txt"
        target.write_text("safe", encoding="utf-8")
        self.symlink_or_skip(root / "linked.txt", target)
        code, result, error, output = self.create_backup(root, name="symlink-backup")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_backup_special_file_is_rejected(self):
        root = self.path("special-source")
        root.mkdir()
        os.mkfifo(root / "pipe")
        code, result, error, output = self.create_backup(root, name="special-backup")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_backup_limits_and_unstable_source_leave_no_output(self):
        root = self.path("limited-source")
        root.mkdir()
        (root / "one.txt").write_bytes(b"1234")
        (root / "two.txt").write_bytes(b"5678")
        profiles = (
            self.backup_profile([{"path": ".", "kind": "tree"}],
                                max_file_bytes=3, name="limit-file.json"),
            self.backup_profile([{"path": ".", "kind": "tree"}],
                                max_total_bytes=4, name="limit-total.json"),
            self.backup_profile([{"path": ".", "kind": "tree"}],
                                max_files=1, name="limit-count.json"),
        )
        for number, profile_path in enumerate(profiles):
            with self.subTest(number=number):
                code, result, error, output = self.create_backup(
                    root, profile_path, f"limited-backup-{number}"
                )
                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)
                self.assertFalse(output.exists())

        normal = self.backup_profile([{"path": ".", "kind": "tree"}], name="unstable.json")
        with patch.object(ops, "_copy_stable",
                          side_effect=ops.PartialError("backup source changed while reading")):
            code, result, error, output = self.create_backup(root, normal, "unstable-backup")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertFalse(output.exists())

    def test_backup_and_restore_never_overwrite_existing_targets(self):
        root = self.path("overwrite-source")
        root.mkdir()
        (root / "file.txt").write_text("safe", encoding="utf-8")
        profile_path = self.backup_profile([{"path": ".", "kind": "tree"}])
        output = self.path("existing-output")
        output.mkdir()
        marker = output / "marker"
        marker.write_text("keep", encoding="utf-8")
        code, result, error = self.invoke_json(
            "backup", "create", "--profile", profile_path, "--root", root, "--output", output
        )
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-anchored staging required")
    def test_backup_restore_and_evidence_reject_staging_source_and_parent_swaps(self):
        for command in ("backup", "restore", "evidence"):
            for attack in ("source", "parent"):
                with self.subTest(command=command, attack=attack):
                    suffix = f"{command}-{attack}"
                    output_parent = self.path(f"staging-race-{suffix}")
                    # Publication intentionally rejects group/world-writable
                    # parents.  Do not let a permissive POSIX login umask make
                    # this race regression exit before the injected swap.
                    output_parent.mkdir(mode=0o700)
                    output = output_parent / "published"

                    if command == "backup":
                        root = self.path(f"staging-source-{suffix}")
                        root.mkdir()
                        (root / "file.txt").write_text("safe\n", encoding="utf-8")
                        profile_path = self.backup_profile(
                            [{"path": ".", "kind": "tree"}],
                            name=f"staging-profile-{suffix}.json",
                        )
                        invoke = lambda: self.invoke_json(
                            "backup", "create", "--profile", profile_path,
                            "--root", root, "--output", output,
                        )
                    elif command == "evidence":
                        profile_path = self.write_profile(profile(evidence={
                            "allow_extensions": [".json"], "max_files": 4,
                            "max_file_bytes": 4096, "max_total_bytes": 16384,
                        }), f"staging-profile-{suffix}.json")
                        event_path = write_json(
                            self.path(f"staging-event-{suffix}.json"),
                            event(f"event-{suffix}", "2026-01-01T00:00:00Z"),
                        )
                        invoke = lambda: self.invoke_json(
                            "evidence", "--profile", profile_path,
                            "--output", output, "--input", event_path,
                        )
                    else:
                        root = self.path(f"staging-source-{suffix}")
                        root.mkdir()
                        (root / "file.txt").write_text("safe\n", encoding="utf-8")
                        backup_profile = self.backup_profile(
                            [{"path": ".", "kind": "tree"}],
                            name=f"staging-backup-profile-{suffix}.json",
                        )
                        code, _result, error, backup = self.create_backup(
                            root, backup_profile, f"staging-backup-{suffix}"
                        )
                        self.assertEqual((code, error), (0, None))
                        invoke = lambda: self.invoke_json(
                            "restore-stage", backup, "--target", output, "--apply",
                            "--approval-id", f"staging-race-{suffix}-1234",
                        )

                    original_publish = ops._publish_directory
                    observed = {}

                    def swap_then_publish(staging, target):
                        self.assertIsInstance(staging, ops._StagingDirectory)
                        if attack == "source":
                            moved = staging.path.with_name(staging.path.name + ".moved")
                            staging.path.rename(moved)
                            staging.path.mkdir(mode=0o700)
                            sentinel = staging.path / "competitor.txt"
                        else:
                            parent = staging.path.parent
                            moved = parent.with_name(parent.name + ".moved")
                            parent.rename(moved)
                            parent.mkdir(mode=0o700)
                            sentinel = parent / "competitor.txt"
                        sentinel.write_text("keep\n", encoding="utf-8")
                        observed["sentinel"] = sentinel
                        return original_publish(staging, target)

                    with patch.object(ops, "_publish_directory", side_effect=swap_then_publish):
                        code, result, error = invoke()

                    self.assertEqual(code, 2)
                    self.assertIsNone(result)
                    self.assertEqual(error["exit_code"], 2)
                    self.assertFalse(output.exists())
                    self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"),
                                     "keep\n")

    def test_backup_source_set_identity_barrier_catches_multi_file_churn(self):
        root = self.path("identity-barrier-source")
        root.mkdir()
        first = root / "a.txt"
        second = root / "b.txt"
        first.write_text("first\n", encoding="utf-8")
        second.write_text("second\n", encoding="utf-8")
        profile_path = self.backup_profile([{"path": ".", "kind": "tree"}],
                                           name="identity-barrier-profile.json")
        original_copy = ops._copy_stable
        copied = 0

        def churn_after_last_copy(*args, **kwargs):
            nonlocal copied
            result = original_copy(*args, **kwargs)
            copied += 1
            if copied == 2:
                first.write_text("changed after its copy\n", encoding="utf-8")
            return result

        with patch.object(ops, "_copy_stable", side_effect=churn_after_last_copy):
            code, result, error, output = self.create_backup(
                root, profile_path, "identity-barrier-backup"
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_backup_second_membership_pass_catches_added_file(self):
        root = self.path("membership-barrier-source")
        root.mkdir()
        (root / "a.txt").write_text("first\n", encoding="utf-8")
        profile_path = self.backup_profile([{"path": ".", "kind": "tree"}],
                                           name="membership-barrier-profile.json")
        original_copy = ops._copy_stable

        def add_member_after_copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            (root / "added.txt").write_text("added during backup\n", encoding="utf-8")
            return result

        with patch.object(ops, "_copy_stable", side_effect=add_member_after_copy):
            code, result, error, output = self.create_backup(
                root, profile_path, "membership-barrier-backup"
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"),
                         "POSIX dirfd traversal required")
    def test_backup_parent_symlink_swap_cannot_escape_root(self):
        root = self.path("parent-swap-source")
        nested = root / "nested"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("inside\n", encoding="utf-8")
        outside = self.path("parent-swap-outside")
        outside.mkdir()
        (outside / "file.txt").write_text("outside-must-not-copy\n", encoding="utf-8")
        profile_path = self.backup_profile([{"path": ".", "kind": "tree"}],
                                           name="parent-swap-profile.json")
        original_copy = ops._copy_stable
        moved = root / "nested-original"
        swapped = False

        def swap_parent(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                nested.rename(moved)
                nested.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_copy(*args, **kwargs)

        with patch.object(ops, "_copy_stable", side_effect=swap_parent):
            code, result, error, output = self.create_backup(
                root, profile_path, "parent-swap-backup"
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_backup_refuses_oversized_generated_manifest(self):
        root = self.path("oversized-manifest-source")
        root.mkdir()
        (root / "file.txt").write_text("safe\n", encoding="utf-8")
        profile_path = self.backup_profile([{"path": ".", "kind": "tree"}],
                                           name="oversized-manifest-profile.json")
        with patch.object(ops, "MAX_JSON_BYTES", 64):
            code, result, error, output = self.create_backup(
                root, profile_path, "oversized-manifest-backup"
            )
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_backup_validates_generated_manifest_before_publication(self):
        root = self.path("invalid-produced-backup-source")
        root.mkdir()
        (root / "file.txt").write_text("safe\n", encoding="utf-8")

        with patch.object(ops, "_now", return_value="not-a-timestamp"):
            code, result, error, output = self.create_backup(
                root, name="invalid-produced-backup"
            )

        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        self.assertFalse(output.exists())

    def test_backup_manifest_rejects_unsafe_mode_mtime_and_kind(self):
        cases = {
            "mode": lambda entry: entry.__setitem__("mode", 0o10000),
            "mtime": lambda entry: entry.__setitem__("mtime_ns", ops.MAX_MTIME_NS + 1),
            "kind": lambda entry: entry.__setitem__("kind", "symlink"),
        }
        for name, mutate_entry in cases.items():
            with self.subTest(name=name):
                root = self.path(f"unsafe-{name}-source")
                root.mkdir()
                (root / "file.txt").write_text("safe\n", encoding="utf-8")
                self.assertEqual(self.create_backup(root, name=f"unsafe-{name}-backup")[0], 0)
                backup = self.path(f"unsafe-{name}-backup")
                self.rewrite_manifest(backup, lambda value: mutate_entry(value["entries"][0]))

                code, result, error = self.invoke_json("backup", "verify", backup)

                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits required")
    def test_restore_strips_setid_sticky_and_shared_write_mode_bits(self):
        root = self.path("unsafe-bits-source")
        root.mkdir()
        (root / "file.txt").write_text("safe\n", encoding="utf-8")
        self.assertEqual(self.create_backup(root, name="unsafe-bits-backup")[0], 0)
        backup = self.path("unsafe-bits-backup")
        self.rewrite_manifest(
            backup, lambda value: value["entries"][0].__setitem__("mode", 0o7777)
        )
        target = self.path("unsafe-bits-restore")

        code, result, error = self.invoke_json(
            "restore-stage", backup, "--target", target, "--apply",
            "--approval-id", "change-safe-mode-1234"
        )

        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["status"], "staged")
        self.assertEqual((target / "file.txt").stat().st_mode & 0o7777, 0o755)

    def test_backup_manifest_rejects_nonportable_casefold_and_nfc_paths(self):
        cases = {
            "reserved": ("CON.txt", "safe-two.txt"),
            "casefold": ("Case.txt", "case.txt"),
            "nfc": ("caf\u00e9.txt", "cafe\u0301.txt"),
        }
        for name, sources in cases.items():
            with self.subTest(name=name):
                root = self.path(f"path-{name}-source")
                root.mkdir()
                (root / "one.txt").write_text("one\n", encoding="utf-8")
                (root / "two.txt").write_text("two\n", encoding="utf-8")
                self.assertEqual(self.create_backup(root, name=f"path-{name}-backup")[0], 0)
                backup = self.path(f"path-{name}-backup")

                def change_sources(value):
                    value["entries"][0]["source"] = sources[0]
                    value["entries"][1]["source"] = sources[1]

                self.rewrite_manifest(backup, change_sources)
                code, result, error = self.invoke_json("backup", "verify", backup)

                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)

    def test_unexpected_typeerror_is_sanitized_and_exits_two(self):
        secret_detail = str(self.temp.resolve()) + "\\synthetic-sensitive-detail"
        with patch.object(ops, "load_profile", side_effect=TypeError(secret_detail)):
            code, output, error = self.invoke_json(
                "preflight", "--profile", self.path("unused-profile.json")
            )

        self.assertEqual(code, 2)
        self.assertIsNone(output)
        self.assertEqual(error["error"], "unexpected_failure")
        self.assertEqual(error["reason"], "TypeError")
        self.assertNotIn(secret_detail, json.dumps(error))


class HealthTests(OpsTestCase):
    def health_profile(self, checks, name="health.json"):
        return self.write_profile(profile(health=checks), name)

    def test_health_healthy_wrong_status_oversized_and_redirect(self):
        QuietHealthHandler.paths = []
        with loopback_server(self, QuietHealthHandler) as url:
            cases = (
                ("healthy", {"name": "healthy", "url": url + "/ok", "contains": "ok"}, 0),
                ("wrong", {"name": "wrong", "url": url + "/ok", "status": 503}, 1),
                ("redirect", {"name": "redirect", "url": url + "/redirect"}, 1),
            )
            for name, check, expected in cases:
                with self.subTest(name=name):
                    profile_path = self.health_profile([check], f"{name}.json")
                    code, result, error = self.invoke_json("health", "--profile", profile_path)
                    self.assertEqual((code, error), (expected, None))
                    self.assertEqual(result["exit_code"], expected)
            oversized = self.health_profile([{"name": "large", "url": url + "/large"}],
                                             "large.json")
            with patch.object(ops, "MAX_HTTP_BODY", 8):
                code, result, error = self.invoke_json("health", "--profile", oversized)
            self.assertEqual((code, error), (1, None))
            self.assertEqual(result["results"][0]["error"], "ValueError")

        self.assertIn("/redirect", QuietHealthHandler.paths)
        self.assertNotIn("/must-not-be-visited", QuietHealthHandler.paths)
        self.assertNotIn("SECRET_REDIRECT_BODY", json.dumps(result))

    def test_connection_refused_is_a_failed_check_not_a_crash(self):
        profile_path = self.health_profile(
            [{"name": "refused", "url": "http://127.0.0.1:1", "timeout": 0.1}]
        )
        with patch.object(ops, "_http_opener") as opener:
            opener.return_value.open.side_effect = ConnectionRefusedError("synthetic")
            code, result, error = self.invoke_json("health", "--profile", profile_path)
        self.assertEqual((code, error), (1, None))
        self.assertFalse(result["results"][0]["ok"])
        self.assertEqual(result["results"][0]["error"], "ConnectionRefusedError")

    def test_invalid_health_profile_exits_two_before_connecting(self):
        invalid = self.write_profile(profile(health=[{
            "name": "invalid", "url": "http://127.0.0.1:1", "unexpected": True
        }]), "invalid-health.json")
        with patch.object(ops, "_http_opener") as opener:
            code, result, error = self.invoke_json("health", "--profile", invalid)
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)
        opener.assert_not_called()


class TimelineAndEvidenceTests(OpsTestCase):
    def evidence_profile(self):
        return self.write_profile(profile(evidence={"allow_extensions": [".json", ".jsonl"],
                                                     "max_files": 32,
                                                     "max_file_bytes": 262144,
                                                     "max_total_bytes": 1048576}),
                                  "evidence-profile.json")

    def test_timeline_orders_events_and_uses_zero_and_one_exit_codes(self):
        first = write_json(self.path("events-a.json"), [
            event("later", "2026-01-01T00:01:00Z", severity="high"),
            event("same-b", "2026-01-01T00:00:00Z"),
        ])
        second = self.path("events-b.jsonl")
        second.write_text(json.dumps(event("same-a", "2026-01-01T01:00:00+01:00")) + "\n",
                          encoding="utf-8")
        output = self.path("timeline.jsonl")
        code, result, error = self.invoke_json("timeline", "--events", first, second,
                                               "--output", output)
        self.assertEqual((code, error), (1, None))
        ordered = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item["id"] for item in ordered], ["same-a", "same-b", "later"])
        self.assertEqual(result["high_or_critical"], 1)

        info_only = write_json(self.path("info.json"), event("info", "2026-01-01T00:00:00Z"))
        code, result, error = self.invoke_json("timeline", "--events", info_only,
                                               "--output", self.path("info.jsonl"))
        self.assertEqual((code, error), (0, None))

    def test_timeline_rejects_duplicate_malformed_oversized_and_secret_content(self):
        duplicate = write_json(self.path("duplicate.json"), [
            event("same", "2026-01-01T00:00:00Z"),
            event("same", "2026-01-01T00:01:00Z"),
        ])
        malformed = self.path("malformed.jsonl")
        malformed.write_text("{not-json}\n", encoding="utf-8")
        oversized = self.path("oversized.jsonl")
        oversized.write_bytes(b"{" + b"x" * 64 + b"}\n")
        secret_text = "password=synthetic-sensitive-value"
        secret = write_json(self.path("secret.json"),
                            event("secret", "2026-01-01T00:00:00Z", summary=secret_text))
        cases = ((duplicate, None), (malformed, None), (oversized, 16), (secret, None))
        for number, (source, line_limit) in enumerate(cases):
            with self.subTest(source=source.name):
                output = self.path(f"rejected-{number}.jsonl")
                manager = patch.object(ops, "MAX_EVENT_LINE", line_limit) if line_limit else nullcontext()
                with manager:
                    code, result, error = self.invoke_json("timeline", "--events", source,
                                                           "--output", output)
                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)
                self.assertFalse(output.exists())
                self.assertNotIn(secret_text, json.dumps(error))

    @unittest.skipIf(os.name == "nt", "secure evidence directory staging is POSIX-only")
    def test_evidence_accepts_supported_sanitized_schemas(self):
        profile_path = self.evidence_profile()
        snapshot = snapshot_document()
        snapshot_path = write_json(self.path("snapshot.json"), snapshot)
        comparison = ops._snapshot_comparison(snapshot, snapshot, "a" * 64, "b" * 64)
        comparison_path = write_json(self.path("comparison.json"), comparison)
        event_path = write_json(self.path("event.json"), event("event-1", "2026-01-01T00:00:00Z"))
        validation_path = write_json(self.path("validation.json"), validation_record("validation-1"))
        scanner_path = write_json(self.path("scanner.json"), {
            "tool": "DurkaHelper defense_scan", "version": "1.6.0", "offline": True,
            "created_at": "2026-01-01T00:00:00Z", "scope": scanner_scope(),
            "partial": False, "exit_code": 0, "findings": [], "issues": []
        })
        operation_path = write_json(self.path("health-result.json"), {
            "checked_at": "2026-01-01T00:00:00Z", "command": "health", "exit_code": 0,
            "profile": {"name": "qa-profile", "sha256": "a" * 64}, "results": [],
            "summary": {"failed": 0, "total": 0}, "tool": {"name": ops.TOOL, "version": ops.VERSION}
        })

        source_root = self.path("evidence-backup-source")
        source_root.mkdir()
        (source_root / "file.txt").write_text("safe", encoding="utf-8")
        backup_profile = self.write_profile(profile(backup={
            "entries": [{"path": ".", "kind": "tree"}], "max_files": 4,
            "max_file_bytes": 1024, "max_total_bytes": 4096
        }), "backup-profile.json")
        backup_dir = self.path("evidence-backup")
        self.assertEqual(self.invoke_json("backup", "create", "--profile", backup_profile,
                                          "--root", source_root, "--output", backup_dir)[0], 0)
        manifest_path = backup_dir / "manifest.json"

        output = self.path("evidence")
        inputs = [snapshot_path, comparison_path, event_path, validation_path, scanner_path,
                  operation_path, manifest_path]
        code, result, error = self.invoke_json("evidence", "--profile", profile_path,
                                               "--output", output, "--input", *inputs)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["artifacts"], len(inputs))
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        schemas = {item["schema"] for item in manifest["artifacts"]}
        self.assertTrue({ops.SNAPSHOT_SCHEMA, ops.COMPARISON_SCHEMA, ops.BACKUP_SCHEMA,
                         ops.EVENT_SCHEMA, ops.VALIDATION_SCHEMA,
                         "durkahelper.scanner-report.safe.v1",
                         "durkahelper.operation-result.safe.v1"} <= schemas)

    @unittest.skipIf(os.name == "nt", "secure evidence directory staging is POSIX-only")
    def test_evidence_rejects_logs_pcaps_and_secret_looking_content(self):
        profile_path = self.evidence_profile()
        secret_text = "token=synthetic-sensitive-value"
        cases = {
            "capture.pcap.json": {},
            "server.log.json": {},
            "neo-info.json": {},
            "compose-config.json": {},
            "secret.json": event("secret-event", "2026-01-01T00:00:00Z", summary=secret_text),
        }
        for number, (name, value) in enumerate(cases.items()):
            with self.subTest(name=name):
                source = write_json(self.path(name), value)
                output = self.path(f"evidence-rejected-{number}")
                code, result, error = self.invoke_json("evidence", "--profile", profile_path,
                                                       "--output", output, "--input", source)
                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)
                self.assertFalse(output.exists())
                self.assertNotIn(secret_text, json.dumps(error))

    @unittest.skipIf(os.name == "nt", "secure evidence directory staging is POSIX-only")
    def test_snapshot_evidence_hides_absolute_root_and_adapter_record_names(self):
        profile_path = self.evidence_profile()
        absolute_root = str(self.temp.resolve())
        process_name = "synthetic-process-identity-should-not-leak"
        service_name = "synthetic-service-identity-should-not-leak"
        snapshot = snapshot_document(root=ops._opaque_root_identifier(Path(absolute_root)), adapters={
            "processes": [{"name": process_name, "pid": 44, "ppid": 1, "uid": 1000}],
            "services": [{"name": service_name, "pid": 55, "state": "running"}],
        })
        source = write_json(self.path("sensitive-identities-snapshot.json"), snapshot)
        output = self.path("sanitized-identities-evidence")

        code, result, error = self.invoke_json(
            "evidence", "--profile", profile_path, "--output", output, "--input", source
        )

        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["artifacts"], 1)
        artifacts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in output.glob("artifact-*.json")
        ]
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        serialized = json.dumps(artifact, ensure_ascii=True, sort_keys=True)
        self.assertEqual(artifact["schema"], "durkahelper.snapshot-evidence.safe.v1")
        self.assertRegex(artifact["root"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(set(artifact["adapters"]), {"processes", "services"})
        self.assertNotIn("listeners", artifact["adapters"])
        for sensitive in (absolute_root, process_name, service_name):
            self.assertNotIn(sensitive, serialized)


class PatchCheckTests(OpsTestCase):
    def test_required_deployment_audit_cannot_be_omitted(self):
        baseline = snapshot_document()
        code, result, error = self.run_patch_check(
            baseline, copy.deepcopy(baseline), *self.complete_evidence("audit-required"),
            "--require-deployment-audit")
        self.assertEqual((code, error), (2, None))
        self.assertIn("deployment_audit_missing", result["summary"])

    def test_deployment_audit_is_bound_to_config_and_validation(self):
        from test_ops_deployment_audit import fixture
        model, policy = fixture()
        baseline = snapshot_document(files=[file_record("compose.json")])
        model["source_sha256"] = baseline["files"][0]["sha256"]
        audit = ops.deployment_audit(model, policy, checked_at=baseline["created_at"])
        model_path = write_json(self.path("deployment-model.json"), model)
        policy_path = write_json(self.path("deployment-policy.json"), policy)
        audit_path = write_json(self.path("deployment-audit.json"), audit)
        extra = ("--deployment-model", model_path, "--deployment-policy", policy_path,
                 "--deployment-audit", audit_path)
        evidence = self.complete_evidence("audit-bound", before=baseline, after=baseline)
        code, result, error = self.run_patch_check(baseline, baseline, *evidence, *extra)
        self.assertEqual((code, error), (2, None))
        self.assertIn("validation_evidence_unbound", result["summary"])
        validation_path = evidence[-1]
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["attributes"].update(
            deployment_audit_sha256=hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            deployment_model_sha256=audit["model_sha256"], deployment_policy_sha256=audit["policy_sha256"])
        write_json(validation_path, validation)
        code, result, error = self.run_patch_check(baseline, baseline, *evidence, *extra)
        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["attributes"]["deployment_model_sha256"], audit["model_sha256"])
        model["source_sha256"] = "f" * 64
        write_json(model_path, model)
        # Merely replacing a model never preserves a previously issued audit.
        code, result, error = self.run_patch_check(baseline, baseline, *evidence, *extra)
        self.assertEqual(code, 2)
        self.assertIn("does not match", error["reason"])
        audit = ops.deployment_audit(model, policy, checked_at=baseline["created_at"])
        write_json(audit_path, audit)
        validation["attributes"].update(
            deployment_audit_sha256=hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            deployment_model_sha256=audit["model_sha256"])
        write_json(validation_path, validation)
        code, result, error = self.run_patch_check(baseline, baseline, *evidence, *extra)
        self.assertEqual((code, error), (2, None))
        self.assertIn("deployment_source_unbound", result["summary"])

    def run_patch_check(self, before, after, *extra):
        before_path = write_json(self.path("patch-before.json"), before)
        after_path = write_json(self.path("patch-after.json"), after)
        return self.invoke_json("patch-check", "--before", before_path, "--after", after_path,
                                *extra)

    def complete_evidence(self, suffix, *, before=None, after=None,
                          validation_status="pass", health_ok=True,
                          after_findings=()):
        before = snapshot_document() if before is None else before
        after = copy.deepcopy(before) if after is None else after
        scanner_base = {
            "tool": "DurkaHelper defense_scan", "version": "1.6.0", "offline": True,
            "partial": False, "issues": [], "scope": scanner_scope(root=before["root"]),
        }
        before_scanner = write_json(self.path(f"scanner-before-{suffix}.json"), {
            **scanner_base, "created_at": before["created_at"],
            "exit_code": 0, "findings": [],
        })
        after_scanner = write_json(self.path(f"scanner-after-{suffix}.json"), {
            **scanner_base, "created_at": after["created_at"],
            "exit_code": 1 if after_findings else 0,
            "findings": list(after_findings),
        })
        health = write_json(self.path(f"health-{suffix}.json"), {
            "checked_at": after["created_at"], "command": "health",
            "exit_code": 0 if health_ok else 1,
            "profile": dict(after["profile"]),
            "results": [{"name": "synthetic-health", "ok": health_ok,
                         "status": 200 if health_ok else 503, "ms": 1}],
            "summary": {"failed": 0 if health_ok else 1, "total": 1},
            "tool": {"name": ops.TOOL, "version": ops.VERSION},
        })
        validation = write_json(
            self.path(f"validation-{suffix}.json"),
            validation_record(
                f"validation-{suffix}", validation_status,
                timestamp=after["created_at"],
                attributes={
                    "run_id": "synthetic-run-" + suffix,
                    "before_snapshot_sha256": hashlib.sha256(
                        json.dumps(before, ensure_ascii=True).encode("utf-8")
                    ).hexdigest(),
                    "after_snapshot_sha256": hashlib.sha256(
                        json.dumps(after, ensure_ascii=True).encode("utf-8")
                    ).hexdigest(),
                    "health_sha256": hashlib.sha256(health.read_bytes()).hexdigest(),
                    "before_scanner_sha256": hashlib.sha256(
                        before_scanner.read_bytes()
                    ).hexdigest(),
                    "after_scanner_sha256": hashlib.sha256(after_scanner.read_bytes()).hexdigest(),
                },
            ),
        )
        return ("--before-scanner", before_scanner, "--after-scanner", after_scanner,
                "--health-result", health, "--validation-record", validation)

    def approved_drift(self, suffix, before, after, drift, **changes):
        document = {
            "schema": ops.APPROVED_DRIFT_SCHEMA,
            "id": "reviewed-drift-" + suffix,
            "reviewed_at": after["created_at"],
            "baseline_sha256": hashlib.sha256(
                json.dumps(before, ensure_ascii=True).encode("utf-8")
            ).hexdigest(),
            "current_sha256": hashlib.sha256(
                json.dumps(after, ensure_ascii=True).encode("utf-8")
            ).hexdigest(),
            "drift": drift,
        }
        document.update(changes)
        return write_json(self.path(f"approved-drift-{suffix}.json"), document)

    def test_patch_check_pass_fail_and_partial_exit_codes(self):
        baseline = snapshot_document()
        code, result, error = self.run_patch_check(baseline, copy.deepcopy(baseline))
        self.assertEqual((code, error), (2, None))
        self.assertEqual(result["status"], "partial")

        code, result, error = self.run_patch_check(
            baseline, copy.deepcopy(baseline), *self.complete_evidence("pass")
        )
        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["status"], "pass")

        changed = snapshot_document(files=[file_record("new.txt")])
        code, result, error = self.run_patch_check(
            baseline, changed, *self.complete_evidence("drift", before=baseline, after=changed)
        )
        self.assertEqual((code, error), (1, None))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["attributes"]["snapshot_drift_count"], 1)

        incomplete = snapshot_document(partial=True)
        code, result, error = self.run_patch_check(
            baseline, incomplete, *self.complete_evidence(
                "partial", before=baseline, after=incomplete
            )
        )
        self.assertEqual((code, error), (2, None))
        self.assertEqual(result["status"], "partial")

    def test_patch_check_honors_validation_and_scanner_results(self):
        baseline = snapshot_document()
        code, result, error = self.run_patch_check(
            baseline, copy.deepcopy(baseline),
            *self.complete_evidence("validation-fail", validation_status="fail")
        )
        self.assertEqual((code, error), (1, None))
        self.assertEqual(result["attributes"]["validation_failures"], 1)

        code, result, error = self.run_patch_check(
            baseline, copy.deepcopy(baseline), *self.complete_evidence(
                "scanner-new",
                after_findings=[{"path": "service.py", "line": 1, "rule": "PY-EVAL"}],
            )
        )
        self.assertEqual((code, error), (1, None))
        self.assertEqual(result["attributes"]["scanner_new_findings"], 1)

        code, result, error = self.run_patch_check(
            baseline, copy.deepcopy(baseline),
            *self.complete_evidence("health-fail", health_ok=False)
        )
        self.assertEqual((code, error), (1, None))
        self.assertEqual(result["attributes"]["health_failures"], 1)

    def test_patch_check_blocks_changed_profile_even_when_evidence_matches_after(self):
        before = snapshot_document(profile_hash="a" * 64)
        after = snapshot_document(profile_hash="b" * 64)

        code, result, error = self.run_patch_check(
            before, after, *self.complete_evidence("profile-change", before=before, after=after)
        )

        self.assertEqual((code, error), (2, None))
        self.assertEqual(result["status"], "partial")
        self.assertIn("profile_changed", result["summary"])

    def test_patch_check_rejects_contradictory_scanner_status(self):
        baseline = snapshot_document()
        base_report = {
            "tool": "DurkaHelper defense_scan", "version": "1.6.0", "offline": True,
            "created_at": baseline["created_at"],
            "scope": scanner_scope(root=baseline["root"]),
            "partial": False, "exit_code": 0, "findings": [], "issues": [],
        }
        cases = (
            {**base_report, "findings": [{"path": "service.py", "line": 1,
                                           "rule": "PY-EVAL"}]},
            {**base_report, "exit_code": 1},
            {**base_report, "exit_code": 2, "partial": False,
             "issues": [{"path": ".", "reason": "synthetic_partial"}]},
        )
        for number, report in enumerate(cases):
            with self.subTest(number=number):
                scanner_path = write_json(self.path(f"contradictory-{number}.json"), report)
                evidence = list(self.complete_evidence(
                    f"contradictory-{number}", before=baseline, after=baseline
                ))
                evidence[1] = scanner_path

                code, result, error = self.run_patch_check(
                    baseline, copy.deepcopy(baseline), *evidence
                )

                self.assertEqual(code, 2)
                self.assertIsNone(result)
                self.assertEqual(error["exit_code"], 2)

    def test_patch_check_status_mapping_is_conservative(self):
        baseline = snapshot_document()
        for status in ("partial", "blocked", "not_run", "skipped_not_applicable"):
            with self.subTest(status=status):
                code, result, error = self.run_patch_check(
                    baseline, copy.deepcopy(baseline),
                    *self.complete_evidence("status-" + status, validation_status=status)
                )
                self.assertEqual((code, error), (2, None))
                self.assertEqual(result["status"], "partial")

    def test_patch_check_rejects_stale_or_unbound_evidence(self):
        baseline = snapshot_document()
        evidence = list(self.complete_evidence("unbound", before=baseline, after=baseline))
        validation_path = Path(evidence[-1])
        record = json.loads(validation_path.read_text(encoding="utf-8"))
        record["attributes"]["health_sha256"] = "0" * 64
        write_json(validation_path, record)

        code, result, error = self.run_patch_check(baseline, copy.deepcopy(baseline), *evidence)

        self.assertEqual((code, error), (2, None))
        self.assertEqual(result["status"], "partial")
        self.assertIn("validation_evidence_unbound", result["summary"])

        stale = list(self.complete_evidence("stale", before=baseline, after=baseline))
        health_path = Path(stale[5])
        health = json.loads(health_path.read_text(encoding="utf-8"))
        health["checked_at"] = "2025-12-31T23:59:59Z"
        write_json(health_path, health)
        code, result, error = self.run_patch_check(baseline, copy.deepcopy(baseline), *stale)
        self.assertEqual((code, error), (2, None))
        self.assertIn("health_time_unbound", result["summary"])

    def test_patch_check_accepts_only_exact_hash_bound_reviewed_drift(self):
        baseline = snapshot_document()
        changed = snapshot_document(files=[file_record("new.txt")])
        comparison = ops._snapshot_comparison(
            baseline, changed,
            hashlib.sha256(json.dumps(baseline, ensure_ascii=True).encode("utf-8")).hexdigest(),
            hashlib.sha256(json.dumps(changed, ensure_ascii=True).encode("utf-8")).hexdigest(),
        )
        approval = self.approved_drift("exact", baseline, changed, comparison["drift"])
        evidence = self.complete_evidence("approved", before=baseline, after=changed)

        code, result, error = self.run_patch_check(
            baseline, changed, *evidence, "--approved-drift", approval
        )
        self.assertEqual((code, error), (0, None))
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["attributes"]["snapshot_drift_approved"])
        self.assertEqual(result["attributes"]["approved_drift_id"], "reviewed-drift-exact")
        self.assertRegex(result["attributes"]["approved_drift_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["attributes"]["run_id"], "synthetic-run-approved")
        for field in ("before_snapshot_sha256", "after_snapshot_sha256",
                      "before_scanner_sha256", "after_scanner_sha256", "health_sha256",
                      "validation_evidence_sha256"):
            self.assertRegex(result["attributes"][field], r"^[0-9a-f]{64}$")

        wrong = self.approved_drift(
            "wrong-hash", baseline, changed, comparison["drift"],
            current_sha256="0" * 64,
        )
        code, result, error = self.run_patch_check(
            baseline, changed, *evidence, "--approved-drift", wrong
        )
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertEqual(error["exit_code"], 2)

    def test_patch_check_binds_scanner_root_and_both_report_hashes(self):
        baseline = snapshot_document()
        evidence = list(self.complete_evidence("scanner-binding", before=baseline,
                                               after=baseline))
        before_scanner_path = Path(evidence[1])
        after_scanner_path = Path(evidence[3])
        validation_path = Path(evidence[7])

        before_report = json.loads(before_scanner_path.read_text(encoding="utf-8"))
        before_report["findings"] = [{"path": "hidden.py", "line": 1, "rule": "PY-EVAL"}]
        before_report["exit_code"] = 1
        write_json(before_scanner_path, before_report)
        code, result, error = self.run_patch_check(baseline, copy.deepcopy(baseline), *evidence)
        self.assertEqual((code, error), (2, None))
        self.assertIn("validation_evidence_unbound", result["summary"])

        # Rebuild coherent evidence hashes for a scanner pair that is internally
        # comparable but belongs to another target.  Root binding must still
        # prevent PASS.
        evidence = list(self.complete_evidence("scanner-root", before=baseline,
                                               after=baseline))
        before_scanner_path = Path(evidence[1])
        after_scanner_path = Path(evidence[3])
        validation_path = Path(evidence[7])
        foreign_scope = scanner_scope(root="sha256:" + "9" * 64)
        for report_path in (before_scanner_path, after_scanner_path):
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["scope"] = foreign_scope
            write_json(report_path, report)
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["attributes"]["before_scanner_sha256"] = hashlib.sha256(
            before_scanner_path.read_bytes()).hexdigest()
        validation["attributes"]["after_scanner_sha256"] = hashlib.sha256(
            after_scanner_path.read_bytes()).hexdigest()
        write_json(validation_path, validation)

        code, result, error = self.run_patch_check(baseline, copy.deepcopy(baseline), *evidence)
        self.assertEqual((code, error), (2, None))
        self.assertIn("scanner_root_unbound", result["summary"])


if __name__ == "__main__":
    unittest.main()
