"""Defensive tools only: temporary files and HTTP on 127.0.0.1."""
from contextlib import contextmanager, redirect_stderr
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "lab")]
import backup_config
import common
import health_service
import http_probe
import log_summary


def cli(script, *args):
    return subprocess.run([sys.executable, str(ROOT / script), *map(str, args)],
                          cwd=ROOT, capture_output=True, text=True, timeout=10)


@contextmanager
def serve(handler=health_service.Handler):
    with redirect_stderr(io.StringIO()):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class ServiceRegressionTests(unittest.TestCase):
    def test_health_and_version_remain_available(self):
        with serve() as url:
            for path, expected in [("/health", "ok"), ("/health?check=1", "ok"),
                                   ("/version", "demo")]:
                with self.subTest(path=path):
                    result = http_probe.probe({"name": "smoke", "url": url + path,
                                               "contains": expected}, 1)
                    self.assertTrue(result["ok"], result)

    def test_head_has_no_body_and_preserves_headers(self):
        with serve() as url:
            with common.opener().open(Request(url + "/health", method="HEAD"), timeout=1) as response:
                self.assertEqual(response.status, 200)
                self.assertGreater(int(response.headers["Content-Length"]), 0)
                self.assertEqual(response.read(), b"")

    def test_unknown_route_and_method_are_explicit_errors(self):
        with serve() as url:
            self.assertTrue(http_probe.probe({"name": "unknown", "url": url + "/missing",
                                              "status": 404}, 1)["ok"])
            with self.assertRaises(HTTPError) as error:
                common.opener().open(Request(url + "/health", data=b"{}"), timeout=1)
            with error.exception as response:
                self.assertEqual(response.code, 405)
                self.assertEqual(response.headers["Allow"], "GET, HEAD")

    def test_content_and_status_mismatches_fail(self):
        with serve() as url:
            for change in [{"contains": "not present"}, {"status": 503}]:
                result = http_probe.probe({"name": "negative", "url": url + "/health", **change}, 1)
                self.assertFalse(result["ok"])

    def test_probe_does_not_follow_redirect_or_print_response(self):
        paths = []

        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-be-visited")
                self.end_headers()
                self.wfile.write(b"SECRET_BODY")

        with serve(Redirect) as url:
            result = http_probe.probe({"name": "redirect", "url": url}, 1)
        self.assertEqual(paths, ["/"])
        self.assertEqual(result["status"], 302)
        self.assertFalse(result["ok"])
        self.assertNotIn("SECRET_BODY", json.dumps(result))

    def test_probe_limits_body_size(self):
        with patch.object(http_probe, "limited_read", side_effect=ValueError("body too large")):
            with serve() as url:
                result = http_probe.probe({"name": "large", "url": url + "/health"}, 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ValueError")

    def test_probe_timeout_and_unavailable_service_are_failures(self):
        for error in [TimeoutError("timeout"), ConnectionRefusedError("unavailable")]:
            with self.subTest(error=type(error).__name__), patch.object(http_probe, "opener") as make:
                make.return_value.open.side_effect = error
                result = http_probe.probe({"name": "health", "url": "http://127.0.0.1:1"}, 0.1)
            self.assertFalse(result["ok"])

    def test_probe_validates_entire_configuration_before_connecting(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "checks.json"
            config.write_text(json.dumps([
                {"name": "first", "url": "http://127.0.0.1:1"},
                {"name": "bad", "url": "http://127.0.0.1:1", "contians": "typo"},
            ]), encoding="utf-8")
            with patch.object(sys, "argv", ["http_probe.py", str(config)]), \
                 patch.object(http_probe, "probe") as probe, redirect_stderr(io.StringIO()):
                self.assertEqual(http_probe.main(), 2)
                probe.assert_not_called()

    def test_probe_cli_success_and_failed_check_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp, serve() as url:
            config = Path(tmp) / "checks.json"
            for expected, code in [(200, 0), (503, 1)]:
                config.write_text(json.dumps([{"name": "health", "url": url + "/health",
                                               "status": expected}]), encoding="utf-8")
                result = cli("scripts/http_probe.py", config)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(result.stdout)["ok"], code == 0)


class LogSummaryTests(unittest.TestCase):
    def test_fixture_counts(self):
        result = cli("scripts/log_summary.py", ROOT / "lab/fixtures/events.jsonl")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["records"], 4)
        self.assertEqual(summary["http_errors"], 2)
        self.assertEqual(summary["statuses"], {"200": 2, "404": 1, "503": 1})

    def test_messages_and_arbitrary_field_values_never_appear(self):
        records = [{"level": "warn", "status": 403, "message": "SECRET_MESSAGE"},
                   {"level": "SECRET_LEVEL", "status": "SECRET_STATUS", "token": "SECRET_TOKEN"},
                   {"level": ["ERROR"], "status": True}]
        stream = io.BytesIO("\n".join(json.dumps(r) for r in records).encode())
        result = log_summary.summarize(stream)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["levels"], {"WARNING": 1})
        self.assertEqual(result["invalid_fields"], 4)

    def test_malformed_blank_non_object_and_oversized_lines(self):
        stream = io.BytesIO(b"\nnot-json\n[]\n\xff\n" + b"x" * (log_summary.MAX_LINE + 2)
                            + b'\n{"status":200}\n')
        summary = log_summary.summarize(stream)
        self.assertEqual(summary["lines"], 6)
        self.assertEqual(summary["invalid_lines"], 4)
        self.assertEqual(summary["blank_lines"], 1)
        self.assertEqual(summary["records"], 1)

    def test_byte_limit(self):
        with self.assertRaises(ValueError):
            log_summary.summarize(io.BytesIO(b'{"status":200}\n'), max_bytes=2)

    def test_cli_marks_partial_summary_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "events.jsonl"
            log.write_text('{"status":200}\nBROKEN_SECRET_LINE\n', encoding="utf-8")
            result = cli("scripts/log_summary.py", log)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["invalid_lines"], 1)
            self.assertNotIn("BROKEN_SECRET_LINE", result.stdout + result.stderr)
            self.assertEqual(cli("scripts/log_summary.py", Path(tmp) / "missing").returncode, 2)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "input"
        self.root.mkdir()
        self.source = self.root / "service.json"
        self.original = b'{"http":{"port":8080,"password":"SECRET_VALUE"},"enabled":true}\n'
        self.source.write_bytes(self.original)
        self.output = self.base / "output"
        self.manifest = {"files": [{"path": "service.json", "allow": [["http", "port"], ["enabled"]]}]}

    def test_selected_values_checksums_permissions_and_original(self):
        session = backup_config.backup(self.root, self.manifest, self.output)
        index = json.loads((session / "manifest.json").read_text())
        data_path = session / index["files"][0]["backup"]
        payload = data_path.read_bytes()
        self.assertEqual(json.loads(payload), {"http": {"port": 8080}, "enabled": True})
        self.assertNotIn(b"SECRET_VALUE", b"".join(p.read_bytes() for p in session.iterdir()))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), index["files"][0]["sha256"])
        self.assertEqual(self.source.read_bytes(), self.original)
        if os.name == "posix":
            self.assertEqual(session.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in session.iterdir()))

    def test_secret_fields_objects_and_missing_fields_are_rejected(self):
        for keys in [["http", "password"], ["http"], ["missing"]]:
            with self.subTest(keys=keys):
                self.manifest["files"][0]["allow"] = [keys]
                with self.assertRaises(ValueError):
                    backup_config.backup(self.root, self.manifest, self.output)
                self.assertFalse(self.output.exists())

    def test_common_secret_key_spellings_are_rejected(self):
        for key in ["api_key", "accessToken", "Authorization", "private-key", "DATABASE_URL", "pwd"]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                backup_config.project_settings({key: "SECRET_VALUE"}, [[key]])

    def test_path_escape_and_symlink_are_rejected(self):
        for path in ["../service.json", "/service.json", "nested/../../service.json", "service.env"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                backup_config.source_path(self.root, path)
        link = self.root / "linked.json"
        link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            backup_config.source_path(self.root, "linked.json")

    def test_invalid_second_file_produces_no_backup(self):
        self.manifest["files"].append({"path": "missing.json", "allow": [["port"]]})
        with self.assertRaises(FileNotFoundError):
            backup_config.backup(self.root, self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_duplicate_keys_and_non_finite_numbers_fail(self):
        for data in ['{"port":1,"port":2}', '{"port":NaN}', '{"port":Infinity}']:
            self.source.write_text(data, encoding="utf-8")
            with self.subTest(data=data), self.assertRaises(ValueError):
                backup_config.read_json(self.source)

    def test_write_failure_removes_partial_backup(self):
        with patch.object(backup_config.Path, "write_text", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                backup_config.backup(self.root, self.manifest, self.output)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_cli_example_and_unique_sessions(self):
        sessions = []
        for _ in range(2):
            result = cli("scripts/backup_config.py", "config/backup.example.json", "--root",
                         "lab/fixtures", "--output", self.output)
            self.assertEqual(result.returncode, 0, result.stderr)
            session = Path(result.stdout.strip())
            self.assertNotIn("DEMO_ONLY_DO_NOT_COPY", "".join(p.read_text() for p in session.iterdir()))
            sessions.append(session)
        self.assertNotEqual(*sessions)

    def test_cli_failure_does_not_print_source_values(self):
        manifest = self.base / "manifest.json"
        manifest.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.source.write_text('{"SECRET_VALUE": BROKEN}', encoding="utf-8")
        result = cli("scripts/backup_config.py", manifest, "--root", self.root, "--output", self.output)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("SECRET_VALUE", result.stdout + result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
