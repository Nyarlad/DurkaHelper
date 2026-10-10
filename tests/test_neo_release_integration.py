"""Published Neo release archive and isolated info/auth smoke contract tests."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("neo_release_test", ROOT / "integration/neo_release_smoke.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


@contextlib.contextmanager
def temporary():
    with tempfile.TemporaryDirectory() as value:
        yield Path(value).resolve()


def archive(overrides=None, extra=None):
    binary = bytearray(128)
    binary[:6] = b"\x7fELF\x02\x01"
    binary[18:20] = (62).to_bytes(2, "little")
    files = {"README.md": b"synthetic", "client_config.yml": b"unused",
             "exploits/.keep": b"", "neo": bytes(binary)}
    files.update(overrides or {})
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        for name, body in files.items():
            member = tarfile.TarInfo(fixture.PREFIX + name)
            member.size = len(body)
            tar.addfile(member, io.BytesIO(body))
        if extra is not None:
            tar.addfile(extra)
    return data.getvalue(), bytes(binary)


@contextlib.contextmanager
def synthetic_release(data):
    with patch.object(fixture, "SIZE", len(data)), patch.object(fixture, "SHA256", hashlib.sha256(data).hexdigest()):
        yield


class ReleaseArchiveTests(unittest.TestCase):
    def test_real_repository_lock_contains_exact_reviewed_pair(self):
        fixture.check_lock(ROOT / "config/toolchain.lock.json")

    def test_valid_archive_extracts_only_verified_elf_into_memory(self):
        data, binary = archive()
        with synthetic_release(data):
            self.assertEqual(fixture.release_binary(data), binary)

    def test_checksum_mismatch_fails_before_decompression(self):
        data, _ = archive()
        with synthetic_release(data), patch.object(fixture.tarfile, "open") as opened:
            with self.assertRaisesRegex(fixture.FixtureError, "SHA-256"):
                fixture.release_binary(data[:-1] + bytes([data[-1] ^ 1]))
            opened.assert_not_called()

    def test_archive_traversal_link_and_duplicate_rejected(self):
        for name, kind in (("../outside", tarfile.REGTYPE), (fixture.PREFIX + "link", tarfile.SYMTYPE),
                           (fixture.PREFIX + "neo", tarfile.REGTYPE)):
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "../outside"
            data, _ = archive(extra=member)
            with self.subTest(name=name), synthetic_release(data), self.assertRaises(fixture.FixtureError):
                fixture.release_binary(data)

    def test_architecture_and_expanded_limit_rejected(self):
        for overrides, limit in (({"neo": b"not executable"}, fixture.MAX_BINARY), ({}, 32)):
            data, _ = archive(overrides)
            with synthetic_release(data), patch.object(fixture, "MAX_BINARY", limit):
                with self.assertRaises(fixture.FixtureError):
                    fixture.release_binary(data)

    def test_preview_neither_downloads_writes_nor_calls_docker(self):
        with temporary() as temp:
            args = argparse.Namespace(lock=ROOT / "config/toolchain.lock.json", workspace=temp / "new",
                                      apply=False, download=True)
            with patch.object(fixture, "download") as download, patch.object(fixture.shared, "checked") as checked:
                self.assertEqual(fixture.prepare(args)["status"], "NOT_RUN")
            self.assertFalse(args.workspace.exists())
            download.assert_not_called()
            checked.assert_not_called()

    def test_docker_mount_delimiter_in_workspace_is_rejected_before_writes(self):
        with temporary() as temp:
            args = argparse.Namespace(lock=ROOT / "config/toolchain.lock.json", workspace=temp / "path,injection",
                                      apply=True, download=True)
            with patch.object(fixture, "download") as download, self.assertRaises(fixture.FixtureError):
                fixture.prepare(args)
            self.assertFalse(args.workspace.exists())
            download.assert_not_called()

    def test_download_redirect_host_allowlist_blocks_credentials_plaintext_and_other_hosts(self):
        redirect = fixture.ReleaseRedirect()
        for url in ("http://github.com/a", "https://evil.invalid/a", "https://u:p@github.com/a", "https://github.com:444/a"):
            with self.subTest(url=url), self.assertRaises(fixture.FixtureError):
                redirect.redirect_request(None, None, 302, "", {}, url)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_replacement_read_is_nonblocking_and_rejected(self):
        with temporary() as temp:
            target = temp / "file"
            target.write_bytes(b"x")
            real_open = os.open

            def swap(path, flags):
                self.assertTrue(flags & os.O_NONBLOCK)
                target.unlink()
                os.mkfifo(target)
                return real_open(path, flags)

            with patch.object(fixture.os, "open", side_effect=swap), self.assertRaises(fixture.FixtureError):
                fixture.bounded_read(target, 10)


class ReleaseFixtureTests(unittest.TestCase):
    def make(self, temp, data):
        source = temp / "archive.tar.gz"
        source.write_bytes(data)
        args = argparse.Namespace(lock="unused", workspace=temp / "fixture", archive=source,
                                  apply=True, download=False, approval_id="unit-test")
        with patch.object(fixture, "check_lock"):
            result = fixture.prepare(args)
        self.assertEqual(result["status"], "PASS")
        return fixture.fixture(args.workspace)

    def test_prepare_no_overwrite_binary_and_config_tamper_rejected(self):
        data, _ = archive()
        with temporary() as temp, synthetic_release(data):
            root, state = self.make(temp, data)
            self.assertEqual(state["release"], "v2.4.2")
            original = (root / "neo").read_bytes()
            (root / "neo").chmod(0o600)
            (root / "neo").write_bytes(b"changed")
            with self.assertRaisesRegex(fixture.FixtureError, "executable changed"):
                fixture.fixture(root)
            (root / "neo").write_bytes(original)
            (root / "client.yml").write_bytes(b"host: outside")
            with self.assertRaisesRegex(fixture.FixtureError, "configuration changed"):
                fixture.fixture(root)
            with patch.object(fixture, "check_lock"), self.assertRaises(fixture.FixtureError):
                fixture.prepare(argparse.Namespace(lock="unused", workspace=root, apply=False))

    def test_apply_requires_approval_and_raw_error_is_suppressed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(fixture, "smoke") as smoke:
            code = fixture.main(["smoke", "--workspace", "unused", "--stack-workspace", "unused", "--apply"])
        self.assertEqual(code, 2)
        smoke.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")

    def test_container_is_nonroot_bounded_no_host_or_privileged_or_logs(self):
        args = fixture.container_arguments(Path("/fixture"), {"id": "test"}, "project_fixture",
                                           "alpine@sha256:" + "a" * 64, False, "test-probe")
        for value in ("--read-only", "--cap-drop=ALL", "--log-driver=none", "--pull=never", "--pids-limit=32"):
            self.assertIn(value, args)
        self.assertEqual(args[args.index("--user") + 1], "65534:65534")
        self.assertEqual(args[args.index("--network") + 1], "project_fixture")
        self.assertEqual(args[-1], "info")
        self.assertNotIn("--privileged", args)
        self.assertNotIn("host", args)
        self.assertNotIn("docker.sock", " ".join(args))
        self.assertNotIn("fixture-only", " ".join(args))

    def test_cleanup_requires_exact_ownership_label(self):
        calls = []
        with patch.object(fixture.shared, "checked", side_effect=lambda cmd, **kw: calls.append(cmd) or b"other"):
            with self.assertRaisesRegex(fixture.FixtureError, "ownership mismatch"):
                fixture.cleanup("exact-name", "expected")
        self.assertEqual(len(calls), 1)

    def test_probe_always_cleans_generated_container_on_capture_failure(self):
        with patch.object(fixture.shared, "checked"), patch.object(fixture, "capture", side_effect=fixture.FixtureError("timeout")), \
                patch.object(fixture, "cleanup") as cleanup:
            with self.assertRaises(fixture.FixtureError):
                fixture.probe(Path("/fixture"), {"id": "synthetic"}, "network", "image", False)
        self.assertEqual(cleanup.call_count, 1)
        self.assertEqual(cleanup.call_args.args[1], "synthetic")

    def test_create_timeout_attempts_only_exact_generated_probe_cleanup(self):
        with patch.object(fixture.shared, "checked", side_effect=fixture.FixtureError("create timeout")), \
                patch.object(fixture, "cleanup") as cleanup:
            with self.assertRaisesRegex(fixture.FixtureError, "create timeout"):
                fixture.probe(Path("/fixture"), {"id": "synthetic"}, "network", "image", False)
        self.assertTrue(cleanup.call_args.args[0].startswith("synthetic-"))
        self.assertEqual(cleanup.call_args.args[1], "synthetic")

    def test_capture_bounded_output_and_timeout(self):
        with patch.object(fixture, "MAX_OUTPUT", 32):
            with self.assertRaisesRegex(fixture.FixtureError, "exceeded limit"):
                fixture.capture([sys.executable, "-I", "-S", "-c", "print('a'*100)"])
        with self.assertRaisesRegex(fixture.FixtureError, "timed out"):
            fixture.capture([sys.executable, "-I", "-S", "-c", "import time; time.sleep(5)"], timeout=0.05)
        self.assertEqual(fixture.capture([sys.executable, "-I", "-S", "-c", "print('fixture')"]), (0, b"fixture\r\n" if os.name == "nt" else b"fixture\n"))


class ReleaseSmokeTests(unittest.TestCase):
    def run_smoke(self, valid=(0, b"config: synthetic\nIPs buckets:\nExploits:"), denied=(1, b"Unauthenticated"), network="true;dh-smoke-111111111111;fixture"):
        state = {"id": "dh-neo-release-111111111111"}
        stack = {"project": "dh-smoke-111111111111", "images": {"alpine": "alpine@sha256:" + "a" * 64}}
        responses = [network.encode(), b"a" * 64,
                     ("true;" + stack["project"] + ";neo-server;sha256:" + "b" * 64).encode(), b"linux;amd64"]
        with patch.object(fixture, "fixture", return_value=(Path("/fixture"), state)), \
                patch.object(fixture.shared, "fixture", return_value=(Path("/stack"), stack)), \
                patch.object(fixture.shared, "farm_port", return_value=1234), patch.object(fixture.shared, "wait_ready"), \
                patch.object(fixture.shared, "checked", side_effect=responses), patch.object(fixture, "probe", side_effect=[valid, denied]):
            return fixture.smoke(argparse.Namespace(workspace="unused", stack_workspace="unused", apply=True))

    def test_success_is_limited_to_independent_published_client_info_and_auth(self):
        result = self.run_smoke()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["archive_sha256"], fixture.SHA256)
        self.assertIn("exploit execution", result["not_validated"])
        self.assertNotIn("config: synthetic", json.dumps(result))

    def test_arbitrary_failure_is_not_auth_rejection_and_empty_success_is_not_info(self):
        self.assertEqual(self.run_smoke(denied=(1, b"Docker unavailable"))["status"], "FAIL")
        self.assertEqual(self.run_smoke(valid=(0, b""))["status"], "FAIL")

    def test_noninternal_or_foreign_network_blocks(self):
        for value in ("false;dh-smoke-111111111111;fixture", "true;other;fixture"):
            with self.subTest(value=value), self.assertRaises(fixture.FixtureError):
                self.run_smoke(network=value)


if __name__ == "__main__":
    unittest.main()
