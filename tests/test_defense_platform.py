"""Cross-platform regression and offline packaging security tests."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_SCRIPT = ROOT / "scripts" / "defense_scan.py"
DIFF_SCRIPT = ROOT / "scripts" / "defense_diff.py"
BUNDLE_BUILDER = ROOT / "scripts" / "build_offline_bundle.py"

SPEC = importlib.util.spec_from_file_location("platform_scanner", SCANNER_SCRIPT)
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)
DIFF_SPEC = importlib.util.spec_from_file_location("platform_diff", DIFF_SCRIPT)
diff = importlib.util.module_from_spec(DIFF_SPEC)
DIFF_SPEC.loader.exec_module(diff)


def cp1252_cli(script, *args):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "cp1252:strict"
    env["PYTHONUTF8"] = "0"
    return subprocess.run(
        [sys.executable, str(script), *map(str, args)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )


def scan_report(findings=(), *, version=scanner.VERSION):
    scope = {
        "schema": "durkahelper.scanner-scope.v1",
        "root": "sha256:" + "1" * 64,
        "rules_sha256": "2" * 64,
        "exclude": [],
        "limits": {"max_bytes": 1048576, "max_files": 20000,
                   "max_findings": 10000},
        "path_semantics": "root-relative-posix.v1",
    }
    scope["sha256"] = hashlib.sha256(json.dumps(
        scope, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {
        "tool": "DurkaHelper defense_scan",
        "version": version,
        "offline": True,
        "created_at": "2026-10-09T00:00:00Z",
        "scope": scope,
        "findings": list(findings),
        "issues": [],
        "partial": False,
        "exit_code": 1 if findings else 0,
    }


class CliEncodingTests(unittest.TestCase):
    def assert_cli_exit(self, result, expected):
        stderr = result.stderr.decode("ascii", "backslashreplace")
        self.assertNotIn("UnicodeEncodeError", stderr, stderr)
        self.assertEqual(result.returncode, expected, stderr)
        self.assertTrue(result.stdout, "successful CLI command produced no output")

    def test_scanner_help_list_and_explain_support_cp1252_stdout(self):
        for args in (("--help",), ("--list-rules",), ("--explain", "PY-EVAL")):
            with self.subTest(args=args):
                self.assert_cli_exit(cp1252_cli(SCANNER_SCRIPT, *args), 0)

    def test_diff_help_supports_cp1252_stdout(self):
        self.assert_cli_exit(cp1252_cli(DIFF_SCRIPT, "--help"), 0)

    def test_diff_text_output_preserves_documented_exit_codes_under_cp1252(self):
        finding = {"path": "service.py", "line": 3, "rule": "PY-EVAL"}
        cases = (
            (scan_report(), scan_report(), 0),
            (scan_report(), scan_report([finding]), 1),
            (scan_report(), scan_report(version="1.5.0"), 2),
        )
        with tempfile.TemporaryDirectory() as temp:
            before_path = Path(temp) / "before.json"
            after_path = Path(temp) / "after.json"
            for before, after, expected in cases:
                with self.subTest(expected=expected):
                    before_path.write_text(json.dumps(before), encoding="ascii")
                    after_path.write_text(json.dumps(after), encoding="ascii")
                    self.assert_cli_exit(
                        cp1252_cli(DIFF_SCRIPT, before_path, after_path), expected
                    )


class IsolatedCliTests(unittest.TestCase):
    def test_all_core_help_commands_work_without_site_or_pythonpath(self):
        scripts = (
            "defense_scan.py", "defense_diff.py", "defense_ops.py",
            "http_probe.py", "log_summary.py", "backup_config.py",
            "build_offline_bundle.py",
        )
        with tempfile.TemporaryDirectory() as temp:
            environment = os.environ.copy()
            environment["PYTHONPATH"] = temp
            (Path(temp) / "common.py").write_text(
                "raise RuntimeError('untrusted cwd helper imported')\n", encoding="ascii")
            for name in scripts:
                with self.subTest(script=name):
                    # The existing HTTP CLI intentionally uses a sibling module;
                    # -E/-s/-S excludes environment and site packages but preserves it.
                    isolation = ["-E", "-s"] if name == "http_probe.py" else ["-I"]
                    completed = subprocess.run(
                        [sys.executable, "-X", "utf8", *isolation, "-S",
                         str(ROOT / "scripts" / name), "--help"],
                        cwd=temp, env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=20,
                    )
                    self.assertEqual(completed.returncode, 0,
                                     completed.stderr.decode("utf-8", "backslashreplace"))
                    self.assertIn(b"usage:", completed.stdout)

    def test_scanner_and_diff_accept_unicode_and_space_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "service \u0442\u0435\u0441\u0442"
            directory.mkdir()
            source = directory / "safe \u043a\u043e\u0434.py"
            source.write_text("value = 1\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-X", "utf8", "-I", "-S", str(SCANNER_SCRIPT),
                 str(directory), "--json"], cwd=temp, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=20,
            )
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode("utf-8", "backslashreplace"))
            report = json.loads(completed.stdout)
            self.assertEqual(report["files_scanned"], 1)
            self.assertFalse(report["partial"])
            report_path = Path(temp) / "report \u0442\u0435\u0441\u0442.json"
            report_path.write_bytes(completed.stdout)
            compared = subprocess.run(
                [sys.executable, "-X", "utf8", "-I", "-S", str(DIFF_SCRIPT),
                 str(report_path), str(report_path), "--json"], cwd=temp,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
            )
            self.assertEqual(compared.returncode, 0,
                             compared.stderr.decode("utf-8", "backslashreplace"))
            self.assertEqual(json.loads(compared.stdout)["exit_code"], 0)


class MacOSWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github" / "workflows" / "macos-arm64.yml").read_text(
            encoding="utf-8")

    def test_dispatch_only_least_privilege_and_bounded_standard_arm_runner(self):
        top_level = re.findall(r"^([^\s#:]+):", self.workflow, re.MULTILINE)
        self.assertEqual(top_level, ["name", "on", "permissions", "concurrency", "jobs"])
        triggers = self.workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", triggers, re.MULTILINE), ["workflow_dispatch"])
        self.assertIn("synthetic_pcap_base64:", triggers)
        self.assertIn("required: false", triggers)
        self.assertNotIn("${{ inputs.synthetic_pcap_base64 }}", self.workflow)
        self.assertIn('vulnbox_handoff.py --event "$GITHUB_EVENT_PATH"', self.workflow)
        permissions = self.workflow.split("\npermissions:\n", 1)[1].split(
            "\nconcurrency:", 1)[0]
        self.assertEqual(permissions.strip(), "contents: read")
        self.assertIn("runs-on: macos-15\n", self.workflow)
        self.assertIn("timeout-minutes: 15\n", self.workflow)
        self.assertIn('test "$(uname -m)" = "arm64"', self.workflow)
        self.assertIn('assert platform.machine() == "arm64"', self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertNotIn("matrix:", self.workflow)

    def test_action_pins_match_lock_and_no_secrets_or_remote_execution(self):
        actions = re.findall(r"uses:\s+([^\s@]+)@([0-9a-f]{40})", self.workflow)
        self.assertEqual(len(actions), 2)
        components = json.loads((ROOT / "config" / "toolchain.lock.json").read_text(
            encoding="utf-8"))["components"]
        for action, commit in actions:
            component = "github-actions-" + action.removeprefix("actions/")
            self.assertEqual(components[component]["source"]["commit"], commit)
        self.assertNotRegex(self.workflow, r"(?im)(?:secrets\.|ssh-key:|upload-artifact@|\b(?:ssh|scp|sudo)\s)")

    def test_ripgrep_is_checksum_pinned_and_required_before_tests(self):
        self.assertIn("ripgrep-15.1.0-aarch64-apple-darwin", self.workflow)
        self.assertIn("378e973289176ca0c6054054ee7f631a065874a352bf43f0fa60ef079b6ba715",
                      self.workflow)
        self.assertLess(self.workflow.index("ripgrep release checksum mismatch"),
                        self.workflow.index('tar -xzf "$rg_dir/release.tar.gz"'))
        self.assertLess(self.workflow.index("command -v rg"),
                        self.workflow.index("name: Run Defense unit tests"))
        self.assertNotIn("brew install", self.workflow)

    def test_ripgrep_version_gate_accepts_official_revision_suffix_only(self):
        code = re.search(r"python -c '(import subprocess;[^\n]+)'", self.workflow).group(1)
        for version in ("ripgrep 15.1.0", "ripgrep 15.1.0 (rev af60c2de9d)"):
            with self.subTest(version=version), patch.object(
                    subprocess, "check_output", return_value=version + "\nfeatures:+pcre2\n"):
                exec(code, {})
        for version in ("ripgrep 15.1.00", "ripgrep 15.1.0-dev", "ripgrep 15.2.0", "other 15.1.0"):
            with self.subTest(version=version), patch.object(
                    subprocess, "check_output", return_value=version + "\n"):
                with self.assertRaises(AssertionError):
                    exec(code, {})

    def test_source_and_clean_extraction_both_require_full_suite_without_skips(self):
        self.assertEqual(self.workflow.count("python -m unittest discover -s tests"), 2)
        self.assertEqual(self.workflow.count("acceptance forbids skipped tests"), 2)
        self.assertIn("test ! -e .git", self.workflow)
        self.assertIn("PYTHONDONTWRITEBYTECODE", self.workflow)


class SymlinkRootTests(unittest.TestCase):
    def symlink_or_skip(self, link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {type(exc).__name__}")
        self.assertTrue(link.is_symlink())

    def test_regular_file_below_symlinked_ancestor_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            (real / "service.py").write_text("value = 1\n", encoding="utf-8")
            alias = root / "alias"
            self.symlink_or_skip(alias, real, directory=True)

            report = scanner.scan(alias / "service.py", scanner.load_rules())

            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(report["issues"], [])
            self.assertEqual(report["exit_code"], 0)

    def test_symlink_leaf_input_remains_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.py"
            target.write_text("value = 1\n", encoding="utf-8")
            link = root / "service.py"
            self.symlink_or_skip(link, target)

            with self.assertRaisesRegex(ValueError, "symlink"):
                scanner.scan(link, scanner.load_rules())

    def test_symlink_directory_supplied_as_scan_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            (target / "service.py").write_text("value = 1\n", encoding="utf-8")
            alias = root / "alias"
            self.symlink_or_skip(alias, target, directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                scanner.scan(alias, scanner.load_rules())

    def test_scan_root_leaf_swap_during_canonicalization_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "service.py"
            path.write_text("value = 1\n", encoding="utf-8")
            regular = path.lstat()
            symlink = type("SymlinkMetadata", (), {
                "st_dev": regular.st_dev,
                "st_ino": regular.st_ino,
                "st_mode": stat.S_IFLNK | 0o777,
            })()

            with patch.object(Path, "lstat", side_effect=[regular, symlink]):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    scanner.canonical_scan_root(path)

    def test_diff_report_below_symlinked_ancestor_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            report = real / "report.json"
            report.write_text(json.dumps(scan_report()), encoding="utf-8")
            alias = root / "alias"
            self.symlink_or_skip(alias, real, directory=True)

            loaded = diff.load_report(alias / "report.json")

            self.assertEqual(loaded["findings"], {})
            self.assertFalse(loaded["partial"])

    def test_diff_symlink_leaf_input_remains_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text(json.dumps(scan_report()), encoding="utf-8")
            link = root / "report.json"
            self.symlink_or_skip(link, target)

            with self.assertRaisesRegex(ValueError, "symlink"):
                diff.load_report(link)


class OfflineBundleTests(unittest.TestCase):
    def test_private_ssh_directory_is_ignored(self):
        entries = {
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn(".ssh/", entries)

    def test_offline_bundle_excludes_private_ssh_directory(self):
        self.assertTrue(BUNDLE_BUILDER.is_file(), "required offline bundle builder is missing")
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            fixture = temp_root / "repository"
            base_ignore = shutil.ignore_patterns(
                ".git", ".ssh", "artifacts", "local", "__pycache__", "*.pyc"
            )

            def fixture_ignore(directory, names):
                ignored = set(base_ignore(directory, names))
                # A verified offline extraction has its transport MANIFEST at
                # the root.  It is not a tracked repository file and must not
                # be re-added to the synthetic Git fixture used by this test.
                if (Path(directory).resolve() == ROOT.resolve() and
                        not (ROOT / ".git").exists() and "MANIFEST.json" in names):
                    try:
                        transport = json.loads(
                            (ROOT / "MANIFEST.json").read_text(encoding="utf-8")
                        )
                    except (OSError, ValueError):
                        transport = {}
                    if transport.get("schema") == "durkahelper.offline-bundle.v1":
                        ignored.add("MANIFEST.json")
                return ignored

            shutil.copytree(
                ROOT,
                fixture,
                ignore=fixture_ignore,
            )
            private_dir = fixture / ".ssh"
            private_dir.mkdir()
            (private_dir / "synthetic-private-key").write_text(
                "TEST-ONLY-SECRET-MUST-NOT-BE-BUNDLED\n", encoding="ascii"
            )

            git = shutil.which("git")
            self.assertIsNotNone(git, "git is required to construct the bundle fixture")
            commands = (
                (git, "init", "-q"),
                (git, "add", "-A"),
                (
                    git,
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "user.name=DurkaHelper Tests",
                    "-c",
                    "user.email=tests.invalid@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ),
            )
            for command in commands:
                completed = subprocess.run(
                    command,
                    cwd=fixture,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr.decode("utf-8", "backslashreplace"),
                )

            output = temp_root / "durkahelper-offline.tar.gz"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(fixture / "scripts" / BUNDLE_BUILDER.name),
                    "--output",
                    str(output),
                ],
                cwd=fixture,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", "backslashreplace"),
            )
            self.assertTrue(output.exists(), "bundle builder did not create --output")

            if output.is_dir():
                names = [path.relative_to(output).as_posix() for path in output.rglob("*")]
            elif tarfile.is_tarfile(output):
                with tarfile.open(output, "r:*") as archive:
                    names = archive.getnames()
            elif zipfile.is_zipfile(output):
                with zipfile.ZipFile(output) as archive:
                    names = archive.namelist()
            else:
                self.fail("offline bundle is neither a directory nor a supported archive")

            bundled_ssh_paths = [
                name
                for name in names
                if ".ssh" in PurePosixPath(name.replace("\\", "/")).parts
            ]
            self.assertEqual(bundled_ssh_paths, [])


if __name__ == "__main__":
    unittest.main()
