"""Determinism, integrity, and secret-exclusion tests for offline bundles."""
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BUILDER_NAME = "build_offline_bundle.py"
BUILDER = ROOT / "scripts" / BUILDER_NAME
SPEC = importlib.util.spec_from_file_location("offline_bundle_builder_under_test", BUILDER)
bundle_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle_builder)


class OfflineBundleTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="qa-bundle-", dir=scratch)
        self.addCleanup(self._temporary.cleanup)
        self.temp = Path(self._temporary.name)
        self.git = shutil.which("git")
        self.assertIsNotNone(self.git, "Git is required by the offline bundle contract")
        self.assertTrue(BUILDER.is_file(), "offline bundle builder is missing")

    def execute(self, *command, cwd=None, env=None, timeout=60):
        return subprocess.run(
            [str(part) for part in command], cwd=cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )

    def git_run(self, repo, *args, check=True):
        completed = self.execute(self.git, *args, cwd=repo, timeout=30)
        if check:
            self.assertEqual(
                completed.returncode, 0,
                completed.stderr.decode("utf-8", "backslashreplace"),
            )
        return completed

    def commit(self, repo, message="fixture"):
        environment = os.environ.copy()
        environment.update({
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        })
        completed = self.execute(
            self.git, "-c", "commit.gpgsign=false", "-c", "user.name=DurkaHelper Tests",
            "-c", "user.email=tests.invalid@example.invalid", "commit", "-q", "-m", message,
            cwd=repo, env=environment, timeout=30,
        )
        self.assertEqual(
            completed.returncode, 0,
            completed.stderr.decode("utf-8", "backslashreplace"),
        )

    def make_repo(self, name="repository"):
        repo = self.temp / name
        (repo / "scripts").mkdir(parents=True)
        shutil.copy2(BUILDER, repo / "scripts" / BUILDER_NAME)
        shutil.copy2(ROOT / ".gitignore", repo / ".gitignore")
        (repo / "README.md").write_text("# Synthetic offline bundle fixture\n", encoding="utf-8")
        (repo / "docs").mkdir()
        (repo / "docs" / "guide.md").write_text("Synthetic guide.\n", encoding="utf-8")
        self.git_run(repo, "init", "-q")
        self.git_run(repo, "add", "-A")
        self.commit(repo)
        return repo

    def builder(self, repo, *args):
        return self.execute(sys.executable, repo / "scripts" / BUILDER_NAME, *args, cwd=repo)

    def build(self, repo, output):
        return self.builder(repo, "--output", output)

    def verify(self, repo, archive):
        return self.builder(repo, "--verify", archive)

    def assert_exit(self, completed, expected):
        stderr = completed.stderr.decode("utf-8", "backslashreplace")
        self.assertEqual(completed.returncode, expected, stderr)
        return completed.stdout.decode("utf-8", "strict")

    def archive_names(self, archive):
        with tarfile.open(archive, "r:gz") as bundle:
            return bundle.getnames()

    def remove_sidecar(self, archive):
        Path(str(archive) + ".sha256").unlink()

    def gzip_bytes(self, payload, mtime=0):
        output = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=output,
                           compresslevel=9, mtime=mtime) as compressed:
            compressed.write(payload)
        return output.getvalue()

    def require_hardlinks(self):
        source = self.temp / "hardlink-probe-source"
        target = self.temp / "hardlink-probe-target"
        source.write_bytes(b"probe")
        try:
            os.link(source, target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard links are unavailable: {type(exc).__name__}")
        finally:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            source.unlink()

    def test_clean_repo_build_is_deterministic_verified_and_excludes_untracked(self):
        repo = self.make_repo()
        (repo / "untracked.txt").write_text("must not be included\n", encoding="utf-8")
        (repo / ".ssh").mkdir()
        (repo / ".ssh" / "synthetic-private-key").write_text(
            "TEST-ONLY-MATERIAL-MUST-NOT-BE-BUNDLED\n", encoding="ascii"
        )
        (repo / "local").mkdir()
        (repo / "local" / "runtime.log").write_text("not bundled\n", encoding="utf-8")
        first = self.temp / "first.tar.gz"
        second = self.temp / "second.tar.gz"

        self.assert_exit(self.build(repo, first), 0)
        self.assert_exit(self.build(repo, second), 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(),
                         first.with_suffix(first.suffix + ".sha256").read_text(
                             encoding="utf-8").split()[0])
        for archive in (first, second):
            output = self.assert_exit(self.verify(repo, archive), 0)
            self.assertIn('"status": "verified"', output)
            names = self.archive_names(archive)
            relative = [PurePosixPath(name).parts[1:] for name in names[1:]]
            flattened = ["/".join(parts) for parts in relative]
            self.assertNotIn("untracked.txt", flattened)
            self.assertFalse(any(".ssh" in parts for parts in relative))
            self.assertFalse(any("local" in parts for parts in relative))

    def test_dirty_tracked_worktree_and_index_are_rejected_without_output(self):
        worktree = self.make_repo("dirty-worktree")
        (worktree / "README.md").write_text("modified\n", encoding="utf-8")
        worktree_output = self.temp / "dirty-worktree.tar.gz"
        self.assert_exit(self.build(worktree, worktree_output), 2)
        self.assertFalse(worktree_output.exists())
        self.assertFalse(Path(str(worktree_output) + ".sha256").exists())

        index = self.make_repo("dirty-index")
        (index / "staged.txt").write_text("staged\n", encoding="utf-8")
        self.git_run(index, "add", "staged.txt")
        index_output = self.temp / "dirty-index.tar.gz"
        self.assert_exit(self.build(index, index_output), 2)
        self.assertFalse(index_output.exists())
        self.assertFalse(Path(str(index_output) + ".sha256").exists())

    def test_existing_archive_or_sidecar_is_never_overwritten(self):
        repo = self.make_repo()
        existing_archive = self.temp / "existing-archive.tar.gz"
        existing_archive.write_bytes(b"KEEP-ARCHIVE")
        self.assert_exit(self.build(repo, existing_archive), 2)
        self.assertEqual(existing_archive.read_bytes(), b"KEEP-ARCHIVE")
        self.assertFalse(Path(str(existing_archive) + ".sha256").exists())

        existing_sidecar_archive = self.temp / "existing-sidecar.tar.gz"
        sidecar = Path(str(existing_sidecar_archive) + ".sha256")
        sidecar.write_bytes(b"KEEP-SIDECAR")
        self.assert_exit(self.build(repo, existing_sidecar_archive), 2)
        self.assertFalse(existing_sidecar_archive.exists())
        self.assertEqual(sidecar.read_bytes(), b"KEEP-SIDECAR")

    def test_publish_race_never_overwrites_competing_archive(self):
        self.require_hardlinks()
        archive_temporary = self.temp / "archive-temporary"
        sidecar_temporary = self.temp / "sidecar-temporary"
        output = self.temp / "race-output.tar.gz"
        sidecar = Path(str(output) + ".sha256")
        archive_temporary.write_bytes(b"PRIVATE-ARCHIVE-TEMPORARY")
        sidecar_temporary.write_bytes(b"PRIVATE-SIDECAR-TEMPORARY")
        real_link = os.link

        def race_link(source, destination, *args, **kwargs):
            destination = Path(destination)
            if destination == output:
                output.write_bytes(b"COMPETING-ARCHIVE")
                raise FileExistsError("synthetic publish race")
            return real_link(source, destination, *args, **kwargs)

        with patch.object(bundle_builder.os, "link", side_effect=race_link):
            with self.assertRaises(bundle_builder.BundleError):
                bundle_builder._publish_pair(
                    archive_temporary, output, sidecar_temporary, sidecar
                )

        self.assertEqual(output.read_bytes(), b"COMPETING-ARCHIVE")
        self.assertFalse(sidecar.exists(), "only this publisher's sidecar link may be rolled back")
        self.assertEqual(archive_temporary.read_bytes(), b"PRIVATE-ARCHIVE-TEMPORARY")
        self.assertEqual(sidecar_temporary.read_bytes(), b"PRIVATE-SIDECAR-TEMPORARY")

    def test_archive_tamper_and_sidecar_mismatch_are_rejected(self):
        repo = self.make_repo()
        tampered = self.temp / "tampered.tar.gz"
        self.assert_exit(self.build(repo, tampered), 0)
        data = bytearray(tampered.read_bytes())
        data[len(data) // 2] ^= 1
        tampered.write_bytes(data)
        result = self.verify(repo, tampered)
        self.assert_exit(result, 2)
        self.assertIn("checksum", result.stderr.decode("utf-8", "backslashreplace"))

        mismatch = self.temp / "mismatch.tar.gz"
        self.assert_exit(self.build(repo, mismatch), 0)
        Path(str(mismatch) + ".sha256").write_text(
            "0" * 64 + "  " + mismatch.name + "\n", encoding="utf-8"
        )
        result = self.verify(repo, mismatch)
        self.assert_exit(result, 2)
        self.assertIn("checksum", result.stderr.decode("utf-8", "backslashreplace"))

    def test_verify_rejects_raw_append_concatenated_gzip_and_nonzero_post_eoa(self):
        repo = self.make_repo()

        raw_append = self.temp / "raw-append.tar.gz"
        self.assert_exit(self.build(repo, raw_append), 0)
        self.remove_sidecar(raw_append)
        raw_append.write_bytes(raw_append.read_bytes() + b"RAW-TRAILER")
        result = self.verify(repo, raw_append)
        self.assert_exit(result, 2)
        self.assertIn("trailing gzip data", result.stderr.decode("utf-8", "backslashreplace"))

        concatenated = self.temp / "concatenated.tar.gz"
        self.assert_exit(self.build(repo, concatenated), 0)
        self.remove_sidecar(concatenated)
        concatenated.write_bytes(concatenated.read_bytes() + self.gzip_bytes(b"second-member"))
        result = self.verify(repo, concatenated)
        self.assert_exit(result, 2)
        self.assertIn("concatenated", result.stderr.decode("utf-8", "backslashreplace"))

        post_eoa = self.temp / "post-eoa.tar.gz"
        self.assert_exit(self.build(repo, post_eoa), 0)
        self.remove_sidecar(post_eoa)
        original = post_eoa.read_bytes()
        commit_time = int.from_bytes(original[4:8], "little")
        tar_payload = gzip.decompress(original)
        post_eoa.write_bytes(self.gzip_bytes(tar_payload + b"X" * tarfile.BLOCKSIZE,
                                             mtime=commit_time))
        result = self.verify(repo, post_eoa)
        self.assert_exit(result, 2)
        self.assertRegex(result.stderr.decode("utf-8", "backslashreplace"),
                         r"canonical tar|data after")

    def test_assume_unchanged_and_skip_worktree_flags_are_rejected(self):
        flags = ("--assume-unchanged", "--skip-worktree")
        for flag in flags:
            with self.subTest(flag=flag):
                name = flag.removeprefix("--").replace("-", "_")
                repo = self.make_repo("flag-" + name)
                completed = self.git_run(repo, "update-index", flag, "README.md", check=False)
                if completed.returncode != 0:
                    self.skipTest(f"Git does not support {flag} in this environment")
                (repo / "README.md").write_text("hidden modification\n", encoding="utf-8")
                listing = self.git_run(repo, "ls-files", "-v", "README.md").stdout
                self.assertNotEqual(listing[:2], b"H ")
                output = self.temp / f"flag-{name}.tar.gz"

                result = self.build(repo, output)

                self.assert_exit(result, 2)
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".sha256").exists())
                self.assertIn("special tracked-file flags",
                              result.stderr.decode("utf-8", "backslashreplace"))

    def test_forbidden_tracked_ssh_secret_and_private_key_material_are_rejected(self):
        cases = (
            ("ssh", ".ssh/id_ed25519", b"synthetic\n"),
            ("attachment", ".codex-remote-attachments/screenshot.png", b"synthetic\n"),
            ("secret", "config/token.secret", b"synthetic\n"),
            ("private-key", "docs/example.txt",
             b"-----BEGIN " + b"PRIVATE KEY-----\nsynthetic\n"),
        )
        for name, relative, payload in cases:
            with self.subTest(name=name):
                repo = self.make_repo("forbidden-" + name)
                path = repo / PurePosixPath(relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                self.git_run(repo, "add", "-f", relative)
                self.commit(repo, "forbidden fixture")
                output = self.temp / f"forbidden-{name}.tar.gz"
                result = self.build(repo, output)
                self.assert_exit(result, 2)
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".sha256").exists())
                self.assertNotIn("synthetic", result.stderr.decode("utf-8", "backslashreplace"))

    def write_unsafe_archive(self, path, member_kind):
        root_name = "DurkaHelper-0123456789ab"
        with path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    root = tarfile.TarInfo(root_name)
                    root.type = tarfile.DIRTYPE
                    root.mode = 0o755
                    root.mtime = 0
                    root.uid = root.gid = 0
                    root.uname = root.gname = ""
                    archive.addfile(root)
                    if member_kind == "traversal":
                        member = tarfile.TarInfo(root_name + "/../escape.txt")
                        member.type = tarfile.REGTYPE
                        member.mode = 0o644
                        member.size = 1
                        payload = io.BytesIO(b"x")
                    else:
                        member = tarfile.TarInfo(root_name + "/link")
                        member.type = tarfile.SYMTYPE
                        member.mode = 0o777
                        member.linkname = "../escape.txt"
                        payload = None
                    member.mtime = 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    archive.addfile(member, payload)

    def test_verify_rejects_traversal_and_link_members(self):
        repo = self.make_repo()
        for kind in ("traversal", "symlink"):
            with self.subTest(kind=kind):
                archive = self.temp / f"unsafe-{kind}.tar.gz"
                self.write_unsafe_archive(archive, kind)
                result = self.verify(repo, archive)
                self.assert_exit(result, 2)
                self.assertFalse((self.temp / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
