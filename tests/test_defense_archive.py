"""Archive API regressions; fixture source is parsed, never executed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("archive_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def signal(self, source):
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertEqual(issues, [])
        return {line for rid, line in hits if rid == "PY-ARCHIVE"}

    def test_tar_single_member_extraction_provenance(self):
        for source in [
            "import tarfile as tf\narchive = tf.open(path)\narchive.extract(member, destination)",
            "from tarfile import TarFile as Archive\narchive = Archive(fileobj=stream)\narchive.extract(member)",
            "import tarfile\narchive = tarfile.TarFile.open(path)\narchive.extract(member)",
            "from tarfile import open as open_tar\nopen_tar(path).extract(member)",
            "import tarfile as tf\nwith tf.open(path) as archive:\n    archive.extract(member, destination)",
            "import tarfile\nwith tarfile.TarFile.open(path) as archive:\n    archive.extract(member)",
        ]:
            with self.subTest(source=source):
                self.assertTrue(self.signal(source))

    def test_callable_data_filter_is_recognized(self):
        for source in [
            "import tarfile\narchive.extractall(destination, filter=tarfile.data_filter)",
            "from tarfile import data_filter as restricted\narchive.extractall(destination, filter=restricted)",
            "import tarfile as tf\nwith tf.open(path) as archive:\n    archive.extract(member, filter=tf.data_filter)",
            "import tarfile\narchive = tarfile.open(path)\narchive.extract(member, filter='data')",
            "import tarfile\narchive.extractall(destination, **{'filter': tarfile.data_filter})",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))
        self.assertTrue(self.signal("import tarfile\narchive=tarfile.open(path)\narchive.extract(member, filter=custom_filter)"))

    def test_tar_unpack_archive_formats(self):
        for archive_format in ("tar", "gztar", "bztar", "xztar", "zstdtar"):
            for source in [
                f"import shutil as sh\nsh.unpack_archive(path, destination, '{archive_format}')",
                f"from shutil import unpack_archive as unpack\nunpack(path, format='{archive_format}')",
                f"import shutil\nfmt='{archive_format}'\nshutil.unpack_archive(path, **{{'format': fmt}})",
            ]:
                with self.subTest(source=source):
                    self.assertTrue(self.signal(source))
        for source in [
            "import shutil\nshutil.unpack_archive(path, format='tar', filter='data')",
            "import shutil\nfrom tarfile import data_filter as safe\nshutil.unpack_archive(path, format='tar', filter=safe)",
            "import shutil\nshutil.unpack_archive(path, format='zip')",
            "import shutil\nshutil.unpack_archive(path)",
            "import shutil\nshutil.unpack_archive(path, format=runtime_format)",
            "custom.unpack_archive(path, format='tar')",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))

    def test_archive_aliases_are_invalidated(self):
        for source in [
            "import tarfile\narchive=tarfile.open(path)\narchive=safe_store\narchive.extract(member)",
            "import tarfile\nwith tarfile.open(path) as archive:\n    pass\narchive.extract(member)",
            "import tarfile\nif condition:\n    archive=tarfile.open(path)\narchive.extract(member)",
            "import tarfile\narchive=tarfile.open(path)\ndef f(archive):\n    archive.extract(member)",
            "import zipfile\nwith zipfile.ZipFile(path) as archive:\n    archive.extract(member)",
            "custom.extract(member)",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))
        # Existing tail heuristic remains deliberately broader than TarFile.
        self.assertTrue(self.signal("import zipfile\nzipfile.ZipFile(path).extractall(destination)"))

    def test_with_does_not_carry_scalar_filter_facts(self):
        source = ("import tarfile\nfilter_name='data'\nwith tarfile.open(path) as archive:\n"
                  "    archive.extract(member, filter=filter_name)")
        self.assertTrue(self.signal(source))

    def test_context_target_shadowing_and_filter_rebinding(self):
        # Counterexamples added after the implementation: the later context
        # target replaces the first one, and a rebound filter is not trusted.
        self.assertFalse(self.signal(
            "import tarfile\nwith tarfile.open(path) as archive, other() as archive:\n"
            "    archive.extract(member)"))
        self.assertTrue(self.signal(
            "from tarfile import data_filter as checked\nchecked=custom_filter\n"
            "archive.extractall(destination, filter=checked)"))
        self.assertFalse(self.signal(
            "import shutil\nshutil.unpack_archive(path, *unknown, 'tar')"))
        self.assertTrue(self.signal(
            "import tarfile\nwith tarfile.open(path) as archive:\n"
            "    with other():\n        pass\n    archive.extract(member)"))

    def test_single_member_report_location_and_contract(self):
        source = ("from tarfile import open as read_tar\nwith read_tar(path) as archive:\n"
                  "    archive.extract(member)\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "archive.py"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["issues"], [])
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual((finding["rule"], finding["path"], finding["line"]),
                         ("PY-ARCHIVE", "archive.py", 3))
        self.assertEqual(finding["doc"], "docs/vulnerabilities/python.md#py-archive")
        self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
