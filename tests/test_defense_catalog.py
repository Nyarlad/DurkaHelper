"""Keep the offline rule pack and the human review guide navigable."""
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "vulnerabilities"


class CatalogTests(unittest.TestCase):
    def test_explicit_detection_contracts_match_the_linked_section(self):
        rules = json.loads((ROOT / "rules" / "defense.json").read_text(encoding="utf-8"))["rules"]
        for rule in rules:
            if not rule.get("detection"):
                continue
            with self.subTest(rule=rule["id"]):
                path, anchor = rule["doc"].split("#", 1)
                text = (ROOT / path).read_text(encoding="utf-8")
                section = text.split(f'<a id="{anchor}"></a>', 1)[1].split("\n<a id=", 1)[0]
                self.assertIn(rule["detection"], section)

    def test_readme_and_index_counts_match_real_rules_and_sections(self):
        rule_ids = {rule["id"] for rule in json.loads(
            (ROOT / "rules" / "defense.json").read_text(encoding="utf-8"))["rules"]}
        sections = {}
        for path in CATALOG.glob("*.md"):
            if path.name != "README.md" and not path.stem.endswith("-RU"):
                sections[path.resolve()] = re.findall(r"^## ([A-Z][A-Z0-9-]+)\. ",
                                                      path.read_text(encoding="utf-8"), re.M)
        total_sections = sum(len(ids) for ids in sections.values())
        for path in (ROOT / "README.md", CATALOG / "README.md"):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                summary = re.search(r"\*\*(\d+) sections, (\d+) scanner rules", text)
                self.assertIsNotNone(summary)
                self.assertEqual(tuple(map(int, summary.groups())), (total_sections, len(rule_ids)))
                rows = re.findall(r"^\| \[[^\]]+\]\(([^)]+\.md)\) \| (\d+) \|$", text, re.M)
                table = {(path.parent / target).resolve(): int(count) for target, count in rows}
                self.assertEqual(set(table), set(sections))
                for target, count in table.items():
                    self.assertEqual(count, len(sections[target]), target)
        index = (CATALOG / "README.md").read_text(encoding="utf-8")
        coverage = re.search(r"(\d+) automatic signals and (\d+) manual-only sections", index)
        self.assertIsNotNone(coverage)
        manual_count = sum(rid not in rule_ids for ids in sections.values() for rid in ids)
        self.assertEqual(tuple(map(int, coverage.groups())), (len(rule_ids), manual_count))
        rules = json.loads((ROOT / "rules/defense.json").read_text(encoding="utf-8"))["rules"]
        records = sum(len(json.loads((ROOT / "tests/fixtures" / name).read_text(encoding="utf-8"))["cases"])
                      for name in ("defense_variants.json", "defense_expansion.json", "defense_boundaries.json"))
        development = (ROOT / "docs/development.md").read_text(encoding="utf-8")
        inventory = re.search(r"Current inventory: (\d+) rules, (\d+) rule-language pairs and (\d+) independent fixture records", development)
        self.assertIsNotNone(inventory)
        self.assertEqual(tuple(map(int, inventory.groups())),
                         (len(rules), sum(len(rule["languages"]) for rule in rules), records))

    def test_rule_links_reach_matching_sections(self):
        rules = json.loads((ROOT / "rules" / "defense.json").read_text(encoding="utf-8"))["rules"]
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                path, anchor = rule["doc"].split("#", 1)
                self.assertTrue(path.startswith("docs/vulnerabilities/"))
                text = (ROOT / path).read_text(encoding="utf-8")
                self.assertIn(f'<a id="{anchor}"></a>', text)
                self.assertIn(f"## {rule['id']}. ", text)
                self.assertIn(f"rule {rule['id']}.", text)

    def test_every_section_has_search_fix_and_verification(self):
        ids = set()
        for path in CATALOG.glob("*.md"):
            if path.name == "README.md" or path.stem.endswith("-RU"):
                continue
            text = path.read_text(encoding="utf-8")
            sections = re.findall(
                r'^## ([A-Z][A-Z0-9-]+)\. ([\s\S]*?)(?=^<a id=|\Z)', text, re.M)
            self.assertTrue(sections, path)
            for rid, body in sections:
                with self.subTest(rule=rid):
                    self.assertNotIn(rid, ids)
                    ids.add(rid)
                    for field in ("**Search:**", "**Vulnerable example:**",
                                  "**Fix:**", "**Verification:**"):
                        self.assertIn(field, body)
                    if "no separate scanner rule" in body:
                        self.assertIn("rg -n ", body)
                        self.assertRegex(body, r"~~~\n\n\S")
        self.assertGreater(len(ids), 100)

    @unittest.skipUnless(shutil.which("rg"), "manual search validation requires ripgrep")
    def test_manual_searches_are_valid_read_only_rg_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Only run documented rg argv, on an inert empty fixture.
            Path(tmp, "empty.txt").write_text("")
            for path in CATALOG.glob("*.md"):
                for command in re.findall(r"^rg -n .+$", path.read_text(encoding="utf-8"), re.M):
                    argv = shlex.split(command)
                    self.assertEqual(argv[0], "rg")
                    self.assertIn("-e", argv)
                    self.assertEqual(argv[-1], ".")
                    self.assertNotIn("--pre", argv)
                    proc = subprocess.run(argv, cwd=tmp, capture_output=True, timeout=2)
                    self.assertIn(proc.returncode, (0, 1), (path, command, proc.stderr))

    def test_local_markdown_links_exist(self):
        paths = [*ROOT.glob("*.md")]
        for directory in ("docs", "lab", "integration", "deployment", ".github"):
            paths.extend((ROOT / directory).rglob("*.md"))
        for path in paths:
            source = self._without_fences(path.read_text(encoding="utf-8"))
            targets = re.findall(r"\]\(([^)]+)\)", source)
            targets.extend(re.findall(r"^\s*\[[^\]]+\]:\s*(\S+)", source, re.M))
            for raw_target in targets:
                target = raw_target.strip().split(' "', 1)[0].strip("<>")
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc:
                    continue
                file_part = unquote(parsed.path)
                anchor = unquote(parsed.fragment)
                dest = ((ROOT / file_part.lstrip("/")) if file_part.startswith("/")
                        else (path.parent / file_part) if file_part else path).resolve()
                self.assertTrue(dest.is_relative_to(ROOT), (path, target))
                self.assertTrue(dest.is_file(), (path, target))
                if anchor and dest.suffix.lower() == ".md":
                    self.assertIn(anchor, self._anchors(dest.read_text(encoding="utf-8")),
                                  (path, target))

    @staticmethod
    def _without_fences(text):
        return re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1\s*$", "", text)

    @classmethod
    def _anchors(cls, text):
        text = cls._without_fences(text)
        anchors = set(re.findall(r'<(?:a|h[1-6])\s+[^>]*id=[\"\']([^\"\']+)', text))
        seen = {}
        for heading in re.findall(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", text, re.M):
            heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
            heading = re.sub(r"<[^>]*>", "", heading).lower()
            slug = re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")
            occurrence = seen.get(slug, 0)
            seen[slug] = occurrence + 1
            anchors.add(slug if not occurrence else f"{slug}-{occurrence}")
        return anchors

    @staticmethod
    def _markdown_paths():
        paths = [*ROOT.glob("*.md")]
        for directory in ("docs", "lab", "integration", "deployment", ".github"):
            paths.extend((ROOT / directory).rglob("*.md"))
        return paths

    def test_primary_markdown_prose_is_english(self):
        for path in self._markdown_paths():
            if path.stem.endswith("-RU"):
                continue
            prose = self._without_fences(path.read_text(encoding="utf-8"))
            # The language switch is the only Russian text in an English page.
            prose = re.sub(r"^English \| \[Русский\]\([^\n]+\)\s*$", "", prose, flags=re.M)
            self.assertNotRegex(prose, r"[\u0400-\u04ff]", str(path.relative_to(ROOT)))

    def test_every_markdown_page_has_a_russian_pair_and_language_switch(self):
        paths = self._markdown_paths()
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                if path.stem.endswith("-RU"):
                    source = path.with_name(path.stem[:-3] + ".md")
                    self.assertTrue(source.is_file(), "orphan Russian translation")
                    continue
                translated = path.with_name(path.stem + "-RU.md")
                self.assertTrue(translated.is_file(), "missing Russian translation")
                en = path.read_text(encoding="utf-8")
                ru = translated.read_text(encoding="utf-8")
                self.assertTrue(f"English | [Русский]({translated.name})" in en, "missing English-to-Russian switch")
                self.assertTrue(f"[English]({path.name}) | Русский" in ru, "missing Russian-to-English switch")
                self.assertRegex(self._without_fences(ru), r"[А-Яа-яЁё]")

    def test_russian_pairs_preserve_executable_examples_and_navigation(self):
        fences = re.compile(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$")
        for path in self._markdown_paths():
            if path.stem.endswith("-RU"):
                continue
            with self.subTest(path=path.relative_to(ROOT)):
                translated = path.with_name(path.stem + "-RU.md")
                en = path.read_text(encoding="utf-8")
                ru = translated.read_text(encoding="utf-8")
                self.assertEqual([m[0] for m in fences.finditer(en)],
                                 [m[0] for m in fences.finditer(ru)],
                                 "commands and code examples must not change in translation")
                self.assertTrue(self._anchors(en) <= self._anchors(ru),
                                "preserve original section anchors in the translation")
                for target in re.findall(r"\]\(([^)]+)\)", self._without_fences(ru)):
                    parsed = urlsplit(target)
                    if parsed.scheme or parsed.netloc or not parsed.path.endswith(".md"):
                        continue
                    dest = (translated.parent / unquote(parsed.path)).resolve()
                    self.assertTrue(dest == path.resolve() or dest.stem.endswith("-RU"),
                                    "Russian navigation must stay in Russian except the English switch")

    def test_russian_catalog_keeps_all_sections_and_review_fields(self):
        for path in CATALOG.glob("*-RU.md"):
            if path.name == "README-RU.md":
                continue
            with self.subTest(path=path.name):
                en = path.with_name(path.stem[:-3] + ".md").read_text(encoding="utf-8")
                ru = path.read_text(encoding="utf-8")
                pattern = r"^## ([A-Z][A-Z0-9-]+)\. "
                self.assertEqual(re.findall(pattern, en, re.M), re.findall(pattern, ru, re.M))
                sections = re.findall(r"^## ([A-Z][A-Z0-9-]+)\. ([\s\S]*?)(?=^## |\Z)", ru, re.M)
                for rid, body in sections:
                    for field in ("**Поиск:**", "**Уязвимый вариант:**", "**Исправление:**", "**Проверка:**"):
                        self.assertIn(field, body, rid)

    def test_russian_catalog_indexes_keep_canonical_counts(self):
        for path in (ROOT / "README.md", CATALOG / "README.md"):
            with self.subTest(path=path.relative_to(ROOT)):
                en = path.read_text(encoding="utf-8")
                ru = path.with_name("README-RU.md").read_text(encoding="utf-8")
                canonical = re.search(r"\*\*(\d+) sections, (\d+) scanner rules", en)
                translated = re.search(r"\*\*(\d+) раздел[а-я]+, (\d+) правил[а-я ]*сканера", ru)
                self.assertIsNotNone(translated)
                self.assertEqual(canonical.groups(), translated.groups())
                row = r"^\| \[[^\]]+\]\(([^)]+\.md)\) \| (\d+) \|$"
                english_rows = re.findall(row, en, re.M)
                russian_rows = [(target.replace("-RU.md", ".md"), count)
                                for target, count in re.findall(row, ru, re.M)]
                self.assertEqual(english_rows, russian_rows)


if __name__ == "__main__":
    unittest.main()
