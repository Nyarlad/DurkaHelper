#!/usr/bin/env python3
"""Build an honest offline rule/language coverage ledger from inert fixtures.

Authored before/after examples are not independent cases. Legacy gaps are
reported, not invented; every rule introduced in 1.7.0 requires two distinct
positive and two negative independent sources per claimed language. Expanded
forms opt in per language with coverage_required; legacy gaps stay visible.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SCANNER_SPEC = importlib.util.spec_from_file_location("durkahelper_coverage_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(_SCANNER_SPEC)
_SCANNER_SPEC.loader.exec_module(scanner)


FIXTURES = (ROOT / "tests/fixtures/defense_variants.json",
            ROOT / "tests/fixtures/defense_expansion.json",
            ROOT / "tests/fixtures/defense_boundaries.json")


def build_ledger(rules=None, cases=None, *, run_checks=False):
    rules = scanner.load_rules() if rules is None else rules
    if cases is None:
        cases = []
        for path in FIXTURES:
            data = json.loads(scanner.read_regular(scanner.canonical_scan_root(path), 4 * 1024 * 1024))
            if data.get("schema_version") != 1 or not isinstance(data.get("cases"), list):
                raise ValueError("unsupported fixture contract")
            cases.extend(data["cases"])
    by_id = {rule["id"]: rule for rule in rules}
    seen = set()
    coverage = {(r["id"], lang): {"positive": set(), "negative": set()}
                for r in rules for lang in r["languages"]}
    failures = []
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str)
                or case["id"] in seen or not isinstance(case.get("source"), str)
                or not case["source"] or len(case["source"]) > 1048576
                or not isinstance(case.get("language"), str)):
            raise ValueError("invalid or duplicate fixture")
        seen.add(case["id"])
        expectations = {}
        for source_key, category in (("expected", "positive"), ("forbidden", "negative")):
            values = case.get(source_key)
            if (not isinstance(values, list) or not all(isinstance(value, str) for value in values)
                    or len(values) != len(set(values))):
                raise ValueError("invalid fixture expectations")
            expectations[category] = set(values)
            for rid in values:
                pair = (rid, case["language"])
                if pair not in coverage:
                    raise ValueError("fixture rule/language mismatch")
                # A duplicate or pasted authored example is never extra coverage.
                source = case["source"].strip()
                if source not in {by_id[rid]["before"].strip(), by_id[rid]["after"].strip()}:
                    coverage[pair][category].add(hashlib.sha256(source.encode("utf-8")).hexdigest())
        if (not expectations["positive"] and not expectations["negative"]
                or expectations["positive"] & expectations["negative"]):
            raise ValueError("contradictory or empty fixture expectations")
        if run_checks:
            hits, issues = scanner.scan_text(case["source"], case["language"], rules)
            ids = {rid for rid, _ in hits}
            if expectations["positive"] - ids or expectations["negative"] & ids or issues:
                failures.append(case["id"])
    rows = []
    for (rid, language), counts in sorted(coverage.items()):
        positive, negative = len(counts["positive"]), len(counts["negative"])
        meets_target = positive >= 2 and negative >= 2
        rows.append({"rule": rid, "language": language, "family": by_id[rid]["family"],
                     "engine": by_id[rid]["engine"], "independent_positive": positive,
                     "independent_negative": negative, "meets_independent_target": meets_target,
                     "required_for_release": (by_id[rid].get("introduced") in {"1.7.0", "1.8.0"}
                                              or language in by_id[rid].get("coverage_required", [])),
                     "limitations": by_id[rid]["limitations"]})
    unmet = [{"rule": row["rule"], "language": row["language"]} for row in rows
             if row["required_for_release"] and not row["meets_independent_target"]]
    return {"schema": "durkahelper.scanner-coverage.v1", "scanner_version": scanner.VERSION,
            "rules_sha256": scanner.rules_fingerprint(rules), "rule_count": len(rules),
            "rule_language_pairs": len(rows), "independent_fixture_records": len(cases),
            "authored_examples_counted": False, "checks_executed": run_checks,
            "failing_case_ids": sorted(failures), "unmet_release_pairs": unmet,
            "rows": rows, "exit_code": 1 if failures or unmet else 0}


def main(argv=None):
    scanner.configure_text_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the complete deterministic coverage ledger")
    parser.add_argument("--check", action="store_true", help="also run inert fixture detector checks; no target code is executed")
    args = parser.parse_args(argv)
    try:
        ledger = build_ledger(run_checks=args.check)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, MemoryError) as exc:
        print(json.dumps({"error": "invalid_coverage_input", "type": type(exc).__name__, "exit_code": 2}))
        return 2
    if args.json:
        print(json.dumps(ledger, ensure_ascii=True, indent=2))
    else:
        print(f"Rules: {ledger['rule_count']}; rule/language pairs: {ledger['rule_language_pairs']}; independent records: {ledger['independent_fixture_records']}")
        print("Authored examples excluded. Legacy gaps remain visible; this is not proof of complete vulnerability coverage.")
        print(f"Checks executed: {ledger['checks_executed']}; failed cases: {len(ledger['failing_case_ids'])}; unmet release pairs: {len(ledger['unmet_release_pairs'])}")
    return ledger["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
