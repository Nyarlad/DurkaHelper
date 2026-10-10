#!/usr/bin/env python3
"""Compare two saved defense_scan JSON reports offline; never open source paths."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 100000
SCOPE_SCHEMA = "durkahelper.scanner-scope.v2"
LEGACY_SCOPE_SCHEMA = "durkahelper.scanner-scope.v1"
PATH_SEMANTICS = "root-relative-posix.v1"
NOTE = ("Matches exact path, line and rule ID without comparing source code. Moving lines creates a "
        "new/not-observed pair. A disappearing signal does not prove a fix. "
        "A clean comparison requires identical verified scopes.")


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, getattr(metadata, "st_ctime_ns", 0))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("invalid timestamp")
    return value


def _positive_integer(value):
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ValueError("invalid scope integer")
    return value


def validate_scope(scope):
    expected = {"schema", "root", "rules_sha256", "exclude", "limits",
                "path_semantics", "sha256"}
    if not isinstance(scope, dict):
        raise ValueError("invalid scope")
    if scope.get("schema") == SCOPE_SCHEMA:
        expected |= {"semantic_revision", "context_sha256"}
    if set(scope) != expected:
        raise ValueError("invalid scope")
    if (not isinstance(scope["schema"], str)
            or scope["schema"] not in {SCOPE_SCHEMA, LEGACY_SCOPE_SCHEMA}
            or scope["path_semantics"] != PATH_SEMANTICS):
        raise ValueError("unsupported scope")
    if not isinstance(scope["root"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", scope["root"]):
        raise ValueError("invalid root identity")
    if not isinstance(scope["rules_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", scope["rules_sha256"]):
        raise ValueError("invalid rules scope")
    exclude = scope["exclude"]
    if (not isinstance(exclude, list) or len(exclude) > 10000
            or any(not isinstance(item, str) or len(item) > 4096 or "\x00" in item
                   for item in exclude)
            or exclude != sorted(set(exclude))):
        raise ValueError("invalid exclusions scope")
    limits = scope["limits"]
    if not isinstance(limits, dict) or set(limits) != {"max_bytes", "max_files", "max_findings"}:
        raise ValueError("invalid limits scope")
    for field in ("max_bytes", "max_files", "max_findings"):
        _positive_integer(limits[field])
    if not isinstance(scope["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", scope["sha256"]):
        raise ValueError("invalid scope digest")
    sanitized = {
        "schema": scope["schema"],
        "root": scope["root"],
        "rules_sha256": scope["rules_sha256"],
        "exclude": list(exclude),
        "limits": {field: limits[field] for field in
                   ("max_bytes", "max_files", "max_findings")},
        "path_semantics": PATH_SEMANTICS,
    }
    if scope["schema"] == SCOPE_SCHEMA:
        if (scope["semantic_revision"] not in {"bounded-source-signals.v2", "bounded-source-signals.v3"}
                or not isinstance(scope["context_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", scope["context_sha256"])):
            raise ValueError("invalid scanner semantics or context digest")
        sanitized.update(semantic_revision=scope["semantic_revision"], context_sha256=scope["context_sha256"])
    expected_digest = hashlib.sha256(_canonical_json(sanitized)).hexdigest()
    if scope["sha256"] != expected_digest:
        raise ValueError("scope digest mismatch")
    sanitized["sha256"] = expected_digest
    return sanitized


def load_report(filename, max_bytes=MAX_REPORT_BYTES):
    requested = Path(os.path.abspath(filename))
    requested_metadata = requested.lstat()
    if stat.S_ISLNK(requested_metadata.st_mode):
        raise ValueError("symlink report")
    # Resolve ordinary symlinked ancestors (notably macOS /tmp -> /private/tmp)
    # before the no-follow leaf open.  This prevents an ancestor swap from
    # redirecting the descriptor while preserving the leaf-symlink boundary.
    # Path.resolve() may require extra handle permissions on Windows.  The
    # macOS/Linux branch canonicalizes ancestors; Windows retains the absolute
    # path after the explicit leaf-symlink check.
    path = requested if os.name == "nt" else requested.parent.resolve(strict=True) / requested.name
    canonical_metadata = path.lstat()
    if stat.S_ISLNK(canonical_metadata.st_mode):
        raise ValueError("symlink report")
    if ((requested_metadata.st_dev, requested_metadata.st_ino,
         stat.S_IFMT(requested_metadata.st_mode)) !=
            (canonical_metadata.st_dev, canonical_metadata.st_ino,
             stat.S_IFMT(canonical_metadata.st_mode))):
        raise ValueError("report changed before reading")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError("report is not a bounded regular file")
        if ((canonical_metadata.st_dev, canonical_metadata.st_ino,
             stat.S_IFMT(canonical_metadata.st_mode)) !=
                (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))):
            raise ValueError("report changed before reading")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        if len(raw) > max_bytes:
            raise ValueError("report too large")
        if file_identity(metadata) != file_identity(after) or len(raw) != metadata.st_size:
            raise ValueError("report changed while reading")
    finally:
        os.close(fd)
    data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
    return validate_report(data)


def validate_report(data):
    if not isinstance(data, dict) or data.get("tool") != "DurkaHelper defense_scan":
        raise ValueError("not a scanner report")
    if data.get("offline") is not True or type(data.get("partial")) is not bool:
        raise ValueError("invalid report status")
    version = data.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,63}", version):
        raise ValueError("invalid version")
    if type(data.get("exit_code")) is not int or data["exit_code"] not in (0, 1, 2):
        raise ValueError("invalid exit code")
    scope = data.get("scope")
    created_at = data.get("created_at")
    if scope is None:
        if created_at is not None:
            _timestamp(created_at)
    else:
        if created_at is None:
            raise ValueError("scoped report has no timestamp")
        _timestamp(created_at)
        scope = validate_scope(scope)
    issues = data.get("issues")
    findings = data.get("findings")
    if not isinstance(issues, list) or not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise ValueError("invalid collections")
    indexed = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid finding")
        path, line, rule = (finding.get(field) for field in ("path", "line", "rule"))
        if not isinstance(path, str) or not 1 <= len(path) <= 4096 or "\x00" in path:
            raise ValueError("invalid path")
        if type(line) is not int or not 1 <= line <= 2**63 - 1:
            raise ValueError("invalid line")
        if not isinstance(rule, str) or not re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", rule) or len(rule) > 100:
            raise ValueError("invalid rule ID")
        key = (path, line, rule)
        if key in indexed:
            raise ValueError("duplicate finding")
        # Do not copy source text, patches, arbitrary descriptions or issue payloads.
        indexed[key] = {"path": path, "line": line, "rule": rule}
    return {"version": version, "created_at": created_at, "scope": scope,
            "scope_sha256": scope["sha256"] if scope is not None else None,
            "partial": data["partial"] or bool(issues) or data["exit_code"] == 2,
            "issue_count": len(issues), "findings": indexed}


def compare_reports(before, after):
    old, new = before["findings"], after["findings"]
    warnings = []
    if before["partial"]:
        warnings.append("before_partial")
    if after["partial"]:
        warnings.append("after_partial")
    if before["version"] != after["version"]:
        warnings.append("scanner_version_changed")
    if before["scope"] is None or after["scope"] is None:
        warnings.append("scope_unverified")
    elif before["scope"] != after["scope"]:
        warnings.append("scope_changed")
    scope_verified = before["scope"] is not None and before["scope"] == after["scope"]
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    existing = [new[key] for key in sorted(new.keys() & old.keys())]
    absent = [old[key] for key in sorted(old.keys() - new.keys())]
    return {"tool": "DurkaHelper defense_diff", "offline": True,
            "matching": ["path", "line", "rule"], "scope_verified": scope_verified,
            "before": {"version": before["version"], "partial": before["partial"],
                       "issue_count": before["issue_count"],
                       "scope_sha256": before["scope_sha256"]},
            "after": {"version": after["version"], "partial": after["partial"],
                      "issue_count": after["issue_count"],
                      "scope_sha256": after["scope_sha256"]},
            "new": added, "existing": existing, "not_observed": absent,
            "counts": {"new": len(added), "existing": len(existing), "not_observed": len(absent)},
            "warnings": warnings, "partial": bool(warnings), "note": NOTE,
            "exit_code": 2 if warnings else 1 if added else 0}


def printable(value):
    return str(value) if str(value).isprintable() else json.dumps(str(value), ensure_ascii=True)


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def configure_text_output():
    """Keep CLI diagnostics printable on legacy Windows code pages."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (AttributeError, OSError, ValueError):
                pass


def main(argv=None):
    configure_text_output()
    parser = argparse.ArgumentParser(description="Compare two defense_scan JSON reports without reading source files.")
    parser.add_argument("before", help="previous JSON report")
    parser.add_argument("after", help="current JSON report")
    parser.add_argument("--json", action="store_true", help="structured JSON result")
    parser.add_argument("--show-existing", action="store_true", help="also show unchanged signals in text output")
    parser.add_argument("--max-bytes", type=positive, default=MAX_REPORT_BYTES, help="size limit for each report; default 32 MiB")
    args = parser.parse_args(argv)
    try:
        report = compare_reports(load_report(args.before, args.max_bytes), load_report(args.after, args.max_bytes))
    except (OSError, ValueError, OverflowError, RecursionError, MemoryError) as exc:
        # Exception messages can contain report contents, paths or secret fields.
        error = {"error": "invalid_or_unreadable_report", "type": type(exc).__name__, "exit_code": 2}
        print(json.dumps(error) if args.json else "ERROR: invalid or unreadable report (" + type(exc).__name__ + ").")
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        for field, label in (("new", "NEW"), ("not_observed", "NOT OBSERVED"), ("existing", "EXISTING")):
            if field == "existing" and not args.show_existing:
                continue
            for finding in report[field]:
                print(f"{label}: {printable(finding['path'])}:{finding['line']} [{finding['rule']}]")
        counts = report["counts"]
        print(f"New: {counts['new']}; existing: {counts['existing']}; not observed: {counts['not_observed']}.")
        if report["warnings"]:
            descriptions = {"before_partial": "previous scan is partial",
                            "after_partial": "current scan is partial",
                            "scanner_version_changed": "scanner versions differ",
                            "scope_unverified": "scope is missing or unverified",
                            "scope_changed": "report scopes differ"}
            print("Incomplete comparison: " + ", ".join(descriptions[item] for item in report["warnings"]))
        print(NOTE)
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
