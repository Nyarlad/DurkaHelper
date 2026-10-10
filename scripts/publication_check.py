#!/usr/bin/env python3
"""Bounded publication hygiene checks. Findings contain locations, never values.

Checks the tracked/non-ignored worktree by default. --history inspects only
commits reachable from explicitly selected --ref values (HEAD by default).
This heuristic gate does not replace manual review of images, CI artifacts,
PR discussions, licenses, or the remote repository's publication settings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading

LIMIT = 8 * 1024 * 1024
MAX_FILES = 20000
PATTERNS = {
    "private-key": re.compile(br"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----"),
    "access-token": re.compile(br"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255}|AKIA[0-9A-Z]{16})\b"),
    "ssh-identity": re.compile(br"\b(?:ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]{40,}={0,3}(?: |$)"),
    "personal-home": re.compile(br"(?:[A-Za-z]:[\\/]Users[\\/](?!Public\b|USER\b|USERNAME\b|example\b)[A-Za-z0-9_.-]+|/Users/(?!USER\b|USERNAME\b|example\b)[A-Za-z0-9_.-]+|/home/(?!USER\b|USERNAME\b|example\b)[A-Za-z0-9_.-]+)"),
    "url-credentials": re.compile(br"\b(?:https?|ssh)://[^\s/:@]{1,100}:[^\s/@]{4,200}@"),
}
FORBIDDEN_PARTS = {".ssh", ".aws", ".gnupg", ".codex-remote-attachments", "local", "artifacts", "upstream", ".git", "secrets"}
FORBIDDEN_SUFFIXES = {".pcap", ".pcapng", ".pem", ".key", ".p12", ".pfx", ".sqlite", ".db", ".log"}
REVIEW_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".tar", ".gz"}


class CheckError(Exception):
    pass


def git(root, *args, limit=LIMIT):
    # No shell, filters, target commands, or network operations.
    command = ["git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(root), *args]
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({"GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment) as process:
        def stop():
            try:
                process.kill()
            except OSError:
                pass
        deadline = threading.Timer(30, stop)
        deadline.daemon = True
        deadline.start()
        try:
            output = process.stdout.read(limit + 1)
            if len(output) > limit:
                raise CheckError("Git output exceeds the publication audit limit")
            if process.wait(timeout=30):
                raise CheckError("Git could not read the selected publication scope")
            return output
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()


def safe_path(value):
    parts = value.split("/")
    if (not value or value.startswith("/") or "\\" in value or ":" in value or
            any(p in {"", ".", ".."} for p in parts) or any(ord(c) < 32 for c in value)):
        raise CheckError("non-portable path in publication scope")
    return value


def finding(path, category, line=0, ref="worktree", fingerprint=None):
    value = {"path": path, "category": category, "line": line, "ref": ref}
    if fingerprint is not None:
        value["fingerprint"] = fingerprint
    return value


def scan_bytes(path, data, ref="worktree", private_terms=()):
    rows = []
    suffix = Path(path).suffix.lower()
    if (set(p.lower() for p in path.split("/")) & FORBIDDEN_PARTS or suffix in FORBIDDEN_SUFFIXES or
            Path(path).name == ".env" or (Path(path).name.startswith(".env.") and Path(path).name != ".env.example")):
        rows.append(finding(path, "private-or-runtime-file", ref=ref))
    if suffix in REVIEW_SUFFIXES or b"\x00" in data:
        rows.append(finding(path, "manual-asset-review", ref=ref))
    for number, line in enumerate(data.splitlines(), 1):
        fingerprint = hashlib.sha256(line).hexdigest()
        for category, pattern in PATTERNS.items():
            if pattern.search(line):
                rows.append(finding(path, category, number, ref, fingerprint))
        if any(term in line for term in private_terms):
            rows.append(finding(path, "private-environment-reference", number, ref, fingerprint))
    return rows


def read_file(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
        raise CheckError("publication input is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        opened = os.fstat(fd)
        if signature(opened) != signature(before) or not stat.S_ISREG(opened.st_mode):
            raise CheckError("publication input changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(LIMIT + 1)
        if len(data) > LIMIT or signature(os.fstat(fd)) != signature(opened) or signature(path.lstat()) != signature(opened):
            raise CheckError("publication input changed while reading")
        return data
    finally:
        os.close(fd)


def audit(root, *, history=False, refs=("HEAD",), max_commits=500, private_terms=(), allowlist=()):
    root = Path(root).resolve(strict=True)
    rows, issues, files = [], [], 0
    seen = set()
    if history:
        if not 1 <= max_commits <= 10000 or not 1 <= len(refs) <= 32:
            raise CheckError("invalid history scope limits")
        resolved = []
        for ref in refs:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,200}", ref):
                raise CheckError("invalid publication ref")
            resolved.append(git(root, "rev-parse", "--verify", ref + "^{commit}").decode("ascii").strip())
        commits = git(root, "rev-list", "--max-count=" + str(max_commits + 1), *resolved).decode("ascii").splitlines()
        if len(commits) > max_commits:
            issues.append("history_commit_limit")
        for commit in commits[:max_commits]:
            entries = git(root, "ls-tree", "-r", "-z", commit).split(b"\x00")
            for entry in filter(None, entries):
                metadata, raw_name = entry.split(b"\t", 1)
                mode, kind, oid = metadata.decode("ascii").split()
                name = safe_path(raw_name.decode("utf-8"))
                if (oid, name) in seen:
                    continue
                seen.add((oid, name))
                if files >= MAX_FILES:
                    issues.append("history_file_limit")
                    break
                files += 1
                if kind != "blob" or mode not in {"100644", "100755"}:
                    rows.append(finding(name, "unreviewed-link-or-submodule", ref=commit))
                    continue
                if int(git(root, "cat-file", "-s", oid)) > LIMIT:
                    issues.append("oversized_history_blob")
                    continue
                rows.extend(scan_bytes(name, git(root, "cat-file", "blob", oid), commit, private_terms))
            if "history_file_limit" in issues:
                break
        scope = {"kind": "selected-history", "refs": resolved, "commits": min(len(commits), max_commits)}
    else:
        names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\x00")
        names = sorted(set(filter(None, names)))
        if len(names) > MAX_FILES:
            issues.append("worktree_file_limit")
        for raw_name in names[:MAX_FILES]:
            name = safe_path(raw_name.decode("utf-8"))
            path = root / name
            files += 1
            if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
                rows.append(finding(name, "unreviewed-link-or-submodule"))
                continue
            try:
                rows.extend(scan_bytes(name, read_file(path), private_terms=private_terms))
            except (CheckError, OSError):
                rows.append(finding(name, "unreadable-or-unstable-input"))
        scope = {"kind": "tracked-and-nonignored-worktree"}
    accepted = set()
    for entry in allowlist:
        if (not isinstance(entry, dict) or set(entry) != {"path", "category", "fingerprint", "reason"} or
                entry["category"] not in PATTERNS or not isinstance(entry["reason"], str) or
                not 10 <= len(entry["reason"]) <= 512 or
                not isinstance(entry["fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"])):
            raise CheckError("allowlist requires exact path, category, line digest and review reason")
        accepted.add((safe_path(entry["path"]), entry["category"], entry["fingerprint"]))
    suppressed = [r for r in rows if (r["path"], r["category"], r.get("fingerprint")) in accepted]
    rows = [r for r in rows if r not in suppressed]
    partial = bool(issues) or any(r["category"] in {"manual-asset-review", "unreadable-or-unstable-input", "unreviewed-link-or-submodule"} for r in rows)
    return {"schema": "durkahelper.publication-check.v1", "scope": scope, "files_checked": files,
            "findings": rows, "issues": sorted(set(issues)), "reviewed_exceptions": len(suppressed),
            "external_surfaces": "NOT_RUN: CI artifacts, PR content, remote refs/settings, asset visual review",
            "exit_code": 2 if partial else 1 if rows else 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--ref", action="append")
    parser.add_argument("--max-commits", type=int, default=500)
    parser.add_argument("--private-denylist", help="ignored local JSON array; never copied into a report")
    parser.add_argument("--allowlist", help="JSON array of exact reviewed synthetic line exceptions")
    args = parser.parse_args(argv)
    try:
        terms = json.loads(read_file(Path(args.private_denylist))) if args.private_denylist else []
        if not isinstance(terms, list) or len(terms) > 256 or any(not isinstance(t, str) or not 4 <= len(t) <= 1024 for t in terms):
            raise CheckError("invalid private denylist")
        allowlist = json.loads(read_file(Path(args.allowlist))) if args.allowlist else []
        if not isinstance(allowlist, list) or len(allowlist) > 1000:
            raise CheckError("invalid reviewed exceptions")
        result = audit(args.root, history=args.history, refs=args.ref or ["HEAD"], max_commits=args.max_commits,
                       private_terms=[t.encode("utf-8") for t in terms], allowlist=allowlist)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return result["exit_code"]
    except (CheckError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": type(exc).__name__, "exit_code": 2, "details": "suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
