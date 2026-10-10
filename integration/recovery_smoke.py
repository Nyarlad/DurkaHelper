#!/usr/bin/env python3
"""Opt-in native PostgreSQL recovery drill for the synthetic S4DFarm fixture.

No production database, overwrite restore, volume deletion or host package
installation is supported. The original fixture must be stopped. Every restore
uses a new isolated database; dump, source and restored data are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading
import time

SPEC = importlib.util.spec_from_file_location("recovery_stack", Path(__file__).with_name("stack_smoke.py"))
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
FixtureError = shared.FixtureError
SCHEMA = "durkahelper.postgres-recovery.v1"
MAX_DUMP = 8 * 1024 * 1024
MAX_ROWS = 1000
STATE_KEYS = {"schema", "project", "source_project", "source_workspace", "postgres_image", "approval_id"}
NOT_VALIDATED = ["Redis recovery", "Neo application state recovery", "Packmate recovery", "production restore",
                 "whole-VM restore", "failure injection", "RPO/RTO target", "Apple Silicon", "Docker Desktop"]


def read_json(path):
    path = shared.no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 1024 * 1024:
        raise FixtureError("recovery state must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise FixtureError("recovery state changed during open")
        data = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        if len(data) > 1024 * 1024 or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise FixtureError("recovery state changed during read")
    return json.loads(data)


def compose_spec(state):
    return {"services": {"postgres": {
        "image": state["postgres_image"], "restart": "no", "cpus": 1.0, "mem_limit": "512m",
        "pids_limit": 128, "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"},
        "environment": {"POSTGRES_USER": "farm", "POSTGRES_PASSWORD": "fixture-recovery-only", "POSTGRES_DB": "farm"},
        "volumes": ["./data/postgres:/var/lib/postgresql/data"], "networks": ["recovery"],
        "healthcheck": {"test": ["CMD", "pg_isready", "-U", "farm", "-d", "farm"],
                        "interval": "2s", "timeout": "2s", "retries": 30}}},
        "networks": {"recovery": {"internal": True}}}


def fixture(workspace):
    workspace = shared.no_links(workspace)
    state = read_json(workspace / "fixture.json")
    if (not isinstance(state, dict) or set(state) != STATE_KEYS or state["schema"] != SCHEMA
            or not re.fullmatch(r"dh-recovery-[a-f0-9]{12}", state.get("project", ""))
            or not re.fullmatch(r"dh-smoke-[a-f0-9]{12}", state.get("source_project", ""))
            or not re.fullmatch(r"postgres:14\.1-alpine@sha256:[a-f0-9]{64}", state.get("postgres_image", ""))):
        raise FixtureError("invalid recovery fixture identity")
    if read_json(workspace / "compose.json") != compose_spec(state):
        raise FixtureError("recovery Compose isolation settings changed")
    shared.no_links(workspace / "data/postgres")
    return workspace, state


def command(workspace, state):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(workspace),
            "--file", str(workspace / "compose.json")]


def prepare(args):
    source, original = shared.fixture(args.source_workspace)
    workspace = shared.no_links(args.workspace)
    if workspace.exists() or not workspace.parent.is_dir() or workspace.is_relative_to(source):
        raise FixtureError("recovery workspace must be new and outside the source fixture")
    image = original["images"]["postgres"]
    if not re.fullmatch(r"postgres:14\.1-alpine@sha256:[a-f0-9]{64}", image):
        raise FixtureError("recovery requires the retained farm PostgreSQL image")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "scope": "new synthetic PostgreSQL target only",
                "effects": ["new private directory and Compose fixture"], "not_validated": NOT_VALIDATED}
    workspace.mkdir(mode=0o700)
    state = {"schema": SCHEMA, "project": "dh-recovery-" + secrets.token_hex(6),
             "source_project": original["project"], "source_workspace": str(source),
             "postgres_image": image, "approval_id": args.approval_id}
    (workspace / "data/postgres").mkdir(parents=True, mode=0o700)
    shared.write(workspace / "compose.json", shared.canonical(compose_spec(state)))
    shared.write(workspace / "fixture.json", shared.canonical(state))
    return {"status": "PASS", "action": "prepare", "project": state["project"], "not_validated": NOT_VALIDATED}


def psql(compose, sql):
    # Bound capture during reading, not after subprocess.run has buffered it.
    argv = compose + ["exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                      "-A", "-t", "-U", "farm", "-d", "farm", "-c", sql]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data, issues = bytearray(), []

    def drain():
        try:
            while True:
                part = process.stdout.read(65536)
                if not part:
                    break
                if len(data) + len(part) > MAX_DUMP:
                    raise FixtureError("synthetic query exceeded size limit")
                data.extend(part)
        except (OSError, FixtureError) as error:
            issues.append(error)
            process.kill()

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    try:
        try:
            code = process.wait(timeout=15)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=10)
            raise FixtureError("synthetic query timed out; test container cleanup required") from error
        thread.join(timeout=10)
        if thread.is_alive() or issues or code:
            raise FixtureError("synthetic query failed or exceeded bounds")
        return bytes(data).strip()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        thread.join(timeout=10)
        process.stdout.close()


def ready(compose):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            # The image initializes databases through a temporary socket-only
            # server. TCP readiness waits for its final post-init server.
            shared.checked(compose + ["exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1",
                                      "-U", "farm", "-d", "farm"], timeout=5)
            return
        except FixtureError:
            time.sleep(1)
    raise FixtureError("test PostgreSQL readiness timed out")


def summary(compose):
    tables = psql(compose, "SELECT table_name FROM information_schema.tables WHERE table_schema='public' "
                  "AND table_type='BASE TABLE' ORDER BY table_name;")
    if tables != b"flags":
        raise FixtureError("source/recovered database is not the expected synthetic flags schema")
    counts = psql(compose, "SELECT count(*),count(*) FILTER (WHERE status='ACCEPTED'),"
        "count(*) FILTER (WHERE sploit IS DISTINCT FROM 'synthetic-smoke' OR team IS DISTINCT FROM 'Synthetic' "
        "OR flag !~ '^[A-Z0-9]{31}=$' OR checksystem_response IS DISTINCT FROM 'accepted synthetic fixture') FROM flags;")
    if not re.fullmatch(rb"[0-9]+\|[0-9]+\|[0-9]+", counts):
        raise FixtureError("invalid synthetic database counts")
    total, accepted, foreign = map(int, counts.split(b"|"))
    if not 1 <= accepted <= total <= MAX_ROWS or foreign:
        raise FixtureError("source/recovered database contains unexpected or non-synthetic data")
    rows = json.loads(psql(compose, "SELECT json_agg(row_to_json(f) ORDER BY flag) FROM flags f;"))
    if not isinstance(rows, list) or len(rows) != total:
        raise FixtureError("source/recovered rows changed during verification")
    return {"tables": 1, "flags": total, "accepted": accepted,
            "rows_sha256": hashlib.sha256(shared.canonical(rows)).hexdigest()}


def dump_database(compose, destination, limit=MAX_DUMP, timeout=60):
    """Bound disk writes while consuming native pg_dump output; retain partials."""
    destination = shared.no_links(destination)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    issues, result = [], {"bytes": 0, "sha256": None}
    process = None
    thread = None
    try:
        process = subprocess.Popen(compose + ["exec", "-T", "postgres", "pg_dump", "-U", "farm", "-d", "farm",
            "--format=custom", "--compress=0", "--no-owner", "--no-privileges"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        def drain():
            sha = hashlib.sha256()
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    while True:
                        data = process.stdout.read(65536)
                        if not data:
                            break
                        if result["bytes"] + len(data) > limit:
                            raise FixtureError("native dump exceeds size limit; partial retained")
                        stream.write(data)
                        sha.update(data)
                        result["bytes"] += len(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                result["sha256"] = sha.hexdigest()
            except (OSError, FixtureError) as error:
                issues.append(error)
                process.kill()

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=10)
            raise FixtureError("native dump timed out; source test container cleanup required") from error
        thread.join(timeout=10)
        if thread.is_alive() or issues or code or result["bytes"] == 0:
            raise FixtureError("native dump failed or exceeded bounds; partial retained, not restored")
        with destination.open("rb") as stream:
            if stream.read(5) != b"PGDMP":
                raise FixtureError("native custom-format dump signature is missing")
        return result
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if thread is not None:
                thread.join(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
        os.close(descriptor)


def restore_database(compose, path, expected):
    # Never --clean or --create: the caller proved this isolated database empty.
    path = shared.no_links(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 5 <= before.st_size <= MAX_DUMP:
            raise FixtureError("restore dump must be a bounded regular file")
        digest = hashlib.sha256()
        signature = stream.read(5)
        digest.update(signature)
        size = 5
        while True:
            data = stream.read(65536)
            if not data:
                break
            size += len(data)
            if size > MAX_DUMP:
                raise FixtureError("restore dump changed or exceeded bounds")
            digest.update(data)
        opened = os.fstat(stream.fileno())
        if (signature != b"PGDMP" or size != expected["bytes"] or digest.hexdigest() != expected["sha256"]
                or (before.st_size, before.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns)):
            raise FixtureError("restore dump verification failed; no restore attempted")
        stream.seek(0)
        try:
            process = subprocess.run(compose + ["exec", "-T", "postgres", "pg_restore", "-U", "farm", "-d", "farm",
                "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges"],
                stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
        except subprocess.TimeoutExpired as error:
            raise FixtureError("restore timed out; new target cleanup required") from error
        if process.returncode:
            raise FixtureError("native restore failed; original source and dump retained")
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise FixtureError("dump changed during restore; target result is not trusted")


def drill(args, workspace, state):
    if not args.snapshot_confirmed:
        raise FixtureError("run --apply requires --snapshot-confirmed for this approved test host")
    source, original = shared.fixture(state["source_workspace"])
    if original["project"] != state["source_project"] or original["images"]["postgres"] != state["postgres_image"]:
        raise FixtureError("source identity changed")
    source_command = shared.compose_command(source, original)
    target_command = command(workspace, state)
    for current in (source_command, target_command):
        if shared.checked(current + ["ps", "--all", "--quiet"], capture=True).strip():
            raise FixtureError("both test projects must be fully stopped before this exclusive drill")
    if any((workspace / "data/postgres").iterdir()):
        raise FixtureError("restore target data directory must be empty")
    shared.write(workspace / "attempt.json", shared.canonical({"approval_id": args.approval_id, "snapshot_confirmed": True}))
    cleanup = {}
    report = {"schema": "durkahelper.recovery-result.v1", "status": "BLOCKED", "checks": {},
              "not_validated": NOT_VALIDATED, "postgres_image": state["postgres_image"]}
    try:
        report["phase"] = "source-start"
        shared.checked(source_command + ["up", "--detach", "--no-build", "--pull", "never", "postgres"], timeout=120)
        ready(source_command)
        report["phase"] = "source-summary"
        before = summary(source_command)
        report["phase"] = "native-dump"
        dump = dump_database(source_command, workspace / "farm.dump")
        report["phase"] = "source-stability"
        if summary(source_command) != before:
            raise FixtureError("synthetic source changed during native dump")
        report["phase"] = "target-start"
        shared.checked(target_command + ["up", "--detach", "--no-build", "--pull", "never", "postgres"], timeout=120)
        ready(target_command)
        report["phase"] = "target-empty"
        empty = psql(target_command, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' "
                     "AND table_type='BASE TABLE';") == b"0"
        if not empty:
            raise FixtureError("new target database is not empty; restore refused")
        report["phase"] = "native-restore"
        restore_database(target_command, workspace / "farm.dump", dump)
        report["phase"] = "restore-verification"
        recovered = summary(target_command)
        unchanged = summary(source_command) == before
        report.update({"source": before, "restored": recovered, "dump": dump, "checks": {
            "empty_target_before_restore": empty, "native_restore_matches": recovered == before,
            "accepted_flags_preserved": recovered["accepted"] == before["accepted"],
            "source_unchanged": unchanged}})
        report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
        report["phase"] = "complete"
    finally:
        # Exact projects only; bind data, images and dump always survive cleanup.
        for role, current in (("target", target_command), ("source", source_command)):
            try:
                shared.checked(current + ["down", "--timeout", "10"], timeout=60)
                cleanup[role] = not shared.checked(current + ["ps", "--all", "--quiet"], capture=True).strip()
            except FixtureError:
                cleanup[role] = False
        report["cleanup"] = cleanup
        if not all(cleanup.values()):
            report["status"] = "BLOCKED"
        shared.write(workspace / "result.json", shared.canonical(report))
    return report


def execute(args):
    workspace, state = fixture(args.workspace)
    args.validated_project = state["project"]
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "project": state["project"],
                "requires": "--apply --approval-id; run also requires --snapshot-confirmed",
                "retained": ["original source data", "native dump", "restored target data"]}
    if args.action == "run":
        return drill(args, workspace, state)
    compose = command(workspace, state)
    shared.checked(compose + ["down", "--timeout", "10"], timeout=60)
    return {"status": "PASS", "action": "down", "project": state["project"], "data_retained": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run", "down"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--source-workspace")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise FixtureError("mutations require a non-secret approval identifier")
        if args.action == "prepare" and not args.source_workspace:
            raise FixtureError("prepare requires the stopped synthetic --source-workspace")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return {"PASS": 0, "NOT_RUN": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]
    except (FixtureError, OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt) as error:
        result = {"status": "BLOCKED", "reason": str(error) if isinstance(error, FixtureError)
                  else "recovery operation failed: " + type(error).__name__}
        if getattr(args, "validated_project", None):
            result.update({"project": args.validated_project, "retained": "source, dump/partial, target data; inspect local result.json"})
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    sys.exit(main())
