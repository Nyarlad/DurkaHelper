#!/usr/bin/env python3
"""Opt-in native Redis RDB recovery using new synthetic source/target only.

No existing deployment or shared database is accepted. This does not validate
Neo's bbolt state, Packmate PostgreSQL or their application-level recovery.
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
import sys
import time

SPEC = importlib.util.spec_from_file_location("component_release", Path(__file__).with_name("neo_release_smoke.py"))
safe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(safe)
shared = safe.shared
Error = shared.FixtureError
SCHEMA = "durkahelper.redis-recovery.v1"
LABEL = "io.durkahelper.redis-recovery"
KEY = "durkahelper:synthetic:recovery"
MAX_RDB = 1024 * 1024
NOT_VALIDATED = ["Neo bbolt application recovery", "Packmate application recovery", "real Redis queues", "whole-stack recovery", "Docker Desktop", "competition RPO/RTO"]


def prepare(args):
    root = shared.no_links(args.workspace)
    if root.exists() or not root.parent.is_dir():
        raise Error("recovery workspace must be a new directory under existing parent")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "effects": ["new private synthetic source/restore directories"], "not_validated": NOT_VALIDATED}
    if os.name == "nt":
        raise Error("native recovery drill requires POSIX ownership")
    images = shared.image_map(Path(__file__).resolve().parents[1] / "config/integration-images.lock.json")
    root.mkdir(mode=0o700)
    for name in ("source", "restore"):
        (root / name).mkdir(mode=0o700)
    state = {"schema": SCHEMA, "id": "dh-redis-recovery-" + secrets.token_hex(6), "image": images["redis"],
             "marker": secrets.token_hex(16), "approval_id": args.approval_id, "uid": os.getuid(), "gid": os.getgid()}
    shared.write(root / "fixture.json", shared.canonical(state))
    return {"status": "PASS", "action": "prepare", "fixture": state["id"], "not_validated": NOT_VALIDATED}


def fixture(path):
    root = shared.no_links(path)
    state = json.loads(safe.bounded_read(root / "fixture.json", 16384))
    images = shared.image_map(Path(__file__).resolve().parents[1] / "config/integration-images.lock.json")
    if (set(state) != {"schema", "id", "image", "marker", "approval_id", "uid", "gid"} or state["schema"] != SCHEMA or
            not re.fullmatch(r"dh-redis-recovery-[a-f0-9]{12}", state["id"]) or state["image"] != images["redis"] or
            not re.fullmatch(r"[a-f0-9]{32}", state["marker"]) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", state["approval_id"])):
        raise Error("invalid Redis recovery fixture identity")
    for name in ("source", "restore"):
        folder = shared.no_links(root / name)
        if not folder.is_dir():
            raise Error("recovery data directories must exist")
    return root, state


def arguments(root, state, role):
    if role not in {"source", "restore"}:
        raise Error("invalid synthetic recovery role")
    if any(c in str(root) for c in (",", "\n", "\r")):
        raise Error("mount delimiter not permitted")
    return ["docker", "create", "--name", state["id"] + "-" + role, "--label", LABEL + "=" + state["id"],
        "--network", "none", "--user", str(state["uid"]) + ":" + str(state["gid"]), "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=32",
        "--log-driver=none", "--pull=never", "--mount", "type=bind,src=" + str(root / role) + ",dst=/data",
        "--entrypoint", "redis-server", state["image"], "--bind", "127.0.0.1", "--protected-mode", "yes", "--dir", "/data",
        "--dbfilename", "dump.rdb", "--appendonly", "no", "--save", ""]


def own(state, role):
    name = state["id"] + "-" + role
    actual = shared.checked(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name], capture=True).decode().strip()
    if actual != state["id"]:
        raise Error("Redis recovery ownership mismatch")
    return name


def cli(state, role, operation, *values):
    if operation not in {"PING", "SET", "GET", "DBSIZE", "SAVE"}:
        raise Error("unsupported synthetic Redis operation")
    return shared.checked(["docker", "exec", own(state, role), "redis-cli", "--raw", operation] + list(values), timeout=10, capture=True).strip()


def ready(state, role):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if cli(state, role, "PING") == b"PONG":
                return
        except Error:
            pass
        time.sleep(0.5)
    raise Error("synthetic Redis readiness timed out")


def cleanup(state, role):
    name = own(state, role)
    shared.checked(["docker", "rm", "--force", name], timeout=20)


def smoke(args):
    root, state = fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "smoke", "effects": ["new source and restored Redis containers without networking", "native SAVE", "bounded RDB copy"],
                "rollback": "remove only exact labelled clients; all data/dump files retained", "not_validated": NOT_VALIDATED}
    if not args.snapshot_confirmed:
        raise Error("recovery drill requires --snapshot-confirmed")
    if os.name == "nt" or (state["uid"], state["gid"]) != (os.getuid(), os.getgid()) or state["uid"] == 0:
        raise Error("drill requires the same non-root POSIX workspace owner")
    if any(any((root / name).iterdir()) for name in ("source", "restore")) or (root / "dump.rdb").exists():
        raise Error("recovery fixture already used; prepare a fresh workspace")
    architecture = shared.checked(["docker", "image", "inspect", "--format", "{{.Os}};{{.Architecture}}", state["image"]], capture=True).decode().strip()
    if architecture not in {"linux;amd64", "linux;arm64"}:
        raise Error("cached pinned Redis image must be a supported Linux architecture")
    created, checks = [], {}
    try:
        shared.checked(arguments(root, state, "source"))
        created.append("source")
        shared.checked(["docker", "start", own(state, "source")])
        ready(state, "source")
        if cli(state, "source", "DBSIZE") != b"0":
            raise Error("new Redis source contains unexpected data")
        write_at = time.monotonic()
        checks["synthetic_write"] = cli(state, "source", "SET", KEY, state["marker"]) == b"OK"
        if not checks["synthetic_write"] or cli(state, "source", "DBSIZE") != b"1":
            raise Error("synthetic source content did not match")
        checks["native_save"] = cli(state, "source", "SAVE") == b"OK"
        save_at = time.monotonic()
        shared.checked(["docker", "stop", "--time", "10", own(state, "source")], timeout=20)
        dump = safe.bounded_read(root / "source/dump.rdb", MAX_RDB)
        if not dump.startswith(b"REDIS") or len(dump) < 20:
            raise Error("native SAVE did not produce a valid bounded RDB header")
        checksum = hashlib.sha256(dump).hexdigest()
        shared.write(root / "dump.rdb", dump)
        recovery_at = time.monotonic()
        shared.write(root / "restore/dump.rdb", dump)
        shared.checked(arguments(root, state, "restore"))
        created.append("restore")
        shared.checked(["docker", "start", own(state, "restore")])
        ready(state, "restore")
        checks["restored_value"] = cli(state, "restore", "GET", KEY) == state["marker"].encode()
        checks["restored_key_count"] = cli(state, "restore", "DBSIZE") == b"1"
        recovered_at = time.monotonic()
        checks["source_dump_unchanged"] = hashlib.sha256(safe.bounded_read(root / "source/dump.rdb", MAX_RDB)).hexdigest() == checksum
        rpo = save_at - write_at
        rto = recovered_at - recovery_at
        checks["synthetic_rpo_under_300s"] = rpo <= 300
        checks["synthetic_rto_under_600s"] = rto <= 600
    finally:
        failures = []
        for role in reversed(created):
            try:
                cleanup(state, role)
            except Error:
                failures.append(role)
        if failures:
            raise Error("exact owned Redis cleanup requires attention: " + ", ".join(failures))
    return {"schema": "durkahelper.component-recovery-report.v1", "component": "redis", "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "image": state["image"], "architecture": architecture, "dump_sha256": checksum, "dump_bytes": len(dump),
            "synthetic_rpo_seconds": round(rpo, 3), "synthetic_rto_seconds": round(rto, 3), "not_validated": NOT_VALIDATED,
            "scope": "one synthetic Redis key saved natively and restored into a new isolated database; not real queue recovery",
            "rollback": "exact owned containers removed; source, restore and native dump files retained"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "smoke"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret approval identifier")
        result = prepare(args) if args.action == "prepare" else smoke(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if result["status"] == "FAIL" else 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "BLOCKED", "reason": "interrupted; inspect exact fixture identity; data retained", "raw_output": "suppressed"}))
        return 2
    except (Error, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else type(error).__name__, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
