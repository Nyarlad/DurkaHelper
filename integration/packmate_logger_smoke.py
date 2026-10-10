#!/usr/bin/env python3
"""Prove Packmate's configuration-only auth-log suppression with synthetic data.

Creates a fresh FILE fixture only. The control intentionally logs a disposable
failed-password canary; no raw log or credential is printed or exported. A
positive control is required so absence alone cannot produce a false PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import sys
import time

SPEC = importlib.util.spec_from_file_location("logger_packmate", Path(__file__).with_name("packmate_smoke.py"))
pack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pack)
safe = pack._sibling("neo_release_smoke")
Error = pack.FixtureError
LOGGER = "ru.serega6531.packmate.configuration.SecurityConfiguration"
SCHEMA = "durkahelper.packmate-logger.v1"
NOTICE = ["other upstream loggers", "real credentials", "LIVE capture", "Docker Desktop", "ARM64"]


def overlay(suppressed):
    app = {"logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "1"}}}
    if suppressed:
        # Compose merges mounts by container destination, replacing this single
        # config mount; application.properties and the upstream image stay intact.
        app["volumes"] = ["./logger.properties:/fixture/application.properties:ro"]
    return {"services": {"packmate": app}}


def prepare(args):
    root = pack.shared.no_links(args.workspace)
    result = pack.prepare(args)
    if not args.apply:
        return {**result, "effects": ["new synthetic FILE fixture", "bounded positive-control logs",
                                     "configuration-only logger override"], "not_validated": NOTICE}
    root, state = pack.fixture(root)
    settings = pack.properties(state) + ("logging.level." + LOGGER + "=OFF\n").encode()
    pack.shared.write(root / "logger.properties", settings)
    (root / "logger.properties").chmod(0o644)
    for name, suppressed in (("control.json", False), ("suppressed.json", True)):
        pack.shared.write(root / name, pack.shared.canonical(overlay(suppressed)))
    pack.shared.write(root / "logger-fixture.json", pack.shared.canonical({
        "schema": SCHEMA, "project": state["project"], "settings_sha256": hashlib.sha256(settings).hexdigest()}))
    return {"status": "PASS", "action": "prepare", "schema": SCHEMA, "not_validated": NOTICE}


def fixture(path):
    root, state = pack.fixture(path)
    settings = pack.properties(state) + ("logging.level." + LOGGER + "=OFF\n").encode()
    record = json.loads(pack.bounded_bytes(root / "logger-fixture.json"))
    if record != {"schema": SCHEMA, "project": state["project"],
                  "settings_sha256": hashlib.sha256(settings).hexdigest()}:
        raise Error("invalid synthetic logger fixture")
    if pack.bounded_bytes(root / "logger.properties") != settings:
        raise Error("logger configuration changed")
    for name, suppressed in (("control.json", False), ("suppressed.json", True)):
        if pack.bounded_bytes(root / name) != pack.shared.canonical(overlay(suppressed)):
            raise Error("logger overlay changed")
    return root, state


def app_identity(command, state):
    identity = pack.shared.checked(command + ["ps", "--quiet", "packmate"], capture=True).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise Error("expected exactly one test app container")
    actual = pack.shared.checked(["docker", "inspect", "--format",
        '{{index .Config.Labels "com.docker.compose.project"}}', identity], capture=True).decode().strip()
    if actual != state["project"]:
        raise Error("logger fixture container ownership mismatch")
    return identity


def logs(identity):
    code, output = safe.capture(["docker", "logs", "--tail", "200", identity], timeout=10)
    if code:
        raise Error("bounded synthetic log read failed")
    return output


def smoke(args):
    root, state = fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "smoke", "not_validated": NOTICE,
                "effects": ["own app/db startup", "failed-auth synthetic control", "own app recreation",
                            "configuration-only suppression check", "own project shutdown"]}
    if any((root / "data/postgres").iterdir()):
        raise Error("logger smoke requires a fresh unused synthetic database")
    base = pack.compose_command(root, state)
    active = pack.shared.checked(["docker", "ps", "-aq", "--filter",
        "label=com.docker.compose.project=" + state["project"]], capture=True)
    if active.strip():
        raise Error("logger project already exists; use a fresh fixture")
    pack.image_evidence(state)
    checks = {}
    started = False
    try:
        for suppressed in (False, True):
            name = "suppressed" if suppressed else "control"
            command = base + ["--file", str(root / (name + ".json"))]
            started = True  # A partial Compose startup still requires scoped cleanup.
            pack.shared.checked(command + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
            port = pack.app_port(command)
            pack.wait_ready(port, state)
            identity = app_identity(command, state)
            canary = ("suppressed-" if suppressed else "control-") + secrets.token_hex(24)
            code, _, _ = pack.request(port, {**state, "password": canary}, "/api/service/")
            checks[name + "_failed_auth_rejected"] = code == 401
            time.sleep(1)
            output = logs(identity)
            checks[name + "_valid_credential_absent"] = state["password"].encode() not in output
            checks[name + "_database_credential_absent"] = state["db_password"].encode() not in output
            checks[name + "_logger_behavior"] = (canary.encode() not in output) if suppressed else (canary.encode() in output)
            code, _, _ = pack.request(port, state, "/api/service/")
            checks[name + "_valid_auth_still_works"] = code == 200
            # No upstream/source change: configuration mount alone changes.
            if not suppressed:
                pack.shared.checked(command + ["stop", "--timeout", "10", "packmate"], timeout=30)
                pack.shared.checked(command + ["rm", "--force", "packmate"], timeout=30)
    finally:
        if started:
            # Exact random project, explicit canonical file. No --volumes or prune.
            pack.shared.checked(base + ["down", "--timeout", "10"], timeout=60)
    return {"schema": "durkahelper.packmate-logger-report.v1", "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "app_image": pack.APP_IMAGE, "logger": LOGGER,
            "settings_sha256": hashlib.sha256(("logging.level." + LOGGER + "=OFF\n").encode()).hexdigest(),
            "scope": "synthetic invalid-auth control and configuration override; upstream unchanged",
            "raw_output": "never exported", "not_validated": NOTICE,
            "rollback": "exact test project removed; database and private config retained"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "smoke"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--source")
    parser.add_argument("--postgres-image")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret approval ID")
        result = prepare(args) if args.action == "prepare" else smoke(args)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["status"] == "FAIL" else 0
    except (Error, OSError, ValueError, TypeError, KeyError, KeyboardInterrupt):
        print(json.dumps({"status": "BLOCKED", "details": "suppressed; inspect only the exact test-owned project"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
