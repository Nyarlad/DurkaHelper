#!/usr/bin/env python3
"""Opt-in harmless Neo lifecycle on an already running synthetic fixture only.

The fixed payload only prints a synthetic flag. It does not contact team IPs,
read credentials, run exploits, alter target services or expose ports. Output is
bounded and suppressed; the original fixture and disabled test entry remain.
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

SPEC = importlib.util.spec_from_file_location("lifecycle_release", Path(__file__).with_name("neo_release_smoke.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
shared = release.shared
Error = shared.FixtureError
SCHEMA = "durkahelper.neo-lifecycle.v1"
LABEL = "io.durkahelper.neo-lifecycle"


def payload(flag):
    if not re.fullmatch(r"[A-F0-9]{31}=", flag):
        raise Error("invalid synthetic flag")
    # Upstream checks a flush marker for non-Python scripts; POSIX printf exits
    # immediately, so no buffered process survives beyond this fixed payload.
    return ("#!/bin/sh\n# flush=True: printf exits immediately\nprintf '%s\\n' '" + flag + "'\n").encode()


def config(identity):
    if not re.fullmatch(r"dh-life-[a-f0-9]{12}", identity):
        raise Error("invalid lifecycle identity")
    return ('host: "neo-server:5005"\ngrpc_auth_key: "fixture-only"\nexploit_dir: "/work/exploits"\nclient_id: "' + identity + '"\n').encode()


def prepare(args):
    root = shared.no_links(args.workspace)
    if root.exists() or not root.parent.is_dir():
        raise Error("lifecycle workspace must be new under existing parent")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "effects": ["private synthetic payload/config workspace"]}
    root.mkdir(mode=0o700)
    identity = "dh-life-" + secrets.token_hex(6)
    flag = secrets.token_hex(16).upper()[:31] + "="
    state = {"schema": SCHEMA, "id": identity, "flag": flag, "approval_id": args.approval_id}
    shared.write(root / "fixture.json", shared.canonical(state))
    shared.write(root / "client.yml", config(identity))
    shared.write(root / "synthetic.sh", payload(flag))
    for name in ("client.yml", "synthetic.sh"):
        (root / name).chmod(0o644)
    return {"status": "PASS", "action": "prepare", "fixture": identity, "payload_sha256": hashlib.sha256(payload(flag)).hexdigest()}


def fixture(path):
    root = shared.no_links(path)
    state = json.loads(release.bounded_read(root / "fixture.json", 16384))
    if set(state) != {"schema", "id", "flag", "approval_id"} or state["schema"] != SCHEMA:
        raise Error("invalid lifecycle fixture")
    if release.bounded_read(root / "client.yml", 4096) != config(state["id"]) or release.bounded_read(root / "synthetic.sh", 4096) != payload(state["flag"]):
        raise Error("synthetic lifecycle payload/config changed")
    return root, state


def arguments(root, state, binary, image, network, name, action):
    allowed = {"worker": ["run", "--jobs", "1", "--endless-jobs", "0"],
               "add": ["add", "--id", state["id"], "--disabled", "--interval", "1h", "--timeout", "3s", "/synthetic.sh"],
               "single": ["single", state["id"]], "disable": ["disable", state["id"]], "info": ["info"]}
    if action not in allowed:
        raise Error("unsupported synthetic lifecycle action")
    if any(character in str(root) + str(binary) for character in (",", "\n", "\r")):
        raise Error("mount delimiters not permitted")
    return ["docker", "create", "--name", name, "--label", LABEL + "=" + state["id"],
        "--network", network, "--user", "65534:65534", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
        "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=32", "--log-driver=none", "--pull=never",
        "--mount", "type=bind,src=" + str(binary) + ",dst=/neo,readonly",
        "--mount", "type=bind,src=" + str(root / "client.yml") + ",dst=/client.yml,readonly",
        "--mount", "type=bind,src=" + str(root / "synthetic.sh") + ",dst=/synthetic.sh,readonly",
        "--tmpfs", "/work:rw,nosuid,nodev,exec,size=16777216,mode=0700,uid=65534,gid=65534",
        "--entrypoint", "/neo", image, "--verbose=false", "--config", "/client.yml"] + allowed[action]


def cleanup(name, identity):
    actual = shared.checked(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name], capture=True).decode().strip()
    if actual != identity:
        raise Error("lifecycle cleanup ownership mismatch")
    shared.checked(["docker", "rm", "--force", name], timeout=20)


def run_client(root, state, binary, image, network, action):
    name = state["id"] + "-" + action + "-" + secrets.token_hex(4)
    created = False
    try:
        shared.checked(arguments(root, state, binary, image, network, name, action))
        created = True
        code, output = release.capture(["docker", "start", "--attach", name], timeout=25)
        if code:
            raise Error("synthetic Neo command failed; raw output suppressed")
        return output
    finally:
        # Exact random name plus owner label only; creation timeouts are reported
        # for manual inspection rather than broad cleanup by a name prefix.
        if created:
            cleanup(name, state["id"])


def accepted(port, flag, identifier, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, data = shared.request(port, "/api/filter_flags?flag=" + flag)
        rows = json.loads(data).get("flags", []) if code == 200 else []
        if any(row.get("flag") == flag and row.get("status") == "ACCEPTED" and row.get("sploit") == "[neo] " + identifier for row in rows):
            return True
        time.sleep(1)
    return False


def smoke(args):
    root, state = fixture(args.workspace)
    release_root, _ = release.fixture(args.release_workspace)
    stack_root, stack = shared.fixture(args.stack_workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "smoke", "effects": ["disabled synthetic entry on lab server", "temporary isolated worker", "one synthetic result", "worker restart"],
                "rollback": "disable exact synthetic entry; remove only owned clients; retain original stack"}
    cmd = shared.compose_command(stack_root, stack)
    port = shared.farm_port(cmd)
    shared.wait_ready(port)
    code, data = shared.request(port, "/api/get_config")
    if code != 200 or json.loads(data).get("TEAMS") != {"Synthetic": "192.0.2.1"}:
        raise Error("lifecycle requires the unchanged synthetic team map")
    network = stack["project"] + "_fixture"
    descriptor = shared.checked(["docker", "network", "inspect", "--format", '{{.Internal}};{{index .Labels "com.docker.compose.project"}}', network], capture=True).decode().strip()
    if descriptor != "true;" + stack["project"]:
        raise Error("lifecycle requires the exact internal fixture network")
    image = stack["images"]["alpine"]
    architecture = shared.checked(["docker", "image", "inspect", "--format", "{{.Os}};{{.Architecture}}", image], capture=True).decode().strip()
    if architecture != "linux;amd64":
        raise Error("published lifecycle fixture is Linux amd64 only")
    binary = release_root / "neo"
    worker = state["id"] + "-worker-" + secrets.token_hex(4)
    checks, created, added = {}, False, False
    try:
        info = run_client(root, state, binary, image, network, "info")
        if state["id"].encode() + b'"' in info:
            raise Error("lifecycle fixture already used; prepare a fresh identity")
        run_client(root, state, binary, image, network, "add")
        added = True
        checks["disabled_payload_registered"] = True
        shared.checked(arguments(root, state, binary, image, network, worker, "worker"))
        created = True
        shared.checked(["docker", "start", worker])
        time.sleep(6)
        run_client(root, state, binary, image, network, "single")
        checks["synthetic_execution_and_mock_acceptance"] = accepted(port, state["flag"], state["id"])
        # Restart only the exact worker; this tests client reconnection, not VM,
        # network fault injection, server restore or database recovery.
        shared.checked(["docker", "stop", "--time", "10", worker], timeout=20)
        shared.checked(["docker", "start", worker])
        time.sleep(6)
        info = run_client(root, state, binary, image, network, "info")
        checks["worker_reconnect"] = state["id"].encode() + b": [" in info
        checks["server_retains_disabled_entry"] = state["id"].encode() in info and b"disabled:true" in info
    finally:
        try:
            if added:
                run_client(root, state, binary, image, network, "disable")
        finally:
            if created:
                cleanup(worker, state["id"])
    return {"schema": "durkahelper.neo-lifecycle-report.v1", "status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
            "release": release.RELEASE, "archive_sha256": release.SHA256, "server_source": shared.PINS["neo"],
            "payload_sha256": hashlib.sha256(payload(state["flag"])).hexdigest(),
            "not_validated": ["real exploits", "server/database recovery", "Docker Desktop", "ARM64", "TLS", "metrics", "network failure"],
            "rollback": "owned clients removed; disabled exact test entry and synthetic results retained on lab stack"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "smoke"])
    for option in ("workspace", "release-workspace", "stack-workspace", "approval-id"):
        parser.add_argument("--" + option, required=option == "workspace")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret approval identifier")
        if args.action == "smoke" and not (args.release_workspace and args.stack_workspace):
            raise Error("smoke requires both existing release and synthetic stack workspaces")
        result = prepare(args) if args.action == "prepare" else smoke(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if result["status"] == "FAIL" else 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "BLOCKED", "reason": "interrupted; inspect exact fixture identity; created clients cleaned in finally and test data retained", "raw_output": "suppressed"}))
        return 2
    except (Error, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else type(error).__name__, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
