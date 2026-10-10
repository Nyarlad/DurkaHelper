#!/usr/bin/env python3
"""Opt-in published Neo v2.4.2 Linux amd64 info/authentication smoke.

No exploit execution, source compilation, host networking or privileged client.
Uses a separate private workspace and an already running validated stack fixture.
Raw info output can contain farm credentials and is never printed or persisted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request


SPEC = importlib.util.spec_from_file_location("neo_release_shared", Path(__file__).with_name("stack_smoke.py"))
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
FixtureError = shared.FixtureError
RELEASE = "v2.4.2"
ASSET = "neo_client_2.4.2_linux_amd64.tar.gz"
PREFIX = "neo_client_2.4.2_linux_amd64/"
URL = "https://github.com/C4T-BuT-S4D/neo/releases/download/v2.4.2/" + ASSET
SHA256 = "42a0affe303195693f29f1998ac13fac9238db71e7395674f5141bfc553274de"
SIZE = 5326241
MAX_BINARY = 32 * 1024 * 1024
MAX_OUTPUT = 65536
SCHEMA = "durkahelper.neo-release-fixture.v1"
LABEL = "durkahelper.neo-release"
NOT_VALIDATED = ["exploit execution", "task lifecycle", "metrics", "TLS", "recovery",
                 "Apple Silicon", "Docker Desktop", "team Ethernet access", "competition adapter"]


def bounded_read(path, limit):
    path = shared.no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise FixtureError("input must be a bounded regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if not stat.S_ISREG(opened.st_mode) or fields(before) != fields(opened):
            raise FixtureError("input changed during open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit or fields(opened) != fields(os.fstat(fd)):
            raise FixtureError("input changed during read or exceeds limit")
        return result
    finally:
        os.close(fd)


def check_lock(path):
    lock = json.loads(bounded_read(path, 1024 * 1024))
    neo = lock["components"]["neo"]
    assets = [a for a in neo["release"]["assets"] if a["name"] == ASSET]
    if (neo["release"]["tag"] != RELEASE or neo["source"]["commit"] != shared.PINS["neo"] or
            len(assets) != 1 or any(assets[0].get(k) != v for k, v in {
                "url": URL, "published_sha256": SHA256, "size": SIZE,
                "os": "linux", "architecture": "amd64"}.items())):
        raise FixtureError("toolchain lock does not match the exact reviewed release/source pair")


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname not in {"github.com", "release-assets.githubusercontent.com"}
                or parsed.username or parsed.password or parsed.port not in {None, 443}):
            raise FixtureError("release download redirect outside approved HTTPS hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
    with opener.open(URL, timeout=20) as response:
        if response.status != 200:
            raise FixtureError("release download did not return HTTP 200")
        data = response.read(SIZE + 1)
    return data


def release_binary(data):
    # Verify the independently published archive digest before decompression.
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise FixtureError("release archive size or SHA-256 mismatch")
    allowed = {PREFIX + name for name in ("README.md", "client_config.yml", "exploits/.keep", "neo")}
    seen, total, binary = set(), 0, None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.name not in allowed or member.name in seen or not member.isfile():
                raise FixtureError("unexpected, duplicate or non-regular release archive member")
            seen.add(member.name)
            total += member.size
            if member.size < 0 or total > MAX_BINARY:
                raise FixtureError("expanded release exceeds limit")
            if member.name == PREFIX + "neo":
                with archive.extractfile(member) as stream:
                    binary = stream.read(MAX_BINARY + 1)
                if len(binary) != member.size:
                    raise FixtureError("truncated release executable")
    if seen != allowed or binary is None:
        raise FixtureError("release archive has missing members")
    if (len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01" or
            int.from_bytes(binary[18:20], "little") != 62):
        raise FixtureError("release executable is not ELF64 Linux amd64")
    return binary


def client_config(denied=False):
    key = "incorrect-fixture-key" if denied else "fixture-only"
    return ('host: "neo-server:5005"\ngrpc_auth_key: "' + key + '"\n'
            'exploit_dir: "/tmp/unused"\nclient_id: "synthetic-release-info-client"\n').encode()


def prepare(args):
    check_lock(args.lock)
    root = shared.no_links(args.workspace)
    if any(character in str(root) for character in (",", "\n", "\r")):
        raise FixtureError("fixture path cannot contain Docker mount delimiters")
    if root.exists() or not root.parent.is_dir():
        raise FixtureError("workspace must be new under an existing parent")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "release": RELEASE, "sha256": SHA256,
                "effects": ["optional bounded HTTPS download", "new private fixture directory"]}
    data = download() if args.download else bounded_read(args.archive, SIZE)
    binary = release_binary(data)
    root.mkdir(mode=0o700)
    state = {"schema": SCHEMA, "id": "dh-neo-release-" + secrets.token_hex(6),
             "release": RELEASE, "archive_sha256": SHA256, "approval_id": args.approval_id}
    for name, value in ((ASSET, data), ("neo", binary), ("client.yml", client_config()),
                        ("denied.yml", client_config(True)), ("fixture.json", shared.canonical(state))):
        shared.write(root / name, value)
    # Bind-mounted synthetic files must be readable by the non-root client;
    # their containing host workspace remains private mode 0700.
    (root / "neo").chmod(0o555)
    for name in ("client.yml", "denied.yml"):
        (root / name).chmod(0o644)
    return {"status": "PASS", "action": "prepare", "fixture": state["id"],
            "release": RELEASE, "archive_sha256": SHA256,
            "binary_sha256": hashlib.sha256(binary).hexdigest()}


def fixture(workspace):
    root = shared.no_links(workspace)
    if any(character in str(root) for character in (",", "\n", "\r")):
        raise FixtureError("fixture path cannot contain Docker mount delimiters")
    state = json.loads(bounded_read(root / "fixture.json", 16384))
    if (set(state) != {"schema", "id", "release", "archive_sha256", "approval_id"} or
            state["schema"] != SCHEMA or state["release"] != RELEASE or state["archive_sha256"] != SHA256 or
            not re.fullmatch(r"dh-neo-release-[a-f0-9]{12}", state["id"]) or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", state["approval_id"])):
        raise FixtureError("invalid release fixture identity")
    binary = release_binary(bounded_read(root / ASSET, SIZE))
    if bounded_read(root / "neo", MAX_BINARY) != binary:
        raise FixtureError("release executable changed")
    for name, denied in (("client.yml", False), ("denied.yml", True)):
        if bounded_read(root / name, 4096) != client_config(denied):
            raise FixtureError("synthetic client configuration changed")
    return root, state


def container_arguments(root, state, network, image, denied, name):
    config = root / ("denied.yml" if denied else "client.yml")
    return ["docker", "create", "--name", name, "--label", LABEL + "=" + state["id"],
        "--network", network, "--user", "65534:65534", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--memory=128m", "--memory-swap=128m",
        "--cpus=0.5", "--pids-limit=32", "--log-driver=none", "--pull=never",
        "--mount", "type=bind,src=" + str(root / "neo") + ",dst=/neo,readonly",
        "--mount", "type=bind,src=" + str(config) + ",dst=/client.yml,readonly",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=4194304,mode=0700,uid=65534,gid=65534",
        "--entrypoint", "/neo", image, "--verbose=false", "--config", "/client.yml", "info"]


def cleanup(name, identity):
    label = shared.checked(["docker", "inspect", "--format",
        '{{index .Config.Labels "' + LABEL + '"}}', name], capture=True).decode().strip()
    if label != identity:
        raise FixtureError("release probe cleanup blocked: container ownership mismatch")
    shared.checked(["docker", "rm", "--force", name], timeout=15)


def capture(argv, timeout=25):
    """Bound combined output in memory; never persist potentially sensitive info."""
    output = bytearray()
    done, overflow = threading.Event(), threading.Event()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def reader():
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                if len(output) + len(chunk) > MAX_OUTPUT:
                    overflow.set()
                    break
                output.extend(chunk)
        finally:
            done.set()

    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout
    try:
        while not done.wait(0.05):
            if time.monotonic() >= deadline:
                raise FixtureError("release client timed out; raw output suppressed")
        if overflow.is_set():
            raise FixtureError("release client output exceeded limit; raw output suppressed")
        return process.wait(timeout=max(0.1, deadline - time.monotonic())), bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        worker.join(timeout=1)
        process.stdout.close()


def probe(root, state, network, image, denied):
    name = state["id"] + "-" + secrets.token_hex(4)
    # Generated exact name plus ownership label makes failure cleanup scoped.
    try:
        shared.checked(container_arguments(root, state, network, image, denied, name))
    except FixtureError as error:
        # A timed-out Docker create can still have created this exact container.
        # Never broaden cleanup to another name or an unlabelled resource.
        try:
            cleanup(name, state["id"])
        except FixtureError:
            raise FixtureError("release client creation failed; inspect exact generated probe " + name +
                               " before manual cleanup; raw output suppressed") from error
        raise
    try:
        return capture(["docker", "start", "--attach", name])
    finally:
        cleanup(name, state["id"])


def smoke(args):
    root, state = fixture(args.workspace)
    stack_root, stack = shared.fixture(args.stack_workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "smoke", "release": RELEASE,
                "effects": ["two temporary info-only clients on validated internal fixture network"],
                "not_validated": NOT_VALIDATED}
    command = shared.compose_command(stack_root, stack)
    shared.wait_ready(shared.farm_port(command))
    project, network = stack["project"], stack["project"] + "_fixture"
    actual = shared.checked(["docker", "network", "inspect", "--format",
        '{{.Internal}};{{index .Labels "com.docker.compose.project"}};{{index .Labels "com.docker.compose.network"}}',
        network], capture=True).decode().strip()
    if actual != "true;" + project + ";fixture":
        raise FixtureError("expected project-owned internal fixture network unavailable")
    container = shared.checked(command + ["ps", "--quiet", "neo-server"], capture=True).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", container):
        raise FixtureError("expected running Neo server unavailable")
    server = shared.checked(["docker", "inspect", "--format",
        '{{.State.Running}};{{index .Config.Labels "com.docker.compose.project"}};{{index .Config.Labels "com.docker.compose.service"}};{{.Image}}',
        container], capture=True).decode().strip().split(";")
    if len(server) != 4 or server[:3] != ["true", project, "neo-server"] or not re.fullmatch(r"sha256:[a-f0-9]{64}", server[3]):
        raise FixtureError("Neo server ownership or state mismatch")
    image = stack["images"]["alpine"]
    arch = shared.checked(["docker", "image", "inspect", "--format", "{{.Os}};{{.Architecture}}", image],
                          capture=True).decode().strip()
    if arch != "linux;amd64":
        raise FixtureError("release smoke requires cached native Linux amd64 runtime image")
    code, valid = probe(root, state, network, image, False)
    denied_code, denied = probe(root, state, network, image, True)
    checks = {"published_release_info": code == 0 and all(marker in valid for marker in
              (b"config:", b"IPs buckets:", b"Exploits:")),
              "wrong_key_rejected": denied_code != 0 and b"Unauthenticated" in denied}
    return {"schema": "durkahelper.neo-release-smoke.v1", "status": "PASS" if all(checks.values()) else "FAIL",
            "release": RELEASE, "archive_sha256": SHA256, "server_source": shared.PINS["neo"],
            "server_image_id": server[3], "runtime_image": image, "runtime_architecture": "linux/amd64",
            "checks": checks, "not_validated": NOT_VALIDATED,
            "scope": "published release-client info/auth against retained-source synthetic server/farm only",
            "rollback": "owned one-shot clients removed; existing stack and prepared files retained"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "smoke"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--stack-workspace")
    parser.add_argument("--lock", default=str(Path(__file__).resolve().parents[1] / "config/toolchain.lock.json"))
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--archive")
    source.add_argument("--download", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise FixtureError("mutations require a non-secret approval identifier")
        if args.action == "prepare" and not (args.archive or args.download):
            raise FixtureError("prepare requires --archive or explicit --download")
        if args.action == "smoke" and not args.stack_workspace:
            raise FixtureError("smoke requires an approved --stack-workspace")
        result = prepare(args) if args.action == "prepare" else smoke(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if result["status"] == "FAIL" else 0
    except (FixtureError, OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, FixtureError) else "operation failed: " + type(error).__name__
        print(json.dumps({"status": "BLOCKED", "reason": reason, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
