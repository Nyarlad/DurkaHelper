#!/usr/bin/env python3
"""Operator-side SSH deployment of existing Packmate host LIVE, including offline images.

Python runs ONLY on the operator workstation. The target needs native Linux
amd64, local rootful Docker/Compose, sh, tar, ip, ss, stat, df and sha256sum.
No package installs, remote pulls, firewall changes or foreign cleanup.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tarfile
import time

SPEC = importlib.util.spec_from_file_location("remote_host_live", Path(__file__).with_name("packmate_host.py"))
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)
kit, shared, Error = host.kit, host.shared, host.Error
SCHEMA = "durkahelper.packmate-remote.v1"
REFS = {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}
DEFAULT = "local/packmate-remote.json"


def ssh_settings(value):
    if not isinstance(value, dict) or set(value) != {"target", "port", "key", "known_hosts", "docker"}:
        raise Error("invalid SSH settings")
    if not isinstance(value["target"], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value["target"]):
        raise Error("SSH target must be USER@HOST, not a command")
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise Error("invalid SSH port")
    for field in ("key", "known_hosts"):
        if value[field] is not None and (not isinstance(value[field], str) or not Path(value[field]).is_absolute()):
            raise Error("SSH key and known_hosts paths must be absolute")
    if not isinstance(value["docker"], str) or not re.fullmatch(r"(?:docker|/[A-Za-z0-9_./-]+)", value["docker"]):
        raise Error("Docker must be docker or an absolute approved wrapper path; no shell commands")
    return value


def remote_path(value):
    if not isinstance(value, str) or not re.fullmatch(r"/(?:home/[a-z_][a-z0-9_-]*|root)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value):
        raise Error("use a dedicated absolute directory below /home/USER or /root")
    if any(part in {".", ".."} for part in value.split("/")):
        raise Error("remote directory traversal is forbidden")
    return PurePosixPath(value)


def settings(value):
    if not isinstance(value, dict) or set(value) != {"schema", "ssh", "workspace", "project", "profile", "credentials", "images"} or value["schema"] != SCHEMA:
        raise Error("invalid remote LIVE configuration")
    ssh_settings(value["ssh"])
    remote_path(value["workspace"])
    user = value["ssh"]["target"].split("@", 1)[0]
    prefix = "/root/" if user == "root" else "/home/" + user + "/"
    if not value["workspace"].startswith(prefix):
        raise Error("workspace must be inside the SSH user's own home directory")
    if not re.fullmatch(r"dh-host-[a-f0-9]{12}", value.get("project", "")):
        raise Error("invalid owned project")
    host.profile(value["profile"])
    host.live.credentials(value["credentials"])
    if value["images"] is not None:
        host.image_ids(value["images"])
    return value


def private_config(path):
    path = kit.safe_path(path)
    metadata = path.stat()
    if os.name == "posix" and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
        raise Error("local LIVE config must be owned and mode 0600")
    return path, settings(kit.load(path))


def write_config(path, value, replace=False):
    path = kit.safe_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not replace:
        shared.write(path, shared.canonical(value))
        return
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    shared.write(temporary, shared.canonical(value))
    os.replace(temporary, path)


class SSH:
    def __init__(self, config):
        self.config = ssh_settings(config)

    def argv(self):
        value = self.config
        args = ["ssh", "-T", "-p", str(value["port"]), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UpdateHostKeys=no", "-o", "PermitLocalCommand=no",
                "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2"]
        if value["key"]:
            args += ["-i", value["key"], "-o", "IdentitiesOnly=yes"]
        if value["known_hosts"]:
            args += ["-o", "UserKnownHostsFile=" + value["known_hosts"]]
        return args

    def shell(self, script, data=None, stream=None, timeout=60):
        try:
            result = subprocess.run(self.argv() + [self.config["target"], script], input=data,
                                    stdin=stream if stream is not None else (subprocess.DEVNULL if data is None else None),
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise Error("SSH unavailable or timed out; partial owned state is retained") from error
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise Error("SSH operation failed; check host trust, ssh-agent, approved wrapper and target prerequisites; raw output suppressed")
        return result.stdout

    def checked(self, argv, cwd=None, timeout=60, capture=False, environment=None):
        if argv[0] not in {"docker", "ip"} or cwd is not None or environment is not None:
            raise Error("unlisted remote operation")
        command = ([self.config["docker"]] + argv[1:]) if argv[0] == "docker" else argv
        raw = self.shell('test -z "${DOCKER_HOST}${DOCKER_CONTEXT}${DOCKER_TLS_VERIFY}${DOCKER_CERT_PATH}" && ' + shlex.join(command), timeout=timeout)
        return raw if capture else b""

    @contextlib.contextmanager
    def route(self):
        original = shared.checked
        shared.checked = self.checked
        try:
            yield
        finally:
            shared.checked = original

    def engine(self):
        raw = self.shell("set -eu; test -S /var/run/docker.sock; test ! -L /var/run/docker.sock; "
                         "stat -c %u /var/run/docker.sock; uname -s; uname -m; uname -r").decode().splitlines()
        if len(raw) != 4 or raw[:2] != ["0", "Linux"] or raw[2] not in {"x86_64", "amd64"}:
            raise Error("native Linux amd64 with root-owned Docker socket required")
        endpoint = json.loads(self.checked(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker}}"], capture=True))
        info = json.loads(self.checked(["docker", "info", "--format", "{{json .}}"], capture=True))
        if (endpoint.get("Host") != "unix:///var/run/docker.sock" or info.get("KernelVersion") != raw[3] or
                info.get("OSType") != "linux" or info.get("Architecture") not in {"x86_64", "amd64"} or
                "docker desktop" in info.get("OperatingSystem", "").lower() or
                any("rootless" in item.lower() for item in info.get("SecurityOptions", []))):
            raise Error("local native rootful Engine required; Desktop/remote Docker contexts unsupported")
        compose = self.checked(["docker", "compose", "version", "--short"], capture=True).decode().strip()
        if not re.fullmatch(r"v?2\.[0-9]+\.[0-9]+(?:[A-Za-z0-9_.+-]*)", compose):
            raise Error("Docker Compose v2 required")
        info["durka_compose_version"] = compose
        return info


def inspect_images(check, refs, *, platform=None):
    images = {}
    for name, reference in refs.items():
        command = ["docker", "image", "inspect"]
        if platform is not None:
            command += ["--platform", platform]
        row = check(command + ["--format", "{{.Id}};{{.Os}};{{.Architecture}}", reference], capture=True).decode().strip().split(";")
        if len(row) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", row[0]) or row[1:] != ["linux", "amd64"]:
            raise Error("cached image missing or not Linux amd64; prepare the offline bundle first")
        if reference.startswith("sha256:") and row[0] != reference:
            raise Error("cached image identity changed")
        images[name] = row[0]
    return host.image_ids(images)


def digest_file(path):
    path = kit.safe_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 1024**3:
        raise Error("image archive must be a regular file at most 8 GiB")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if stamp(path.stat()) != stamp(before):
        raise Error("image archive changed while reading")
    return path, digest.hexdigest()


def bundle(path):
    root = kit.safe_path(path)
    value = kit.load(root / "manifest.json")
    if (not isinstance(value, dict) or set(value) != {"schema", "refs", "images", "sha256"} or
            value["schema"] != "durkahelper.packmate-images.v1" or value["refs"] != REFS):
        raise Error("bundle is not for the retained pinned Packmate/PostgreSQL pair")
    host.image_ids(value["images"])
    archive, checksum = digest_file(root / "images.tar")
    if checksum != value["sha256"]:
        raise Error("offline archive checksum mismatch; do not load")
    return archive, value["images"]


def make_bundle(args):
    root = kit.safe_path(args.output)
    if root.exists():
        raise Error("bundle output must be a new directory; existing files are preserved")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "bundle", "downloads": bool(args.download)}
    root.mkdir(mode=0o700, parents=True)
    if args.download:
        for reference in REFS.values():
            shared.checked(["docker", "pull", "--platform", "linux/amd64", reference], timeout=900)
    # Multi-platform stores on ARM Macs retain both PostgreSQL variants. Pulling
    # AMD64 does not change the native default used by image inspect or save.
    images = inspect_images(shared.checked, REFS, platform="linux/amd64")
    # Containerd may expose a platform child ID through inspect without making
    # that ID addressable by save. Resolve the retained digest-pinned names and
    # let the exporter select the verified AMD64 variant; never use floating tags.
    shared.checked(["docker", "image", "save", "--platform", "linux/amd64", "--output", str(root / "images.tar"), *REFS.values()], timeout=900)
    (root / "images.tar").chmod(0o600)
    _, checksum = digest_file(root / "images.tar")
    shared.write(root / "manifest.json", shared.canonical({"schema": "durkahelper.packmate-images.v1", "refs": REFS,
                                                         "images": images, "sha256": checksum}))
    return {"status": "PASS", "action": "bundle", "offline_bundle": str(root), "target_platform": "linux/amd64"}


def init(args):
    path = kit.safe_path(args.config)
    if path.exists():
        raise Error("LIVE config already exists; no overwrite")
    ssh = ssh_settings({"target": args.host, "port": args.ssh_port, "key": str(Path(args.key).expanduser().absolute()) if args.key else None,
                        "known_hosts": str(Path(args.known_hosts).expanduser().absolute()) if args.known_hosts else None, "docker": args.docker})
    remote_path(args.remote_dir)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", args.interface or "") or args.interface == "any":
        raise Error("one approved interface is required")
    client = SSH(ssh)
    info = client.engine()
    rows = json.loads(client.checked(["ip", "-json", "link", "show", "dev", args.interface], capture=True))
    if len(rows) != 1 or "UP" not in rows[0].get("flags", []):
        raise Error("selected interface not UP")
    config = host.profile({"schema": host.SCHEMA, "daemon_id": info["ID"], "interface": args.interface,
                           "ifindex": rows[0]["ifindex"], "interface_mac": rows[0]["address"], "local_ip": args.service_ip,
                           "bind_address": args.bind, "ui_port": args.ui_port, "db_port": args.db_port,
                           "tcp_timeout_seconds": 30, "udp_timeout_seconds": 10, "timeout_check_seconds": 5,
                           "retention_minutes": 60, "cleanup_interval_minutes": 1})
    value = {"schema": SCHEMA, "ssh": ssh, "workspace": args.remote_dir, "project": "dh-host-" + secrets.token_hex(6),
             "profile": config, "credentials": {"username": "operator", "password": secrets.token_hex(24),
                                                "db_password": secrets.token_hex(24)}, "images": None}
    write_config(path, settings(value))
    return {"status": "PASS", "action": "init", "config": str(path), "remote_changed": False,
            "interface": config["interface"], "next": "doctor; then up with explicit capture approvals"}


def discover(args):
    """Read-only target doctor before a local configuration exists."""
    client = SSH({"target": args.host, "port": args.ssh_port, "key": str(Path(args.key).expanduser().absolute()) if args.key else None,
                  "known_hosts": str(Path(args.known_hosts).expanduser().absolute()) if args.known_hosts else None, "docker": args.docker})
    for port in (args.ui_port, args.db_port):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise Error("doctor ports must be between 1024 and 65535")
    if args.interface and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", args.interface) or args.interface == "any"):
        raise Error("doctor requires an ordinary interface name, not any")
    info = client.engine()
    rows = json.loads(client.checked(["ip", "-json", "address", "show"] + (["dev", args.interface] if args.interface else []), capture=True))
    interfaces = [{"name": row["ifname"], "index": row["ifindex"], "mac": row.get("address"), "up": "UP" in row.get("flags", []),
                   "ipv4": [item["local"] for item in row.get("addr_info", []) if item.get("family") == "inet"]} for row in rows]
    disk_path = remote_path(args.remote_dir) if args.remote_dir else PurePosixPath("/home/" + args.host.split("@", 1)[0])
    raw = client.shell(path_guard(disk_path) + "for x in sh tar ip ss stat df sha256sum cut awk; do command -v $x >/dev/null; done; "
                       "awk '/MemAvailable:/ {print $2}' /proc/meminfo; p=" + shlex.quote(str(disk_path)) + "; "
                       'while test ! -d "$p"; do p=${p%/*}; test -n "$p" || p=/; done; df -Pk "$p" | awk \'NR==2 {print $4}\'').decode().split()
    available, disk = [int(item) for item in raw]
    ports = client.shell("ss -H -ltn '( sport = :" + str(args.ui_port) + " or sport = :" + str(args.db_port) + " )'").strip()
    images = "CACHED_AMD64_VERIFIED"
    try:
        inspect_images(client.checked, REFS)
    except Error:
        images = "MISSING_OR_WRONG_PLATFORM"
    blockers = []
    if ports:
        blockers.append("requested_ports_occupied")
    if available < 3072 * 1024:
        blockers.append("available_ram_below_3_gib")
    if disk < 5 * 1024**2:
        blockers.append("free_disk_below_5_gib")
    if args.interface and not any(row["up"] for row in interfaces):
        blockers.append("selected_interface_not_up")
    return {"status": "BLOCKED" if blockers else ("WARNING" if images != "CACHED_AMD64_VERIFIED" else "PASS"), "blockers": blockers,
            "action": "doctor", "read_only": True, "engine_id": info["ID"], "engine": "native-linux-amd64",
            "linux": info.get("OperatingSystem"), "kernel": info.get("KernelVersion"), "docker_version": info.get("ServerVersion"),
            "compose_version": info.get("durka_compose_version"), "cpus": info.get("NCPU"),
            "interfaces": interfaces, "available_ram_mib": available // 1024, "free_disk_mib": disk // 1024,
            "requested_ports": {"ui": args.ui_port, "db_loopback": args.db_port, "occupied": bool(ports)},
            "images": images, "python_on_target": "NOT_REQUIRED", "capture_permission": "NOT_VERIFIED",
            "next": "choose the permitted interface/service IP/UI bind; resolve ports/resources; init config; prepare offline bundle if needed",
            "traffic_visibility": "NOT_VERIFIED: network placement and a known request/response must be checked manually"}


def path_guard(root):
    # Reject symlink ancestors before ANY reads/writes in the target directory.
    return "set -eu; " + "; ".join("test ! -L " + shlex.quote(str(parent)) for parent in [*reversed(root.parents), root]) + "; "


def files(value):
    state = {"schema": host.SCHEMA, "project": value["project"], "profile": value["profile"], "credentials": value["credentials"]}
    return {"state.json": shared.canonical(state), "images.json": shared.canonical(value["images"]),
            "runtime-compose.json": shared.canonical(host.compose_spec(value["profile"], value["credentials"], value["project"], value["images"])),
            "application.properties": host.properties(value["profile"], value["credentials"])}


def verify_workspace(client, value):
    root = remote_path(value["workspace"])
    script = path_guard(root) + "if test ! -e " + shlex.quote(str(root)) + "; then printf MISSING; else "
    script += "test -d " + shlex.quote(str(root)) + "; test \"$(stat -c %u:%a " + shlex.quote(str(root)) + ")\" = \"$(id -u):700\"; "
    for name, content in files(value).items():
        path = shlex.quote(str(root / name))
        mode = "644" if name == "application.properties" else "600"
        script += "test -f " + path + "; test ! -L " + path + "; "
        script += "test \"$(stat -c %u:%a:%h " + path + ")\" = \"$(id -u):" + mode + ":1\"; "
        script += "test \"$(sha256sum " + path + " | cut -d ' ' -f 1)\" = " + hashlib.sha256(content).hexdigest() + "; "
    for name in ("data", "data/postgres"):
        script += "test -d " + shlex.quote(str(root / name)) + "; test ! -L " + shlex.quote(str(root / name)) + "; "
    script += "printf PRESENT; fi"
    return client.shell(script).decode() == "PRESENT"


def upload(client, value):
    root = remote_path(value["workspace"])
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name, content in files(value).items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o644 if name == "application.properties" else 0o600
            archive.addfile(entry, io.BytesIO(content))
    script = path_guard(root) + "umask 077; test ! -e " + shlex.quote(str(root)) + "; "
    script += "mkdir -p " + shlex.quote(str(root.parent)) + "; mkdir " + shlex.quote(str(root)) + "; "
    script += "tar -xf - -C " + shlex.quote(str(root)) + "; chmod 644 " + shlex.quote(str(root / "application.properties")) + "; "
    script += "mkdir -p " + shlex.quote(str(root / "data/postgres"))
    client.shell(script, data=payload.getvalue())
    if not verify_workspace(client, value):
        raise Error("remote transfer incomplete; retain partial workspace for inspection")


def doctor(client, value):
    info = client.engine()
    if info["ID"] != value["profile"]["daemon_id"]:
        raise Error("approved Docker Engine identity changed; review before reinitializing")
    host.interface(value["profile"])
    addresses = json.loads(client.checked(["ip", "-json", "address", "show"], capture=True))
    if not any(item.get("local") == value["profile"]["bind_address"] and item.get("family") == "inet"
               for row in addresses for item in row.get("addr_info", [])):
        raise Error("UI bind address is not assigned to this Linux host")
    current = host.owned(remote_path(value["workspace"]), value, images=value["images"])
    if current and not verify_workspace(client, value):
        raise Error("running owned resources have no matching workspace")
    root = remote_path(value["workspace"])
    script = path_guard(root) + "for x in sh tar ip ss stat df sha256sum cut awk; do command -v $x >/dev/null; done; "
    script += "awk '/MemAvailable:/ {print $2}' /proc/meminfo; p=" + shlex.quote(str(root)) + "; "
    script += 'while test ! -d "$p"; do p=${p%/*}; test -n "$p" || p=/; done; df -Pk "$p" | awk \'NR==2 {print $4}\''
    available, disk = [int(item) for item in client.shell(script).decode().split()]
    if available < (1024 if current else 3072) * 1024 or disk < 5 * 1024**2:
        raise Error("insufficient free resources: need 3 GiB RAM before startup and 5 GiB disk")
    ports = client.shell("ss -H -ltn '( sport = :" + str(value["profile"]["ui_port"]) + " or sport = :" + str(value["profile"]["db_port"]) + " )'").strip()
    if ports and not (set(current) == {"db", "packmate"} and all(item["running"] for item in current.values())):
        raise Error("requested ports are occupied; stop/reconfigure ONLY the known conflicting deployment yourself")
    return {"status": "PASS", "action": "doctor", "read_only": True, "python_on_target": "NOT_REQUIRED",
            "engine": "native-linux-amd64", "interface": value["profile"]["interface"], "ifindex": value["profile"]["ifindex"],
            "linux": info.get("OperatingSystem"), "kernel": info.get("KernelVersion"), "docker_version": info.get("ServerVersion"),
            "compose_version": info.get("durka_compose_version"), "cpus": info.get("NCPU"),
            "available_ram_mib": available // 1024, "free_disk_mib": disk // 1024,
            "owned_services": {key: item["running"] for key, item in current.items()},
            "capture_permission": "NOT_VERIFIED until explicit approved up", "traffic_correctness": "NOT_TESTED"}


@contextlib.contextmanager
def tunnel(client, profile):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = client.argv() + ["-N", "-o", "ExitOnForwardFailure=yes", "-L",
                               "127.0.0.1:" + str(port) + ":" + profile["bind_address"] + ":" + str(profile["ui_port"]), client.config["target"]]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            if process.poll() is not None:
                raise Error("SSH readiness tunnel failed; forwarding must be permitted")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise Error("SSH readiness tunnel did not open")
        yield {"bind_address": "127.0.0.1", "ui_port": port}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run(args):
    if args.action == "bundle":
        return make_bundle(args)
    if args.action == "init":
        return init(args)
    if args.action == "doctor" and args.host:
        return discover(args)
    path, value = private_config(args.config)
    if args.action == "password":
        if sys.platform != "darwin":
            raise Error("clipboard helper is Mac-only; use the private credentials.password field without screen sharing")
        subprocess.run(["/usr/bin/pbcopy"], input=value["credentials"]["password"].encode("ascii"), check=True)
        return {"status": "PASS", "action": "password", "username": value["credentials"]["username"], "password": "COPIED_NOT_PRINTED"}
    if args.action in {"up", "down"} and not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "requires": "--apply; up also requires whole-interface and host-network approvals"}
    if args.action == "up" and not (args.host_network_approved and args.interface_scope_approved):
        raise Error("up requires --host-network-approved --interface-scope-approved for the configured entire interface")
    client = SSH(value["ssh"])
    with client.route():
        if args.action == "down":
            info = client.engine()
            if info["ID"] != value["profile"]["daemon_id"] or value["images"] is None or not verify_workspace(client, value):
                raise Error("down requires the original Engine and intact owned workspace")
            host.owned(remote_path(value["workspace"]), value, images=value["images"])
            client.checked(host.command(remote_path(value["workspace"]), value, runtime=True) + ["down", "--timeout", "10"], timeout=90)
            return {"status": "PASS", "action": "down", "data_retained": True}
        report = doctor(client, value)
        if args.action == "status":
            return dict(report, action="status", url="http://" + value["profile"]["bind_address"] + ":" + str(value["profile"]["ui_port"]))
        archive = None
        if args.bundle:
            archive, images = bundle(args.bundle)
        else:
            try:
                images = inspect_images(client.checked, REFS if value["images"] is None else value["images"])
            except Error:
                if args.action == "doctor":
                    return dict(report, status="WARNING", images="MISSING_OR_WRONG_PLATFORM", next="prepare bundle and pass --bundle; no downloads on target")
                raise
        if args.action == "doctor":
            return dict(report, images="OFFLINE_BUNDLE_VERIFIED" if archive else "CACHED_AMD64_VERIFIED", remote_changed=False)
        if value["images"] is not None and images != value["images"]:
            raise Error("image identities differ from this deployment; do not upgrade implicitly")
        if archive:
            try:
                inspect_images(client.checked, images)
            except Error:
                with archive.open("rb") as stream:
                    client.shell('test -z "${DOCKER_HOST}${DOCKER_CONTEXT}${DOCKER_TLS_VERIFY}${DOCKER_CERT_PATH}" && ' +
                                 shlex.join([value["ssh"]["docker"], "image", "load"]), stream=stream, timeout=900)
                _, rechecked = bundle(args.bundle)
                if rechecked != images:
                    raise Error("offline bundle changed during transfer; startup blocked")
                inspect_images(client.checked, images)
        value["images"] = images
        write_config(path, value, replace=True)
        if not verify_workspace(client, value):
            upload(client, value)
        host.owned(remote_path(value["workspace"]), value, images=images)
        host.interface(value["profile"])
        doctor(client, value)
        command = host.command(remote_path(value["workspace"]), value, runtime=True)
        client.checked(command + ["config", "--quiet"])
        client.checked(command + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
        with tunnel(client, value["profile"]) as endpoint:
            host.live.ready(endpoint, value["credentials"])
        current = host.owned(remote_path(value["workspace"]), value, images=images)
        if set(current) != {"db", "packmate"} or not all(item["running"] for item in current.values()):
            raise Error("exactly two owned running services required")
        return {"status": "PASS", "action": "up", "authenticated_capture_started": True, "traffic_correctness": "NOT_TESTED",
                "url": "http://" + value["profile"]["bind_address"] + ":" + str(value["profile"]["ui_port"]),
                "username": value["credentials"]["username"], "password_command": "durka.py traffic live password --config " + str(path),
                "retention": "age cleanup, not hard disk quota", "rollback": "traffic live down --config SAME_CONFIG --apply"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "doctor", "preflight", "bundle", "up", "status", "down", "password"])
    parser.add_argument("--config", default=DEFAULT, help="private remote LIVE config; separate from the local farm config")
    parser.add_argument("--host", help="approved USER@HOST")
    parser.add_argument("--key", help="existing SSH identity; load encrypted identities into ssh-agent first")
    parser.add_argument("--known-hosts", help="existing verified known_hosts; never auto-accept host keys")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--docker", default="docker", help="docker or absolute path of existing approved wrapper")
    parser.add_argument("--remote-dir", help="new dedicated directory on Linux; never overwrites existing deployment")
    parser.add_argument("--interface", help="entire approved Linux capture interface, never any")
    parser.add_argument("--service-ip", help="service-side IPv4 in captured traffic")
    parser.add_argument("--bind", help="explicit Linux UI IPv4")
    parser.add_argument("--ui-port", type=int, default=65000)
    parser.add_argument("--db-port", type=int, default=55432)
    parser.add_argument("--bundle", help="prepared local offline image directory")
    parser.add_argument("--output", help="new local offline image directory for bundle")
    for flag in ("apply", "download", "host-network-approved", "interface-scope-approved"):
        parser.add_argument("--" + flag, action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            args.action = "doctor"
        if args.action == "init" and not all((args.host, args.remote_dir, args.interface, args.service_ip, args.bind)):
            raise Error("init requires --host --remote-dir --interface --service-ip --bind")
        if args.action == "bundle" and not args.output:
            raise Error("bundle requires --output NEW_DIRECTORY")
        result = run(args)
        print(json.dumps(result, sort_keys=True))
        return 2 if result.get("status") == "BLOCKED" else 0
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "action": args.action,
                          "reason": str(error) if isinstance(error, Error) else "operation failed (" + type(error).__name__ + "); raw details suppressed",
                          "rollback": "retain partial files/data; down only the matching config with --apply; no automatic removal"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
