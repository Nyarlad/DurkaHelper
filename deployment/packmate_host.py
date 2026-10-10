#!/usr/bin/env python3
"""Opt-in native Linux host-interface Packmate; never a Desktop capture fallback.

The entire selected interface must be approved: unchanged upstream briefly uses
a broad TCP/UDP filter at startup. Host networking and NET_RAW are explicit
trust-boundary expansions. No interface, route or firewall is modified here.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

SPEC = importlib.util.spec_from_file_location("host_live", Path(__file__).with_name("packmate_live.py"))
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)
kit, shared, Error = live.kit, live.shared, live.Error
SCHEMA = "durkahelper.packmate-host.v1"
LABEL = "io.durkahelper.packmate-host"


def profile(value):
    keys = {"schema", "daemon_id", "interface", "ifindex", "interface_mac", "local_ip",
            "bind_address", "ui_port", "db_port", "tcp_timeout_seconds", "udp_timeout_seconds",
            "timeout_check_seconds", "retention_minutes", "cleanup_interval_minutes"}
    if not isinstance(value, dict) or set(value) != keys or value["schema"] != SCHEMA:
        raise Error("invalid host capture profile")
    if not isinstance(value["daemon_id"], str) or not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", value["daemon_id"]):
        raise Error("exact approved Engine identity required")
    if not isinstance(value["interface"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", value["interface"]):
        raise Error("one explicit Linux interface is required; any is not supported")
    if value["interface"] == "any":
        raise Error("any-interface capture is forbidden")
    if type(value["ifindex"]) is not int or not 1 <= value["ifindex"] <= 2**31 - 1:
        raise Error("exact interface index required")
    if not isinstance(value["interface_mac"], str) or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", value["interface_mac"]):
        raise Error("exact interface hardware address required")
    for key in ("local_ip", "bind_address"):
        address = ipaddress.ip_address(value[key])
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise Error("explicit unicast IPv4 required")
    for key, lower, upper in (("ui_port", 1024, 65535), ("db_port", 1024, 65535),
                              ("tcp_timeout_seconds", 1, 600), ("udp_timeout_seconds", 1, 600),
                              ("timeout_check_seconds", 1, 60), ("retention_minutes", 1, 1440),
                              ("cleanup_interval_minutes", 1, 60)):
        if type(value[key]) is not int or not lower <= value[key] <= upper:
            raise Error("invalid bounded host capture setting")
    if value["ui_port"] == value["db_port"]:
        raise Error("UI and loopback database ports must differ")
    return value


def properties(config, secret):
    # Reuse the pinned upstream field names and exact logger mitigation.
    pairs = dict(line.split("=", 1) for line in live.properties(config, secret, "unused").decode("ascii").splitlines())
    pairs.update({"spring.datasource.url": "jdbc:postgresql://127.0.0.1:" + str(config["db_port"]) + "/packmate",
                  "server.address": config["bind_address"], "server.port": str(config["ui_port"])})
    return "".join(key + "=" + str(value) + "\n" for key, value in sorted(pairs.items())).encode("ascii")


def compose_spec(config, secret, project, images=None):
    images = images or {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}
    base = {"restart": "no", "cpus": 1.0, "mem_limit": "512m", "pids_limit": 128,
            "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"}, "labels": {LABEL: project}}
    db = dict(base, image=images["db"], platform="linux/amd64",
              environment={"POSTGRES_DB": "packmate", "POSTGRES_USER": "packmate", "POSTGRES_PASSWORD": secret["db_password"]},
              volumes=["./data/postgres:/var/lib/postgresql/data"], networks=["database"],
              ports=[{"target": 5432, "published": str(config["db_port"]), "host_ip": "127.0.0.1", "protocol": "tcp"}],
              healthcheck={"test": ["CMD", "pg_isready", "-U", "packmate", "-d", "packmate"],
                           "interval": "2s", "timeout": "2s", "retries": 45})
    app = dict(base, image=images["packmate"], platform="linux/amd64", user="0:0", read_only=True,
               cap_drop=["ALL"], cap_add=["NET_RAW"], network_mode="host", mem_limit="1536m",
               tmpfs=["/tmp:size=67108864,mode=1777,noexec,nosuid,nodev", "/jna:size=16777216,mode=0700,nosuid,nodev,exec"],
               volumes=["./application.properties:/configuration/application.properties:ro"], entrypoint=["java"],
               command=["-Xms64m", "-Xmx768m", "-XX:ActiveProcessorCount=1", "-Djna.tmpdir=/jna",
                        "-Djava.net.preferIPv4Stack=true", "-jar", "/app/app.jar",
                        "--spring.config.additional-location=file:/configuration/application.properties"],
               depends_on={"db": {"condition": "service_healthy"}})
    return {"services": {"db": db, "packmate": app}, "networks": {"database": {"labels": {LABEL: project}}}}


def prepare(args):
    config, secret = profile(kit.load(args.profile)), live.credentials(kit.load(args.credentials))
    root = kit.safe_path(args.workspace)
    if root.exists() or not root.parent.is_dir():
        raise Error("new workspace with existing private parent required")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "daemon_contacted": False,
                "capture_started": False, "requires": "approved entire interface, host networking and NET_RAW"}
    if os.name != "posix":
        raise Error("host capture preparation requires POSIX")
    if root.parent.stat().st_uid != os.getuid() or root.parent.stat().st_mode & 0o077:
        raise Error("workspace parent must be owned and mode 0700")
    state = {"schema": SCHEMA, "project": "dh-host-" + secrets.token_hex(6), "profile": config, "credentials": secret}
    root.mkdir(mode=0o700)
    shared.write(root / "state.json", shared.canonical(state))
    shared.write(root / "compose.json", shared.canonical(compose_spec(config, secret, state["project"])))
    shared.write(root / "application.properties", properties(config, secret))
    # Root with DAC_OVERRIDE dropped cannot read the operator-owned 0600 file.
    # Only this individually mounted file is readable by the container; its
    # parent remains 0700, and the credential ledger is never made public.
    (root / "application.properties").chmod(0o644)
    (root / "data").mkdir(mode=0o700)
    (root / "data/postgres").mkdir(mode=0o700)
    return {"status": "PASS", "action": "prepare", "capture_started": False}


def workspace(path):
    root = kit.safe_path(path)
    if not root.is_dir() or (os.name == "posix" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077)):
        raise Error("private owned workspace required")
    state = kit.load(root / "state.json")
    if (not isinstance(state, dict) or set(state) != {"schema", "project", "profile", "credentials"} or
            state["schema"] != SCHEMA or not isinstance(state["project"], str) or
            not re.fullmatch(r"dh-host-[a-f0-9]{12}", state["project"])):
        raise Error("invalid host capture state")
    profile(state["profile"])
    live.credentials(state["credentials"])
    for name, expected in {"compose.json": shared.canonical(compose_spec(state["profile"], state["credentials"], state["project"])),
                           "application.properties": properties(state["profile"], state["credentials"])}.items():
        if kit.read(root / name) != expected:
            raise Error("immutable host capture configuration changed")
    for name in ("data", "data/postgres"):
        if (root / name).is_symlink() or not (root / name).is_dir():
            raise Error("host capture data must remain ordinary directories")
    return root, state


def interface(config):
    data = json.loads(shared.checked(["ip", "-json", "link", "show", "dev", config["interface"]], capture=True))
    if (not isinstance(data, list) or len(data) != 1 or data[0].get("ifname") != config["interface"] or
            data[0].get("ifindex") != config["ifindex"] or data[0].get("address") != config["interface_mac"] or
            "UP" not in data[0].get("flags", [])):
        raise Error("approved interface identity or UP state changed")


def local_engine():
    """Host-interface approval must refer to this kernel, never a remote daemon."""
    if any(os.environ.get(name) for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")):
        raise Error("host capture refuses Docker endpoint override variables; use the local standard Engine context")
    endpoint = json.loads(shared.checked(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker}}"], capture=True))
    if not isinstance(endpoint, dict) or endpoint.get("Host") != "unix:///var/run/docker.sock":
        raise Error("host capture requires the local standard Unix Docker socket, not a remote context")
    metadata = Path("/var/run/docker.sock").lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
        raise Error("host capture requires a real root-owned local Docker socket")
    observed = json.loads(shared.checked(["docker", "info", "--format",
        '{"security":{{json .SecurityOptions}},"kernel":{{json .KernelVersion}}}'], capture=True))
    if (not isinstance(observed, dict) or not isinstance(observed.get("security"), list) or
            any(not isinstance(value, str) or "rootless" in value.lower() for value in observed["security"]) or
            observed.get("kernel") != os.uname().release):
        raise Error("host capture requires the local rootful Engine on this kernel")


def image_ids(images):
    if not isinstance(images, dict) or set(images) != {"packmate", "db"} or any(
            not isinstance(v, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", v) for v in images.values()):
        raise Error("invalid cached host capture image receipt")
    return images


def receipt_images(root):
    return image_ids(kit.load(root / "images.json"))


def fresh_runtime(root):
    # lexists, rather than exists, also rejects a dangling symlink. A partial
    # previous publication is deliberately not repaired or overwritten here.
    if any(os.path.lexists(root / name) for name in ("images.json", "runtime-compose.json")):
        raise Error("bootstrap requires a fresh workspace without runtime or image receipt")


def bootstrap_receipt(root, path, expected_sha256):
    """Detached operator approval binds IDs reviewed against the pinned refs.

    The receipt does not prove upstream provenance on its own. It is portable
    between approved daemons only after the independently recorded hash is
    checked; Docker is never contacted while validating this input.
    """
    fresh_runtime(root)
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise Error("bootstrap requires an independently approved canonical image receipt SHA-256")
    source = kit.safe_path(path)
    before = source.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_size > 4096 or before.st_nlink != 1 or
            (os.name == "posix" and (before.st_uid != os.getuid() or before.st_mode & 0o077))):
        raise Error("bootstrap receipt must be a private owned bounded regular file")

    def stamp(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
                metadata.st_ctime_ns, metadata.st_mode, metadata.st_uid, metadata.st_nlink)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Error("duplicate bootstrap receipt key")
            result[key] = value
        return result

    content = kit.read(source, limit=4096)
    if stamp(source.lstat()) != stamp(before):
        raise Error("bootstrap receipt changed while reading")
    images = image_ids(json.loads(content, object_pairs_hook=unique))
    if len(set(images.values())) != 2:
        raise Error("bootstrap requires distinct application and database image IDs")
    if hashlib.sha256(shared.canonical(images)).hexdigest() != expected_sha256:
        raise Error("bootstrap receipt differs from independently approved canonical checksum")
    return images, (stamp(before), content)


def publish_bootstrap(root, payload, identities):
    """No-replace publication, retaining descriptors until both paths verify.

    On an interrupted or raced publication, keep partial files for inspection;
    they are never repaired automatically and cannot trigger container startup.
    """
    fresh_runtime(root)
    parent = root.lstat()
    descriptors = []
    try:
        for name, content in (("runtime-compose.json", payload), ("images.json", shared.canonical(identities))):
            current = root.lstat()
            if (not stat.S_ISDIR(current.st_mode) or
                    (current.st_dev, current.st_ino) != (parent.st_dev, parent.st_ino)):
                raise Error("bootstrap workspace changed during publication")
            path = root / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
            descriptors.append((descriptor, path, content))
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(descriptor)
        for descriptor, path, content in descriptors:
            held, named = os.fstat(descriptor), path.lstat()
            if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or
                    (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or
                    kit.read(path) != content):
                raise Error("bootstrap publication changed; partial workspace retained for inspection")
        current = root.lstat()
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (parent.st_dev, parent.st_ino):
            raise Error("bootstrap workspace changed during publication")
    finally:
        for descriptor, _, _ in descriptors:
            os.close(descriptor)


def owned(root, state, images=None):
    """Validate exact project IDs, immutable images and mounts without foreign logs."""
    project = state["project"]
    if not isinstance(project, str) or not re.fullmatch(r"dh-host-[a-f0-9]{12}", project):
        raise Error("invalid host capture ownership project")
    def listing(argv, maximum):
        values = shared.checked(argv, capture=True).decode().split()
        if len(values) > maximum or len(set(values)) != len(values) or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in values):
            raise Error("unexpected host capture resource inventory")
        return values

    identifiers = listing(["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project], 2)
    images = (image_ids(images) if images is not None else receipt_images(root)) if identifiers else None
    current = {}
    fmt = ('{"id":{{json .Id}},"labels":{{json .Config.Labels}},"image":{{json .Image}},'
           '"running":{{json .State.Running}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}},'
           '"mode":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
           '"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
           '"caps":{{json .HostConfig.CapAdd}},"drop":{{json .HostConfig.CapDrop}}}')
    physical = project + "_database"
    for identity in identifiers:
        value = json.loads(shared.checked(["docker", "container", "inspect", "--format", fmt, identity], capture=True))
        labels, mounts = value.get("labels") or {}, value.get("mounts")
        service = labels.get("com.docker.compose.service")
        if (value.get("id") != identity or labels.get("com.docker.compose.project") != project or
                labels.get(LABEL) != project or service not in {"db", "packmate"} or service in current or
                value.get("image") != images[service] or value.get("privileged") is not False or
                type(value.get("running")) is not bool or not isinstance(mounts, list)):
            raise Error("host capture resource ownership, service or image mismatch")
        expected = {"/configuration/application.properties": (str(root / "application.properties"), False)} if service == "packmate" else {
            "/var/lib/postgresql/data": (str(root / "data/postgres"), True)}
        actual = {item.get("Destination"): (item.get("Source"), item.get("RW")) for item in mounts if item.get("Type") == "bind"}
        tmpfs = {"/tmp", "/jna"} if service == "packmate" else set()
        if (actual != expected or any(item.get("Type") != "bind" and not (item.get("Type") == "tmpfs" and
                item.get("Destination") in tmpfs) for item in mounts)):
            raise Error("host capture bind mounts differ from the private workspace")
        if service == "packmate":
            if (value.get("mode") != "host" or set(value.get("networks") or {}) != {"host"} or
                    value.get("ports") not in (None, {}) or value.get("readonly") is not True or
                    value.get("caps") not in (["NET_RAW"], ["CAP_NET_RAW"]) or value.get("drop") != ["ALL"]):
                raise Error("host capture runtime privilege or network boundary changed")
        else:
            ports = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(state["profile"]["db_port"])}]}
            if value.get("mode") != physical or set(value.get("networks") or {}) != {physical} or value.get("ports") != ports:
                raise Error("host capture database network or loopback publication changed")
        current[service] = value
    networks = listing(["docker", "network", "ls", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project], 1)
    # A name collision without our ownership labels must be rejected before up.
    exact = listing(["docker", "network", "ls", "--quiet", "--no-trunc", "--filter", "name=^" + re.escape(physical) + "$"], 1)
    if set(exact) != set(networks):
        raise Error("host capture database network name or ownership collision")
    for identity in networks:
        fmt = '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"containers":{{json .Containers}},"internal":{{json .Internal}}}'
        value = json.loads(shared.checked(["docker", "network", "inspect", "--format", fmt, identity], capture=True))
        labels = value.get("labels") or {}
        expected_members = {current["db"]["id"]} if current.get("db", {}).get("running") else set()
        if (value.get("id") != identity or value.get("name") != physical or labels.get(LABEL) != project or
                labels.get("com.docker.compose.project") != project or value.get("internal") is not False or
                not isinstance(value.get("containers"), dict) or set(value["containers"]) != expected_members):
            raise Error("host capture database network isolation or membership changed")
        if "db" in current and current["db"]["networks"][physical].get("NetworkID") != identity:
            raise Error("host capture database network identity mismatch")
    if "db" in current and not networks:
        raise Error("host capture database network missing")
    return current


def runtime(root, state, expected_images_sha256=None, bootstrap_images=None):
    receipt = root / "images.json"
    bootstrap_identity = None
    if bootstrap_images is not None:
        images, bootstrap_identity = bootstrap_receipt(root, bootstrap_images, expected_images_sha256)
    elif receipt.exists():
        images = receipt_images(root)
        checksum = hashlib.sha256(shared.canonical(images)).hexdigest()
        if expected_images_sha256 is not None and expected_images_sha256 != checksum:
            raise Error("host capture image receipt differs from independently approved checksum")
        # An operator-recorded checksum enables tag-free Docker save/load. If
        # none is supplied, independently resolve the pinned upstream refs on
        # each launch; a mutable receipt alone never authorizes another image.
        if expected_images_sha256 is None:
            for name, reference in {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}.items():
                observed = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}}", reference], capture=True).decode().strip()
                if observed != images[name]:
                    raise Error("host capture image receipt differs from pinned upstream image")
    else:
        images = {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}
        if expected_images_sha256 is not None:
            raise Error("no cached image receipt exists to bind the independently approved checksum")
    identities = {}
    for name, reference in images.items():
        observed = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", reference], capture=True).decode().strip().split(";")
        if (len(observed) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", observed[0]) or observed[1:] != ["linux", "amd64"] or
                (reference.startswith("sha256:") and reference != observed[0])):
            raise Error("host capture image identity or architecture mismatch")
        identities[name] = observed[0]
    payload = shared.canonical(compose_spec(state["profile"], state["credentials"], state["project"], identities))
    if bootstrap_images is not None:
        # The source and both destination names must still match the approved
        # preflight after Docker inspection. No partial state is overwritten.
        verified, current_identity = bootstrap_receipt(root, bootstrap_images, expected_images_sha256)
        if current_identity != bootstrap_identity or verified != identities:
            raise Error("bootstrap receipt changed during image inspection")
        publish_bootstrap(root, payload, identities)
    elif receipt.exists():
        if kit.read(root / "runtime-compose.json") != payload:
            raise Error("host capture runtime changed")
    else:
        shared.write(root / "runtime-compose.json", payload)
        shared.write(receipt, shared.canonical(identities))
    return hashlib.sha256(shared.canonical(identities)).hexdigest()


def command(root, state, runtime=False):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(root),
            "--file", str(root / ("runtime-compose.json" if runtime else "compose.json"))]


def execute(args):
    root, state = workspace(args.workspace)
    config = state["profile"]
    bootstrap = getattr(args, "bootstrap_images", None)
    if bootstrap is not None:
        if args.action != "up":
            raise Error("bootstrap images are accepted only for the first up")
        bootstrap_receipt(root, bootstrap, getattr(args, "expected_images_sha256", None))
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "daemon_contacted": False,
                "capture_scope": "entire approved host interface; upstream startup filter is TCP/UDP"}
    if not sys.platform.startswith("linux"):
        raise Error("host capture requires native Linux, not Docker Desktop")
    if args.action == "up" and not (args.host_network_approved and args.interface_scope_approved and
                                    args.capture_approval == config["interface"] + ":" + str(config["ifindex"]) + ":" + config["interface_mac"]):
        raise Error("up requires exact interface capture approval, whole-interface scope and host-network approval")
    local_engine()
    live.daemon(config)
    owned(root, state)
    if args.action == "down":
        shared.checked(command(root, state) + ["down", "--timeout", "10"], timeout=60)
        return {"status": "PASS", "action": "down", "data_retained": True, "interface_unchanged": True}
    interface(config)
    checksum = runtime(root, state, getattr(args, "expected_images_sha256", None), bootstrap)
    shared.checked(command(root, state, True) + ["config", "--quiet"])
    shared.checked(command(root, state, True) + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
    live.ready(config, state["credentials"])
    current = owned(root, state)
    if set(current) != {"db", "packmate"} or not all(value["running"] for value in current.values()):
        raise Error("host capture readiness is not bound to exactly two owned running services")
    return {"status": "PASS", "action": "up", "authenticated_capture_started": True,
            "traffic_correctness": "NOT_RUN", "retention": "age policy, not a hard disk quota",
            "network_scope": "explicit host network; DB published only on IPv4 loopback",
            "not_validated": ["actual event interface", "physical team LAN", "sustained load", "hard storage bound"],
            "images_sha256": checksum, "offline_note": "record this checksum independently for tag-free restart approval",
            "rollback": "down with same workspace, apply and approval ID; data retained"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "up", "down"])
    parser.add_argument("--workspace", required=True)
    for name in ("profile", "credentials", "approval-id", "capture-approval", "expected-images-sha256", "bootstrap-images"):
        parser.add_argument("--" + name)
    for name in ("apply", "host-network-approved", "interface-scope-approved"):
        parser.add_argument("--" + name, action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and non-secret --approval-id")
        if args.action == "prepare" and not (args.profile and args.credentials):
            raise Error("prepare requires private profile and credentials")
        if args.bootstrap_images is not None and args.action != "up":
            raise Error("bootstrap images are accepted only for the first up")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else "host capture operation rejected; raw details suppressed",
                          "rollback": "down only this workspace with apply/approval; databases retained; inspect partial resources before retry"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
