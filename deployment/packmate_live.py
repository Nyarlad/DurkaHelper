#!/usr/bin/env python3
"""Explicitly approved Linux container-namespace LIVE capture, unchanged Packmate.

The namespace owner must already publish the selected UI port and carry the
approved ownership label. Its single user-defined bridge is shared with the
private (unpublished) database: every bridge peer is inside the trust boundary.
Host capture, Docker Desktop and automatic network changes are unsupported.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

_SPEC = importlib.util.spec_from_file_location("live_toolkit", Path(__file__).with_name("toolkit.py"))
kit = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(kit)
shared, Error = kit.shared, kit.Error
SCHEMA = "durkahelper.packmate-live.v1"
LABEL = "io.durkahelper.packmate-live"
CAPTURE_LABEL = "io.durkahelper.capture-scope"
PORT = 65000
API = re.compile(r"/(?:$|api/(?:service/|pattern/|pcap/(?:started|start|stop)|stream/[1-9][0-9]{0,4}|packet/[1-9][0-9]{0,18}))\Z")
NOT_VALIDATED = ["host or mirrored-interface capture", "Docker Desktop", "team LAN", "real Vulnbox traffic",
                 "packet loss under load", "hard storage quota", "60 minute sustained capture", "actual Mac"]


def profile(value):
    keys = {"schema", "daemon_id", "capture_container", "network_id", "capture_scope", "interface", "local_ip",
            "bind_address", "ui_port", "tcp_timeout_seconds", "udp_timeout_seconds", "timeout_check_seconds",
            "retention_minutes", "cleanup_interval_minutes"}
    if not isinstance(value, dict) or set(value) != keys or value["schema"] != SCHEMA:
        raise Error("invalid LIVE profile; only explicitly approved container namespace mode is supported")
    for key, pattern in (("daemon_id", r"[A-Za-z0-9:_.-]{8,128}"), ("capture_container", r"[a-f0-9]{64}"),
                         ("network_id", r"[a-f0-9]{64}"), ("capture_scope", r"[A-Za-z0-9_.-]{1,80}")):
        if not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]):
            raise Error("invalid LIVE identity")
    # A single ordinary bridge endpoint has eth0. Multi-network, host, loopback,
    # interface aliases and guessed mirrored interfaces require separate review.
    if value["interface"] != "eth0":
        raise Error("this profile supports only a reviewed single-bridge eth0 namespace")
    for key in ("local_ip", "bind_address"):
        address = ipaddress.ip_address(value[key])
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise Error("LIVE addresses must be explicit unicast IPv4 addresses")
        if key == "local_ip" and address.is_loopback:
            raise Error("capture local IP must be the inspected bridge endpoint")
    for key, maximum in (("ui_port", 65535), ("tcp_timeout_seconds", 600), ("udp_timeout_seconds", 600),
                         ("timeout_check_seconds", 60), ("retention_minutes", 1440), ("cleanup_interval_minutes", 60)):
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise Error("invalid LIVE bounded policy value")
    return value


def credentials(value):
    if not isinstance(value, dict) or set(value) != {"username", "password", "db_password"}:
        raise Error("invalid LIVE credential fields")
    for key, text in value.items():
        pattern = r"[A-Za-z0-9_.-]{4,64}" if key == "username" else r"[A-Za-z0-9_.-]{20,128}"
        if not isinstance(text, str) or not re.fullmatch(pattern, text) or text.startswith("REPLACE_"):
            raise Error("LIVE requires privately generated credentials")
    return value


def properties(config, secret, project):
    pairs = {"spring.datasource.url": "jdbc:postgresql://" + project + "-db:5432/packmate",
             "spring.datasource.username": "packmate", "spring.datasource.password": secret["db_password"],
             "packmate.web.account-login": secret["username"], "packmate.web.account-password": secret["password"],
             "packmate.capture-mode": "LIVE", "packmate.interface-name": config["interface"],
             "packmate.local-ip": config["local_ip"], "packmate.timeout.tcp-stream-timeout": config["tcp_timeout_seconds"],
             "packmate.timeout.udp-stream-timeout": config["udp_timeout_seconds"],
             "packmate.timeout.check-interval": config["timeout_check_seconds"], "packmate.cleanup.enabled": "true",
             "packmate.cleanup.threshold": config["retention_minutes"], "packmate.cleanup.interval": config["cleanup_interval_minutes"],
             "server.port": PORT, "server.address": config["local_ip"], "logging.level." + kit.LOGGER: "OFF"}
    return "".join(key + "=" + str(value) + "\n" for key, value in sorted(pairs.items())).encode("ascii")


def compose_spec(config, secret, project, images=None):
    images = images or {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}
    base = {"restart": "no", "cpus": 1.0, "mem_limit": "512m", "pids_limit": 128,
            "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"}, "labels": {LABEL: project}}
    database = dict(base, image=images["db"], platform="linux/amd64",
                    environment={"POSTGRES_DB": "packmate", "POSTGRES_USER": "packmate", "POSTGRES_PASSWORD": secret["db_password"]},
                    volumes=["./data/postgres:/var/lib/postgresql/data"], networks={"capture": {"aliases": [project + "-db"]}},
                    healthcheck={"test": ["CMD", "pg_isready", "-U", "packmate", "-d", "packmate"],
                                 "interval": "2s", "timeout": "2s", "retries": 45})
    # Linux libpcap opens AF_PACKET sockets with NET_RAW. UID 0 with ALL dropped
    # and only NET_RAW added is used because nonroot Docker cap_add does not
    # reliably retain effective capabilities for the unmodified upstream Java.
    app = dict(base, image=images["packmate"], platform="linux/amd64", user="0:0", read_only=True,
               cap_drop=["ALL"], cap_add=["NET_RAW"], mem_limit="1536m",
               network_mode="container:" + config["capture_container"],
               tmpfs=["/tmp:size=67108864,mode=1777,noexec,nosuid,nodev", "/jna:size=16777216,mode=0700,nosuid,nodev,exec"],
               volumes=["./application.properties:/configuration/application.properties:ro"], entrypoint=["java"],
               command=["-Xms64m", "-Xmx768m", "-XX:ActiveProcessorCount=1", "-Djna.tmpdir=/jna",
                        "-Djava.net.preferIPv4Stack=true", "-jar", "/app/app.jar",
                        "--spring.config.additional-location=file:/configuration/application.properties"],
               depends_on={"db": {"condition": "service_healthy"}})
    return {"services": {"db": database, "packmate": app},
            "networks": {"capture": {"external": True, "name": config["network_id"]}}}


def validate_state(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "project", "profile", "credentials"} or
            value["schema"] != SCHEMA or not re.fullmatch(r"dh-live-[a-f0-9]{12}", value.get("project", ""))):
        raise Error("invalid LIVE ownership state")
    profile(value["profile"])
    credentials(value["credentials"])
    return value


def workspace(path):
    root = kit.safe_path(path)
    if not root.is_dir():
        raise Error("LIVE workspace missing")
    if os.name == "posix" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise Error("LIVE workspace must be private and owned by the current user")
    state = validate_state(kit.load(root / "state.json"))
    expected = {"compose.json": shared.canonical(compose_spec(state["profile"], state["credentials"], state["project"])),
                "application.properties": properties(state["profile"], state["credentials"], state["project"])}
    for name, content in expected.items():
        if kit.read(root / name) != content:
            raise Error("LIVE immutable configuration changed; prepare a new workspace")
    if (root / "data").is_symlink() or (root / "data/postgres").is_symlink() or not (root / "data/postgres").is_dir():
        raise Error("LIVE database data must remain an ordinary owned path")
    return root, state


def prepare(args):
    config, secret = profile(kit.load(args.profile)), credentials(kit.load(args.credentials))
    root = kit.safe_path(args.workspace)
    if root.exists() or not root.parent.is_dir():
        raise Error("LIVE workspace must be a new directory with an existing parent")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "mode": "LIVE", "daemon_contacted": False,
                "effects": "new private workspace only; no capture or Docker operation"}
    if os.name != "posix":
        raise Error("LIVE preparation requires POSIX private permissions")
    state = {"schema": SCHEMA, "project": "dh-live-" + secrets.token_hex(6), "profile": config, "credentials": secret}
    root.mkdir(mode=0o700)
    shared.write(root / "state.json", shared.canonical(state))
    shared.write(root / "compose.json", shared.canonical(compose_spec(config, secret, state["project"])))
    shared.write(root / "application.properties", properties(config, secret, state["project"]))
    (root / "application.properties").chmod(0o644)
    (root / "data/postgres").mkdir(mode=0o700, parents=True)
    return {"status": "PASS", "action": "prepare", "mode": "LIVE", "capture_started": False,
            "retention": "age policy only, not a hard storage quota", "not_validated": NOT_VALIDATED}


def daemon(config):
    raw = shared.checked(["docker", "info", "--format", "{{.ID}};{{.OSType}};{{.Architecture}};{{.OperatingSystem}}"], capture=True).decode().strip().split(";", 3)
    if len(raw) != 4 or raw[0] != config["daemon_id"] or raw[1] != "linux" or raw[2] not in {"x86_64", "amd64"} or "docker desktop" in raw[3].lower():
        raise Error("LIVE requires the approved native Linux amd64 Docker Engine, not Docker Desktop")


def capture_scope(config):
    template = '{"id":{{json .Id}},"running":{{json .State.Running}},"mode":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .NetworkSettings.Ports}},"owner":{{json (index .Config.Labels "' + CAPTURE_LABEL + '")}}}'
    item = json.loads(shared.checked(["docker", "container", "inspect", "--format", template, config["capture_container"]], capture=True))
    if (item.get("id") != config["capture_container"] or item.get("running") is not True or
            item.get("owner") != config["capture_scope"] or item.get("mode") in {"host", "none", "default", "bridge"} or
            str(item.get("mode", "")).startswith("container:") or not isinstance(item.get("networks"), dict) or len(item["networks"]) != 1):
        raise Error("capture namespace identity, ownership, running state or network scope mismatch")
    endpoint = next(iter(item["networks"].values()))
    if endpoint.get("NetworkID") != config["network_id"] or endpoint.get("IPAddress") != config["local_ip"]:
        raise Error("capture bridge endpoint changed")
    if item.get("ports", {}).get(str(PORT) + "/tcp") != [{"HostIp": config["bind_address"], "HostPort": str(config["ui_port"])}]:
        raise Error("namespace owner must already publish exactly the approved Packmate UI binding")
    template = '{"id":{{json .Id}},"driver":{{json .Driver}},"owner":{{json (index .Labels "' + CAPTURE_LABEL + '")}}}'
    network = json.loads(shared.checked(["docker", "network", "inspect", "--format", template, config["network_id"]], capture=True))
    if network != {"id": config["network_id"], "driver": "bridge", "owner": config["capture_scope"]}:
        raise Error("capture bridge ownership or driver mismatch")


def owned(state):
    project = state["project"]
    identifiers = shared.checked(["docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project], capture=True).decode().split()
    if len(identifiers) > 4 or any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in identifiers):
        raise Error("unexpected LIVE resource listing")
    for identity in identifiers:
        owner = shared.checked(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', identity], capture=True).decode().strip()
        if owner != project:
            raise Error("LIVE resource owner mismatch; operation refused")


def runtime(root, state):
    receipt_path = root / "images.json"
    if receipt_path.exists():
        images = kit.load(receipt_path)
        if not isinstance(images, dict) or set(images) != {"packmate", "db"} or any(not isinstance(v, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", v) for v in images.values()):
            raise Error("invalid LIVE immutable image receipt")
    else:
        images = {"packmate": kit.PACKMATE, "db": kit.PACKMATE_DB}
    identities = {}
    for name, reference in images.items():
        raw = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", reference], capture=True).decode().strip().split(";")
        if len(raw) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", raw[0]) or raw[1:] != ["linux", "amd64"] or (reference.startswith("sha256:") and reference != raw[0]):
            raise Error("LIVE cached image identity or architecture mismatch")
        identities[name] = raw[0]
    spec = compose_spec(state["profile"], state["credentials"], state["project"], identities)
    payload = shared.canonical(spec)
    if receipt_path.exists():
        if kit.read(root / "runtime-compose.json") != payload:
            raise Error("LIVE runtime Compose differs from immutable image receipt")
    else:
        shared.write(root / "runtime-compose.json", payload)
        shared.write(receipt_path, shared.canonical(identities))
    return spec


def command(root, state, runtime=False):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(root),
            "--file", str(root / ("runtime-compose.json" if runtime else "compose.json"))]


def request(config, secret, path, method="GET", body=None, auth=True):
    if method not in {"GET", "POST"} or not isinstance(path, str) or not API.fullmatch(path):
        raise Error("unlisted LIVE API operation")
    headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode((secret["username"] + ":" + secret["password"]).encode("ascii")).decode("ascii")
    req = urllib.request.Request("http://" + config["bind_address"] + ":" + str(config["ui_port"]) + path,
                                 headers=headers, method=method, data=None if body is None else shared.canonical(body))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), shared.NoRedirect())
    try:
        response = opener.open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Error("LIVE API response exceeded bound")
        if response.status != 200:
            raise Error("LIVE API did not return HTTP 200; body suppressed")
        return json.loads(raw) if raw else None


def ready(config, secret, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if isinstance(request(config, secret, "/api/service/"), list) and request(config, secret, "/api/pcap/started") is True:
                return
        except (Error, OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise Error("authenticated LIVE capture readiness timed out; inspect owned deployment or run down")


def execute(args):
    root, state = workspace(args.workspace)
    config = state["profile"]
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "mode": "LIVE", "daemon_contacted": False,
                "capture_scope": "explicitly approved container namespace only", "retention": "age policy, not hard storage quota"}
    if not sys.platform.startswith("linux"):
        raise Error("LIVE operations require a native Linux host")
    if args.action == "up" and args.capture_approval != config["capture_container"]:
        raise Error("LIVE startup requires --capture-approval matching the exact approved container ID")
    daemon(config)
    owned(state)
    if args.action == "down":
        shared.checked(command(root, state) + ["down", "--timeout", "10"], timeout=60)
        return {"status": "PASS", "action": "down", "capture_owner_unchanged": True, "database_data_retained": True}
    capture_scope(config)
    runtime(root, state)
    shared.checked(command(root, state, True) + ["config", "--quiet"])
    shared.checked(command(root, state, True) + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
    ready(config, state["credentials"])
    return {"status": "PASS", "action": "up", "mode": "LIVE", "authenticated_capture_started": True,
            "traffic_correctness": "NOT_RUN", "network_scope": "approved bridge peers can reach authenticated DB; no host DB publication",
            "retention": "upstream age cleanup enabled; not a hard disk quota", "not_validated": NOT_VALIDATED,
            "rollback": "down --workspace SAME_WORKSPACE --apply --approval-id ID; namespace owner/network/data retained"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "up", "down"])
    parser.add_argument("--workspace", required=True)
    for name in ("profile", "credentials", "approval-id", "capture-approval"):
        parser.add_argument("--" + name)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret --approval-id")
        if args.action == "prepare" and not (args.profile and args.credentials):
            raise Error("prepare requires private profile and credentials JSON")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else "LIVE operation rejected; raw details suppressed",
                          "rollback": "inspect exact owned project; down retains namespace owner, network and database data"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
