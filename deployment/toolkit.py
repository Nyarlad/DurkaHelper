#!/usr/bin/env python3
"""Pinned, private S4DFarm/Neo/Packmate deployment. Preview is the default.

Never run this against an untrusted Docker daemon or untrusted source checkout.
No secrets, expanded Compose model or upstream command output are printed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("deployment_shared", ROOT / "integration/stack_smoke.py")
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
Error = shared.FixtureError
SCHEMA = "durkahelper.deployment.v1"
LABEL = "io.durkahelper.deployment"
PROBE_LABEL = "io.durkahelper.readiness-probe"
LIGHT = "ghcr.io/c4t-but-s4d/neo_env_light:v2.4.2@sha256:75deed498a6451f702d88f05495af8c7006707ac223ad4b2e7def0d947b622bc"
PACKMATE = "registry.gitlab.com/packmate/packmate:v4.0@sha256:faa39ec74a63d84558e08ab949b7724a0a014f6629d105a5212a3afb05c7cbf7"
PACKMATE_DB = "postgres:15.2@sha256:78a275d4c891f7b3a33d3f1a78eda9f1d744954d9e20122bfdc97cdda25cddaf"
LOGGER = "ru.serega6531.packmate.configuration.SecurityConfiguration"
BUILD_SERVICES = ("farm", "celery", "front", "neo-server")
SERVICES = ("postgres", "redis", "neo-redis", "farm", "front", "neo-server", "packmate-db", "packmate")
NOT_VALIDATED = ["Docker Desktop", "physical team LAN", "continuous capture",
                 "competition protocol", "component recovery", "full offline cold start"]


def safe_path(path):
    """Allow ordinary macOS ancestor aliases, reject a linked leaf/reparse point."""
    raw = Path(os.path.abspath(path))
    if raw.is_symlink() or getattr(raw.lstat() if raw.exists() else None, "st_file_attributes", 0) & 0x400:
        raise Error("linked deployment paths are not allowed")
    resolved = shared.no_links(raw) if os.name == "nt" else raw.parent.resolve(strict=True) / raw.name
    if any(c in str(resolved) for c in (",", "\r", "\n", "$")):
        raise Error("deployment path contains unsupported delimiter")
    return resolved


def read(path, limit=1024 * 1024):
    path = safe_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise Error("input must be a bounded regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        same = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or same(opened) != same(before):
            raise Error("input changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit or same(opened) != same(os.fstat(fd)) or same(opened) != same(path.lstat()):
            raise Error("input changed while reading")
        return result
    finally:
        os.close(fd)


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Error("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=unique)


def validate_profile(value):
    required = {"schema", "platform", "bind_address", "ports", "allow_amd64_emulation", "farm", "packmate"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != "durkahelper.deployment-profile.v1":
        raise Error("invalid deployment profile schema or fields")
    platform = value["platform"]
    if platform not in ({"os": "linux", "architecture": "amd64", "runtime": "docker-engine"},
                        {"os": "linux", "architecture": "arm64", "runtime": "docker-engine"},
                        {"os": "darwin", "architecture": "arm64", "runtime": "docker-desktop"}):
        raise Error("unsupported deployment platform")
    ip = ipaddress.ip_address(value["bind_address"])
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise Error("bind_address must be an explicit unicast IPv4 address, never wildcard")
    ports = value["ports"]
    if (not isinstance(ports, dict) or set(ports) != {"farm", "neo", "packmate"} or
            any(type(p) is not int or not 1024 <= p <= 65535 for p in ports.values()) or len(set(ports.values())) != 3):
        raise Error("three distinct unprivileged UI/API ports are required")
    if type(value["allow_amd64_emulation"]) is not bool:
        raise Error("allow_amd64_emulation must be boolean")
    pm = value["packmate"]
    if not isinstance(pm, dict) or set(pm) != {"mode", "local_ip", "pcap_file", "interface", "retention_minutes"}:
        raise Error("invalid Packmate profile")
    if pm["mode"] not in {"FILE", "LIVE"}:
        raise Error("Packmate mode must be FILE or LIVE")
    ipaddress.ip_address(pm["local_ip"])
    if not isinstance(pm["pcap_file"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.pcap", pm["pcap_file"]):
        raise Error("pcap_file must be a simple .pcap filename")
    if not isinstance(pm["interface"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{0,32}", pm["interface"]):
        raise Error("invalid capture interface")
    if type(pm["retention_minutes"]) is not int or not 5 <= pm["retention_minutes"] <= 1440:
        raise Error("capture retention must be 5..1440 minutes")
    farm = value["farm"]
    required_farm = {"teams", "flag_format", "protocol", "protocol_settings", "submit_limit", "submit_period", "flag_lifetime"}
    if not isinstance(farm, dict) or set(farm) != required_farm:
        raise Error("invalid farm profile")
    if not isinstance(farm["teams"], dict) or not 1 <= len(farm["teams"]) <= 512:
        raise Error("explicit bounded competition team map required")
    for name, addr in farm["teams"].items():
        if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,80}", name):
            raise Error("invalid team label")
        ipaddress.ip_address(addr)
    if not isinstance(farm["flag_format"], str) or not 1 <= len(farm["flag_format"]) <= 512:
        raise Error("explicit bounded competition flag format required")
    # Only the reviewed JSON-scalar adapter configuration is accepted. This is
    # not a claim that ructf_http is correct for any particular competition.
    if farm["protocol"] != "ructf_http" or set(farm["protocol_settings"]) != {"SYSTEM_URL", "SYSTEM_TOKEN"}:
        raise Error("only reviewed ructf_http adapter supported; other competition protocols need an adapter review")
    import urllib.parse
    endpoint = urllib.parse.urlsplit(farm["protocol_settings"]["SYSTEM_URL"])
    if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.username or endpoint.password:
        raise Error("competition endpoint must be explicit HTTP(S), without embedded credentials")
    for name in ("submit_limit", "submit_period", "flag_lifetime"):
        if type(farm[name]) is not int or not 1 <= farm[name] <= 86400:
            raise Error("invalid competition timing/limit setting")
    if not isinstance(farm["protocol_settings"]["SYSTEM_TOKEN"], str) or not 1 <= len(farm["protocol_settings"]["SYSTEM_TOKEN"]) <= 512:
        raise Error("competition token must be supplied privately")
    return value


def validate_credentials(value):
    if not isinstance(value, dict) or set(value) != {"farm_password", "database_password", "neo_key", "packmate_user", "packmate_password"}:
        raise Error("invalid credential fields")
    for name, text in value.items():
        pattern = r"[A-Za-z0-9_.-]{4,64}" if name == "packmate_user" else r"[A-Za-z0-9_.-]{20,128}"
        if not isinstance(text, str) or not re.fullmatch(pattern, text) or text.startswith("REPLACE_"):
            raise Error("credentials require safe generated ASCII values; passwords/key at least 20 characters")
    return value


def compose_spec(profile, credentials, project, images):
    spec = shared.compose_spec(project, images)
    for name in ("receiver", "neo-client", "neo-client-denied"):
        del spec["services"][name]
    for name, service in spec["services"].items():
        service["labels"] = {LABEL: project}
        service["restart"] = "unless-stopped"
        service["platform"] = "linux/" + profile["platform"]["architecture"]
        if "build" in service:
            service["image"] = project + "-" + name + ":pinned"
        if name in {"farm", "celery"}:
            service["networks"] = ["fixture", "edge"]
            service["environment"]["POSTGRES_DSN"] = "host=postgres port=5432 user=farm password=" + credentials["database_password"] + " dbname=farm"
            service["environment"]["SERVER_PASSWORD"] = credentials["farm_password"]
            service["depends_on"].pop("receiver", None)
        if name == "postgres":
            service["environment"]["POSTGRES_PASSWORD"] = credentials["database_password"]
        if name in {"redis", "neo-redis"}:
            service["healthcheck"] = {"test": ["CMD", "redis-cli", "ping"], "interval": "5s", "timeout": "2s", "retries": 12}
    # Submission is opt-in so a restored deployment cannot send old queued data.
    spec["services"]["celery"]["profiles"] = ["submission"]
    for service, label in (("front", "farm"), ("neo-server", "neo")):
        port = spec["services"][service]["ports"][0]
        port.update(host_ip=profile["bind_address"], published=str(profile["ports"][label]))
    spec["services"]["neo-worker"] = {
        "image": LIGHT, "platform": "linux/" + profile["platform"]["architecture"],
        "entrypoint": ["/usr/local/bin/neo"], "command": ["--verbose=false", "--config", "/client.yml", "run", "--jobs", "1"],
        "user": "65534:65534", "read_only": True, "cap_drop": ["ALL"], "init": True,
        "security_opt": ["no-new-privileges:true"], "cpus": 1.0, "mem_limit": "512m", "pids_limit": 64,
        "volumes": ["./config/neo-client.yml:/client.yml:ro"],
        "tmpfs": ["/work:rw,nosuid,nodev,size=268435456,mode=0700,uid=65534,gid=65534,exec"],
        "working_dir": "/work", "networks": ["fixture", "edge"], "restart": "no", "profiles": ["worker"],
        "labels": {LABEL: project}, "logging": {"driver": "none"}}
    base = {"restart": "unless-stopped", "cpus": 1.0, "mem_limit": "512m", "pids_limit": 128,
            "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"}, "labels": {LABEL: project}}
    spec["services"]["packmate-db"] = dict(base, image=PACKMATE_DB, networks=["fixture"],
        environment={"POSTGRES_USER": "packmate", "POSTGRES_DB": "packmate", "POSTGRES_PASSWORD": credentials["database_password"]},
        volumes=["./data/packmate-db:/var/lib/postgresql/data"],
        healthcheck={"test": ["CMD", "pg_isready", "-U", "packmate", "-d", "packmate"], "interval": "5s", "timeout": "2s", "retries": 24})
    spec["services"]["packmate"] = dict(base, image=PACKMATE, platform="linux/amd64", user="65534:65534",
        read_only=True, cap_drop=["ALL"], mem_limit="1536m", networks=["fixture", "edge"],
        tmpfs=["/tmp:size=67108864,mode=1777,noexec,nosuid,nodev", "/jna:size=16777216,mode=0700,uid=65534,gid=65534,nosuid,nodev,exec"],
        volumes=["./config/packmate.properties:/configuration/application.properties:ro", "./pcaps:/app/pcaps:ro"],
        entrypoint=["java"], command=["-Xms64m", "-Xmx768m", "-XX:ActiveProcessorCount=1", "-Djna.tmpdir=/jna", "-jar", "/app/app.jar",
            "--spring.config.additional-location=file:/configuration/application.properties"],
        ports=[{"target": 65000, "published": str(profile["ports"]["packmate"]), "host_ip": profile["bind_address"], "protocol": "tcp"}],
        depends_on={"packmate-db": {"condition": "service_healthy"}})
    for network in spec["networks"].values():
        network["labels"] = {LABEL: project}
    return spec


def properties(profile, credentials):
    pm = profile["packmate"]
    pairs = {"spring.datasource.url": "jdbc:postgresql://packmate-db:5432/packmate", "spring.datasource.username": "packmate",
             "spring.datasource.password": credentials["database_password"], "packmate.web.account-login": credentials["packmate_user"],
             "packmate.web.account-password": credentials["packmate_password"], "packmate.capture-mode": pm["mode"],
             "packmate.pcap-file": pm["pcap_file"], "packmate.local-ip": pm["local_ip"], "packmate.interface-name": pm["interface"],
             "packmate.cleanup.enabled": "true" if pm["mode"] == "LIVE" else "false",
             "packmate.cleanup.threshold": str(pm["retention_minutes"]), "server.port": "65000", "server.address": "0.0.0.0",
             "logging.level." + LOGGER: "OFF"}
    return "".join(key + "=" + value + "\n" for key, value in sorted(pairs.items()))


def model(spec, profile, image_ids=None):
    services = []
    for name, service in sorted(spec["services"].items()):
        mounts = []
        for mount in service.get("volumes", []):
            source, target, *flags = mount.split(":")
            scope = "approved-data" if source.startswith(("./data/", "./pcaps")) else "approved-config"
            mounts.append({"kind": "bind", "target": target, "source_scope": scope, "read_only": "ro" in flags})
        for mount in service.get("tmpfs", []):
            mounts.append({"kind": "tmpfs", "target": mount.split(":")[0], "source_scope": "approved-data", "read_only": False})
        role = "backend" if name in {"postgres", "redis", "neo-redis", "packmate-db"} else "worker" if name in {"celery", "neo-worker"} else "ui" if name in {"front", "packmate"} else "api"
        services.append({"id": name, "role": role, "image": (image_ids or {}).get(name, service["image"]),
            "architectures": ["amd64"] if name == "packmate" else [profile["platform"]["architecture"]],
            "mode": "file" if name == "packmate" else "none",
            "ports": [{"host_ip": p["host_ip"], "host_port": int(p["published"]), "container_port": p["target"], "protocol": p["protocol"]} for p in service.get("ports", [])],
            "mounts": mounts, "privileged": False, "network_mode": "bridge", "capabilities": [],
            "nonroot": service.get("user", "0").split(":")[0] != "0" if "user" in service else None,
            "healthcheck": bool(service.get("healthcheck")), "memory_limit_mb": int(service["mem_limit"][:-1]),
            "cpu_limit": service["cpus"], "restart": service["restart"]})
    return {"schema": "durkahelper.deployment-model.v1", "source_sha256": hashlib.sha256(shared.canonical(spec)).hexdigest(),
            "platform": profile["platform"], "services": services}


def policy(profile, deployment_model):
    return {"schema": "durkahelper.deployment-policy.v1", "team_lan": not ipaddress.ip_address(profile["bind_address"]).is_loopback,
            "approved_bind_addresses": [profile["bind_address"]],
            "approved_publications": [dict(service=s["id"], **{k: v for k, v in p.items() if k != "host_ip"}) for s in deployment_model["services"] for p in s["ports"]],
            "approved_images": sorted({s["image"] for s in deployment_model["services"] if "@sha256:" in s["image"] or re.fullmatch(r"sha256:[a-f0-9]{64}", s["image"])}),
            "require_healthcheck": True, "require_resource_limits": True, "require_nonroot": True,
            "require_restart": True, "allow_amd64_emulation": profile["allow_amd64_emulation"], "approved_live_capture": []}


def write_build_files(workspace, images):
    replacements = {"python:3.9-slim": images["python"], "node:20-slim": images["node"],
                    "nginx:1.21.0-alpine": images["nginx"], "golang:1.21-alpine": images["golang"], "alpine": images["alpine"]}
    for role in ("server", "celery", "front"):
        root = workspace / "sources/s4dfarm/server"
        value = shared.pin_dockerfile(read(root / "docker" / role / "Dockerfile").decode(), replacements)
        if role == "front":
            value = value.replace("ENV PNPM_HOME=", 'ENV NODE_OPTIONS="--max-old-space-size=768"\nENV COREPACK_DEFAULT_TO_LATEST=0\nENV COREPACK_ENABLE_AUTO_PIN=0\nENV PNPM_HOME=')
            value = value.replace("RUN corepack enable", 'RUN corepack enable && corepack prepare ' + shared.PNPM_DESCRIPTOR + ' --activate && test "$(pnpm --version)" = "' + shared.PNPM_VERSION + '"')
            value = value.replace("COPY --from=front-build /app/dist /front", "COPY --from=front-build /app/dist /front\nRUN chmod -R a+rX /front")
        shared.write(root / ("Dockerfile.fixture." + role), value)
    root = workspace / "sources/neo"
    value = shared.pin_dockerfile(read(root / "Dockerfile").decode(), replacements)
    value = value.replace("ENV CGO_ENABLED=0", "ENV CGO_ENABLED=0\nENV GOMAXPROCS=1\nENV GOFLAGS=-p=1\nENV GOMEMLIMIT=768MiB")
    shared.write(root / "Dockerfile.fixture", value)


def neo_farm_url(profile):
    """Neo advertises this same URL to workers; bridge DNS is not LAN DNS."""
    if ipaddress.ip_address(profile["bind_address"]).is_loopback:
        # Laptop-only demo with the bundled container worker, not LAN clients.
        return "http://front"
    return "http://" + profile["bind_address"] + ":" + str(profile["ports"]["farm"])


def prepare(args):
    profile = validate_profile(load(args.profile))
    credentials = validate_credentials(load(args.credentials))
    root = safe_path(args.workspace)
    if root.exists():
        raise Error("deployment workspace must be new; existing data is never overwritten")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "source_pins": shared.PINS,
                "effects": ["private source/config/data directory", "no downloads or Docker operations"], "not_validated": NOT_VALIDATED}
    if os.name == "nt":
        raise Error("private deployment creation requires POSIX permissions; Windows is preview/test only")
    if profile["packmate"]["mode"] == "LIVE":
        raise Error("LIVE needs a separately approved Linux capture namespace and database routing; this bridge deployment is FILE-only")
    if profile["platform"]["architecture"] == "arm64" and not profile["allow_amd64_emulation"]:
        raise Error("pinned Packmate image is amd64-only; explicit emulation acceptance required")
    images = shared.image_map(ROOT / "config/integration-images.lock.json")
    root.mkdir(mode=0o700)
    project = "dh-deploy-" + secrets.token_hex(6)
    for component in shared.PINS:
        shared.export_source(getattr(args, component + "_source"), root / "sources" / component, component)
    write_build_files(root, images)
    for folder in ("postgres", "redis", "neo-redis", "neo", "packmate-db"):
        (root / "data" / folder).mkdir(parents=True, mode=0o700)
    (root / "pcaps").mkdir(mode=0o755)
    farm = profile["farm"]
    config = dict(DEBUG=False, TEAMS=farm["teams"], FLAG_FORMAT=farm["flag_format"], SYSTEM_PROTOCOL=farm["protocol"],
                  SUBMIT_FLAG_LIMIT=farm["submit_limit"], SUBMIT_PERIOD=farm["submit_period"], FLAG_LIFETIME=farm["flag_lifetime"],
                  SERVER_PASSWORD=credentials["farm_password"], TIMEZONE="UTC", **farm["protocol_settings"])
    shared.write(root / "config/farm.py", "CONFIG = " + repr(config) + "\n")
    shared.write(root / "config/neo-server.yml", 'db_path: "/data/db.db"\nredis_url: "redis://neo-redis:6379/0"\nbase_dir: "/data/exploits"\nping_every: "5s"\nsubmit_every: "2s"\ngrpc_auth_key: "' + credentials["neo_key"] + '"\nfarm:\n  url: "' + neo_farm_url(profile) + '"\n  password: "' + credentials["farm_password"] + '"\n')
    shared.write(root / "config/neo-client.yml", 'host: "neo-server:5005"\ngrpc_auth_key: "' + credentials["neo_key"] + '"\nexploit_dir: "/work/exploits"\nclient_id: "deployment-worker"\n')
    shared.write(root / "config/packmate.properties", properties(profile, credentials))
    for filename in ("neo-client.yml", "packmate.properties"):
        (root / "config" / filename).chmod(0o644)  # Individually mounted for UID 65534; private 0700 parent.
    spec = compose_spec(profile, credentials, project, images)
    shared.write(root / "compose.json", shared.canonical(spec))
    shared.write(root / "profile.json", shared.canonical(profile))
    deployment_model = model(spec, profile)
    shared.write(root / "model.json", shared.canonical(deployment_model))
    shared.write(root / "policy.json", shared.canonical(policy(profile, deployment_model)))
    files = {p.relative_to(root).as_posix(): hashlib.sha256(read(p, shared.MAX_SOURCE)).hexdigest()
             for p in root.rglob("*") if p.is_file()}
    shared.write(root / "deployment.json", shared.canonical({"schema": SCHEMA, "project": project, "files": files,
        "source_pins": shared.PINS, "approval_id": args.approval_id}))
    return {"status": "PASS", "action": "prepare", "project": project, "not_validated": NOT_VALIDATED,
            "submission": "disabled; enable only after protocol and restored-queue review", "rollback": "retain private workspace; no services started"}


def workspace(path):
    root = safe_path(path)
    if os.name != "nt" and root.stat().st_mode & 0o077:
        raise Error("deployment workspace must have private 0700 permissions")
    state = load(root / "deployment.json")
    if (not isinstance(state, dict) or set(state) != {"schema", "project", "files", "source_pins", "approval_id"} or
            state["schema"] != SCHEMA or not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", state["project"]) or state["source_pins"] != shared.PINS):
        raise Error("invalid deployment ownership manifest")
    if not isinstance(state["files"], dict) or not 1 <= len(state["files"]) <= 20000:
        raise Error("invalid deployment file manifest")
    for name, checksum in state["files"].items():
        if (not isinstance(name, str) or Path(name).is_absolute() or "\\" in name or ":" in name or
                any(part in {"..", "."} for part in name.split("/")) or not re.fullmatch(r"[a-f0-9]{64}", checksum)):
            raise Error("invalid deployment manifest member")
        # Parent aliases are allowed for the operator's workspace, never inside it.
        candidate = root / name
        if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root and root in p.parents):
            raise Error("linked deployment member")
        if hashlib.sha256(read(candidate, shared.MAX_SOURCE)).hexdigest() != checksum:
            raise Error("deployment immutable configuration/source changed; prepare a new deployment")
    for folder in ("data", "data/postgres", "data/redis", "data/neo-redis", "data/neo", "data/packmate-db", "pcaps"):
        if (root / folder).is_symlink() or not (root / folder).is_dir():
            raise Error("deployment data path must be a real directory")
    return root, state, load(root / "compose.json"), validate_profile(load(root / "profile.json"))


def command(root, state, runtime=False):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(root), "--file", str(root / ("runtime-compose.json" if runtime else "compose.json"))]


def owned_resources(state):
    """All matched resources must carry BOTH the Compose and private owner labels."""
    project = state["project"]
    for kind, listing in (("container", ["ps", "--all", "--quiet"]), ("network", ["network", "ls", "--quiet"])):
        output = shared.checked(["docker"] + listing + ["--filter", "label=com.docker.compose.project=" + project], capture=True).decode().split()
        if len(output) > 64 or any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in output):
            raise Error("unexpected project resource listing")
        for identity in output:
            fmt = '{{index .Config.Labels "' + LABEL + '"}}' if kind == "container" else '{{index .Labels "' + LABEL + '"}}'
            actual = shared.checked(["docker", kind, "inspect", "--format", fmt, identity], capture=True).decode().strip()
            if actual != project:
                raise Error("ownership mismatch; refusing to affect project resources")


def image_preflight(spec, profile, require_build=True):
    checks = {}
    for name, svc in spec["services"].items():
        if "build" in svc and not require_build:
            continue
        actual = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", svc["image"]], capture=True).decode().strip().split(";")
        expected = "amd64" if name == "packmate" else profile["platform"]["architecture"]
        if len(actual) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", actual[0]) or actual[1:] != ["linux", expected]:
            raise Error("cached image architecture mismatch or invalid image identity")
        checks[name] = actual[0]
    return checks


def runtime_spec(spec, identities):
    result = copy.deepcopy(spec)
    if set(identities) != set(spec["services"]) or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in identities.values()):
        raise Error("every runtime service requires an exact immutable local image identity")
    for name, identity in identities.items():
        result["services"][name]["image"] = identity
        result["services"][name].pop("build", None)
    return result


def check_build_receipt(root, spec, identities=None):
    receipt = load(root / "build-receipt.json")
    if receipt.get("schema") == "durkahelper.deployment-build.v1":
        raise Error("legacy receipt does not pin all runtime images; prepare and build a new deployment before offline use")
    if (set(receipt) != {"schema", "compose_sha256", "runtime_sha256", "images"} or receipt["schema"] != "durkahelper.deployment-build.v2"
            or receipt["compose_sha256"] != hashlib.sha256(shared.canonical(spec)).hexdigest()
            or set(receipt["images"]) != set(spec["services"])):
        raise Error("build receipt does not match this deployment")
    runtime = runtime_spec(spec, receipt["images"])
    if (load(root / "runtime-compose.json") != runtime or
            hashlib.sha256(read(root / "runtime-compose.json")).hexdigest() != receipt["runtime_sha256"]):
        raise Error("runtime Compose changed after immutable build receipt")
    if identities is not None and identities != receipt["images"]:
        raise Error("runtime image identities differ from immutable receipt")
    return runtime


def wait_farm(profile, spec, timeout=60):
    """Authenticate with the private configured password without emitting it."""
    url = "http://" + profile["bind_address"] + ":" + str(profile["ports"]["farm"]) + "/api/get_config"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), shared.NoRedirect())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request = urllib.request.Request(url, headers={"Authorization": spec["services"]["farm"]["environment"]["SERVER_PASSWORD"]})
        try:
            with opener.open(request, timeout=3) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise Error("farm readiness response exceeded its bound")
                data = json.loads(raw)
                if response.status == 200 and isinstance(data, dict) and data.get("TEAMS") == profile["farm"]["teams"] and data.get("SYSTEM_PROTOCOL") == profile["farm"]["protocol"]:
                    return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise Error("authenticated farm readiness timed out; services retained for scoped down")


def cleanup_readiness_probes(state, name=None):
    """Reconcile uncertain creates by exact name and both private labels.

    The down path also finds probes whose Docker create outlived an interrupted
    CLI. Never infer ownership from a matching name alone or delete by a name.
    """
    project = state["project"]
    if not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", project):
        raise Error("invalid readiness project identity")
    pattern = re.escape(project) + r"-readiness-[a-f0-9]{8}"
    if name is not None and not re.fullmatch(pattern, name):
        raise Error("invalid readiness probe name")
    command = ["docker", "ps", "--all", "--quiet", "--no-trunc"]
    if name is not None:
        command += ["--filter", "name=^/" + name + "$"]
    else:
        command += ["--filter", "label=" + LABEL + "=" + project,
                    "--filter", "label=" + PROBE_LABEL + "=neo"]
    identifiers = shared.checked(command, capture=True).decode().split()
    if len(identifiers) > (1 if name else 64) or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in identifiers):
        raise Error("unexpected readiness probe resource listing")
    template = '{"id":{{json .Id}},"name":{{json .Name}},"owner":{{json (index .Config.Labels "' + LABEL + '")}},"purpose":{{json (index .Config.Labels "' + PROBE_LABEL + '")}}}'
    for identity in identifiers:
        observed = json.loads(shared.checked(["docker", "inspect", "--format", template, identity], capture=True))
        actual_name = observed.get("name", "")
        if (observed.get("id") != identity or observed.get("owner") != project or observed.get("purpose") != "neo" or
                not isinstance(actual_name, str) or not re.fullmatch("/" + pattern, actual_name) or
                (name is not None and actual_name != "/" + name)):
            raise Error("readiness probe ownership mismatch; cleanup refused")
        shared.checked(["docker", "rm", "--force", identity], timeout=20)


def wait_neo(root, state, runtime, timeout=60):
    """Info-only authenticated probe, nonroot and scoped to the owned bridge."""
    project = state["project"]
    name = project + "-readiness-" + secrets.token_hex(4)
    image = runtime["services"]["neo-worker"]["image"]
    # The name is registered before issuing create: a cancelled CLI can leave
    # a successful daemon-side create whose response was never observed.
    attempted = False
    try:
        attempted = True
        shared.checked(["docker", "create", "--name", name, "--label", LABEL + "=" + project,
            "--label", PROBE_LABEL + "=neo",
            "--network", project + "_fixture", "--user", "65534:65534", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=32",
            "--log-driver=none", "--pull=never", "--mount", "type=bind,src=" + str(root / "config/neo-client.yml") + ",dst=/client.yml,readonly",
            "--entrypoint", "/usr/local/bin/neo", image, "--verbose=false", "--config", "/client.yml", "info"], timeout=20)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                shared.checked(["docker", "start", "--attach", name], timeout=min(10, max(1, deadline - time.monotonic())))
                return
            except Error:
                time.sleep(0.5)
        raise Error("authenticated Neo readiness timed out; services retained for scoped down")
    finally:
        if attempted:
            cleanup_readiness_probes(state, name)


def execute(args):
    root, state, spec, profile = workspace(args.workspace)
    cmd = command(root, state)
    if args.action == "model":
        return model(check_build_receipt(root, spec), profile) if (root / "build-receipt.json").exists() else model(spec, profile)
    if args.action == "preflight":
        result = {"status": "PASS", "action": "preflight", "configuration_integrity": "PASS",
                  "runtime": "NOT_RUN", "not_validated": NOT_VALIDATED, "competition_ready": False}
        if args.runtime:
            runtime = check_build_receipt(root, spec)
            shared.checked(command(root, state, runtime=True) + ["config", "--quiet"])
            owned_resources(state)
            result["cached_image_ids"] = image_preflight(runtime, profile)
            check_build_receipt(root, spec, result["cached_image_ids"])
            result["runtime"] = "PASS"
        return result
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "project": state["project"],
                "effects": ["project-scoped Docker operation"], "rollback": "down retains data and images"}
    if os.name == "nt":
        raise Error("deployment mutations require POSIX permissions")
    owned_resources(state)
    shared.checked(cmd + ["config", "--quiet"])
    if args.action == "build":
        if not args.connected_preparation:
            raise Error("build requires --connected-preparation; prepare dependencies before offline rehearsal")
        if (root / "build-receipt.json").exists():
            raise Error("deployment already built; prepare a new workspace instead of overwriting its receipt")
        for name in BUILD_SERVICES:
            svc = spec["services"][name]
            build = svc["build"]
            shared.checked(["docker", "build", "--platform", svc["platform"], "--memory", "1536m", "--memory-swap", "1536m",
                "--cpu-period", "100000", "--cpu-quota", "100000", "--tag", svc["image"], "--file",
                str(root / build["context"] / build["dockerfile"]), str(root / build["context"])], timeout=1800,
                environment=dict(os.environ, DOCKER_BUILDKIT="0"))
        # Docker save/load by ID deliberately loses tags and RepoDigests. Pin
        # *every* service to its verified platform-specific configuration ID,
        # including databases and externally published runtime images.
        identities = image_preflight(spec, profile)
        runtime = runtime_spec(spec, identities)
        runtime_data = shared.canonical(runtime)
        shared.write(root / "runtime-compose.json", runtime_data)
        runtime_model = model(runtime, profile)
        shared.write(root / "runtime-model.json", shared.canonical(runtime_model))
        shared.write(root / "runtime-policy.json", shared.canonical(policy(profile, runtime_model)))
        shared.write(root / "build-receipt.json", shared.canonical({"schema": "durkahelper.deployment-build.v2",
            "compose_sha256": hashlib.sha256(shared.canonical(spec)).hexdigest(), "runtime_sha256": hashlib.sha256(runtime_data).hexdigest(), "images": identities}))
        return {"status": "PASS", "action": "build", "image_ids": identities,
                "rollback": "images retained; interrupted builds may require inspection of exact build identity"}
    if args.action == "down":
        cleanup_readiness_probes(state)
        shared.checked(cmd + ["--profile", "submission", "--profile", "worker", "down", "--timeout", "15"], timeout=90)
        return {"status": "PASS", "action": "down", "rollback": "data and images retained; up recreates only this project"}
    runtime = check_build_receipt(root, spec)
    check_build_receipt(root, spec, image_preflight(runtime, profile))
    cmd = command(root, state, runtime=True)
    if args.action == "up":
        pcap = safe_path(root / "pcaps" / profile["packmate"]["pcap_file"])
        if not pcap.is_file() or pcap.is_symlink():
            raise Error("FILE mode requires an operator-provided closed regular PCAP before startup")
        # The retained Neo server fetches farm configuration once at startup.
        # Compose's service_started condition is insufficient for that contract.
        shared.checked(cmd + ["up", "--detach", "--no-build", "--pull", "never"] + [name for name in SERVICES if name != "neo-server"], timeout=180)
        wait_farm(profile, spec)
        shared.checked(cmd + ["up", "--detach", "--no-build", "--pull", "never", "neo-server"], timeout=60)
        wait_neo(root, state, runtime)
    elif args.action == "enable-submission":
        if not args.protocol_reviewed or not args.queue_reviewed:
            raise Error("submission requires --protocol-reviewed and --queue-reviewed")
        shared.checked(cmd + ["--profile", "submission", "up", "--detach", "--no-build", "--pull", "never", "celery"], timeout=60)
    elif args.action == "worker":
        shared.checked(cmd + ["--profile", "worker", "up", "--detach", "--no-build", "--pull", "never", "neo-worker"], timeout=60)
    return {"status": "PASS", "action": args.action, "readiness": {"farm_authenticated": "PASS", "neo_authenticated": "PASS", "packmate": "NOT_RUN", "team_lan": "NOT_RUN"} if args.action == "up" else "NOT_RUN", "not_validated": NOT_VALIDATED,
            "rollback": "run down with the same workspace and approval; no volumes or data are deleted"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "preflight", "model", "build", "up", "down", "worker", "enable-submission"])
    parser.add_argument("--workspace", required=True)
    for option in ("profile", "credentials", "s4dfarm-source", "neo-source", "approval-id"):
        parser.add_argument("--" + option)
    for option in ("apply", "runtime", "connected-preparation", "protocol-reviewed", "queue-reviewed"):
        parser.add_argument("--" + option, action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret --approval-id")
        if args.action == "prepare" and not all((args.profile, args.credentials, args.s4dfarm_source, args.neo_source)):
            raise Error("prepare requires profile, credentials and both pinned source checkout paths")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "BLOCKED", "reason": "interrupted; inspect exact owned project before retry; data retained"}))
        return 2
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Error) else "operation rejected: " + type(error).__name__
        print(json.dumps({"status": "BLOCKED", "reason": reason, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
