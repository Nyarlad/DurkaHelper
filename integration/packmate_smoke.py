#!/usr/bin/env python3
"""Opt-in isolated Packmate v4.0 FILE-mode smoke; no LIVE capture or deployment.

All stages default to previews. Prepared fixtures use generated synthetic data
and passwords, a private database backend, and one loopback ephemeral web port.
The app also joins a generated edge bridge and has outbound connectivity.
Pre-pull the exact images before rehearsing disconnected operation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import urllib.error
import urllib.request


def _sibling(name):
    spec = importlib.util.spec_from_file_location("fixture_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = _sibling("stack_smoke")
pcap = _sibling("synthetic_pcap")
FixtureError = shared.FixtureError
SOURCE_PIN = "938031f1dedfbedabef5b049368ed5b6ba6a900a"
APP_IMAGE = "registry.gitlab.com/packmate/packmate:v4.0@sha256:faa39ec74a63d84558e08ab949b7724a0a014f6629d105a5212a3afb05c7cbf7"
SCHEMA = "durkahelper.packmate-fixture.v1"
STATE_KEYS = {"schema", "project", "source_contract_commit", "app_image", "postgres_image",
              "username", "password", "db_password", "marker", "approval_id"}
MAX_JSON = 1024 * 1024
PORT = 65000
ROLLBACK = "down --workspace SAME_WORKSPACE --apply --approval-id ID; data and images retained"
NETWORK_SCOPE = "database internal backend only; app also joins project edge bridge with outbound connectivity; published web port loopback only"
SAFE_API_PATH = re.compile(r"/api/(?:service/|pattern/|pcap/(?:started|start)|stream/18080|packet/[1-9][0-9]{0,18})\Z")
NOT_VALIDATED = ["LIVE capture", "TLS decryption", "large PCAP performance", "recovery",
                 "Apple Silicon", "Docker Desktop", "team Ethernet access",
                 "offline image acquisition", "image-to-source build provenance"]


def bounded_bytes(path, limit=MAX_JSON):
    path = shared.no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise FixtureError("fixture input must be a bounded regular file")
    # A regular-file lstat can race with FIFO replacement. Nonblocking open
    # prevents waiting for a writer before descriptor metadata can reject it.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
            raise FixtureError("fixture input changed during open")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if (len(data) != before.st_size or len(data) > limit or
                opened.st_mtime_ns != after.st_mtime_ns or opened.st_size != after.st_size):
            raise FixtureError("fixture input changed while reading")
        return data
    finally:
        os.close(descriptor)


def validate_state(state):
    if not isinstance(state, dict) or set(state) != STATE_KEYS:
        raise FixtureError("invalid Packmate fixture state")
    if (state["schema"] != SCHEMA or state["source_contract_commit"] != SOURCE_PIN or
            state["app_image"] != APP_IMAGE or
            not isinstance(state["postgres_image"], str) or
            not re.fullmatch(r"postgres:15\.2@sha256:[a-f0-9]{64}", state["postgres_image"])):
        raise FixtureError("fixture must retain the pinned Packmate and PostgreSQL versions")
    for name, pattern in (("project", r"dh-packmate-[a-f0-9]{12}"),
                          ("username", r"fixture-[a-f0-9]{12}"),
                          ("password", r"[a-f0-9]{48}"), ("db_password", r"[a-f0-9]{48}"),
                          ("marker", r"[a-f0-9]{24}"), ("approval_id", r"[A-Za-z0-9_.-]{1,80}")):
        if not isinstance(state[name], str) or not re.fullmatch(pattern, state[name]):
            raise FixtureError("invalid generated fixture identity")
    return state


def properties(state):
    return ("spring.datasource.password=" + state["db_password"] + "\n" +
            "packmate.web.account-login=" + state["username"] + "\n" +
            "packmate.web.account-password=" + state["password"] + "\n").encode("ascii")


def compose_spec(state, *, legacy_internal_only=False, legacy_no_jna=False):
    def service(**values):
        result = {"restart": "no", "cpus": 1.0, "mem_limit": "512m", "pids_limit": 128,
                  "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"},
                  "networks": ["backend"]}
        result.update(values)
        return result
    spec = {
        "services": {
            "db": service(image=state["postgres_image"],
                environment={"POSTGRES_USER": "packmate", "POSTGRES_DB": "packmate",
                             "POSTGRES_PASSWORD": state["db_password"]},
                volumes=["./data/postgres:/var/lib/postgresql/data"],
                healthcheck={"test": ["CMD", "pg_isready", "-U", "packmate", "-d", "packmate"],
                             "interval": "2s", "timeout": "2s", "retries": 30}),
            "packmate": service(image=APP_IMAGE, user="65534:65534", read_only=True,
                cap_drop=["ALL"], mem_limit="1g", working_dir="/app",
                networks=["backend", "edge"],
                # JNA extracts its native dispatch library before loading it.
                # Docker's default noexec tmpfs makes FILE import fail even
                # though the UI is healthy. Allow execution only on this small
                # app-owned native-library mount, not on general /tmp.
                tmpfs=["/tmp:size=67108864,mode=1777,noexec",
                       "/jna:size=16777216,mode=0700,uid=65534,gid=65534,nosuid,nodev,exec"],
                volumes=["./application.properties:/fixture/application.properties:ro",
                         "./pcaps:/app/pcaps:ro"],
                entrypoint=["java"], command=["-Xms64m", "-Xmx512m", "-XX:ActiveProcessorCount=1",
                    "-Djna.tmpdir=/jna",
                    "-Djava.net.preferIPv4Stack=true", "-Djava.net.preferIPv4Addresses=true",
                    "-jar", "/app/app.jar", "--spring.config.additional-location=file:/fixture/application.properties",
                    "--spring.datasource.url=jdbc:postgresql://db:5432/packmate",
                    "--spring.datasource.username=packmate", "--packmate.capture-mode=FILE",
                    "--packmate.pcap-file=synthetic.pcap", "--packmate.local-ip=" + pcap.SERVER_IP,
                    "--packmate.cleanup.enabled=false", "--server.port=65000", "--server.address=0.0.0.0"],
                ports=[{"target": PORT, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}],
                depends_on={"db": {"condition": "service_healthy"}}),
        },
        # Internal-only bridge membership suppresses published ports on tested
        # Engine 29. The app's project-owned edge enables loopback publication;
        # it also permits app egress and is NOT an egress-isolation boundary.
        "networks": {"backend": {"internal": True}, "edge": {"internal": False}},
    }
    if legacy_internal_only:
        # Cleanup compatibility only; fixture() never accepts this for startup.
        spec["networks"] = {"fixture": {"internal": True}}
        for service in spec["services"].values():
            service["networks"] = ["fixture"]
    if legacy_no_jna:
        spec["services"]["packmate"]["tmpfs"] = ["/tmp:size=67108864,mode=1777"]
        spec["services"]["packmate"]["command"].remove("-Djna.tmpdir=/jna")
    return spec


def fixture(workspace, check_payload=True):
    workspace = shared.no_links(workspace)
    state = validate_state(json.loads(bounded_bytes(workspace / "fixture.json")))
    expected = {"compose.json": shared.canonical(compose_spec(state))}
    if check_payload:
        expected.update({"application.properties": properties(state),
                         "pcaps/synthetic.pcap": pcap.make_pcap(state["marker"])})
        shared.no_links(workspace / "data" / "postgres")
    for name, payload in expected.items():
        actual = bounded_bytes(workspace / name)
        if actual != payload:
            if (not check_payload and name == "compose.json" and any(
                    actual == shared.canonical(compose_spec(state, legacy_internal_only=internal, legacy_no_jna=no_jna))
                    for internal, no_jna in ((True, False), (True, True), (False, True)))):
                continue
            raise FixtureError("generated fixture file changed; create a new fixture")
    return workspace, state


def prepare(args):
    workspace = shared.no_links(args.workspace)
    if workspace.exists() or not workspace.parent.is_dir():
        raise FixtureError("workspace must be a new directory under an existing parent")
    if not args.postgres_image or not re.fullmatch(r"postgres:15\.2@sha256:[a-f0-9]{64}", args.postgres_image):
        raise FixtureError("prepare requires the immutable postgres:15.2 repository digest")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "mode": "FILE", "source_contract_commit": SOURCE_PIN,
                "app_image": APP_IMAGE, "network_scope": NETWORK_SCOPE,
                "effects": ["new private fixture", "synthetic PCAP and generated passwords"]}
    if not args.source:
        raise FixtureError("prepare --apply requires the reviewed pinned source checkout")
    source = shared.no_links(args.source)
    if shared.git_read(source, ["rev-parse", "HEAD"]).decode().strip() != SOURCE_PIN:
        raise FixtureError("Packmate source HEAD differs from retained API contract pin")
    if shared.git_read(source, ["status", "--porcelain", "--untracked-files=all"]):
        raise FixtureError("Packmate source checkout must be clean")
    state = {"schema": SCHEMA, "project": "dh-packmate-" + secrets.token_hex(6),
             "source_contract_commit": SOURCE_PIN, "app_image": APP_IMAGE, "postgres_image": args.postgres_image,
             "username": "fixture-" + secrets.token_hex(6), "password": secrets.token_hex(24),
             "db_password": secrets.token_hex(24), "marker": secrets.token_hex(12),
             "approval_id": args.approval_id}
    validate_state(state)
    workspace.mkdir(mode=0o700)
    shared.write(workspace / "compose.json", shared.canonical(compose_spec(state)))
    shared.write(workspace / "application.properties", properties(state))
    # Only disposable generated credentials and synthetic capture are readable by
    # the nonroot app. The enclosing host fixture remains mode 0700.
    (workspace / "application.properties").chmod(0o644)
    shared.write(workspace / "pcaps/synthetic.pcap", pcap.make_pcap(state["marker"]))
    (workspace / "pcaps").chmod(0o755)
    (workspace / "pcaps/synthetic.pcap").chmod(0o644)
    (workspace / "data/postgres").mkdir(parents=True, mode=0o700)
    shared.write(workspace / "fixture.json", shared.canonical(state))
    return {"status": "PASS", "action": "prepare", "project": state["project"], "mode": "FILE",
            "pcap_sha256": hashlib.sha256(pcap.make_pcap(state["marker"])).hexdigest(),
            "not_validated": NOT_VALIDATED, "network_scope": NETWORK_SCOPE}


def compose_command(workspace, state):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(workspace),
            "--file", str(workspace / "compose.json")]


def app_port(command):
    value = shared.checked(command + ["port", "packmate", str(PORT)], capture=True).decode().strip()
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", value)
    if not match or not 1 <= int(match[1]) <= 65535:
        raise FixtureError("Packmate must publish one loopback ephemeral port")
    return int(match[1])


def request(port, state, path, method="GET", body=None, auth="valid"):
    if not 1 <= port <= 65535 or not path.startswith("/") or path.startswith("//"):
        raise FixtureError("invalid local fixture request")
    headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
    if auth != "none":
        password = state["password"] if auth == "valid" else "wrong-generated-fixture-password"
        headers["Authorization"] = "Basic " + base64.b64encode(
            (state["username"] + ":" + password).encode("ascii")).decode("ascii")
    req = urllib.request.Request("http://127.0.0.1:" + str(port) + path, method=method, headers=headers,
                                 data=None if body is None else shared.canonical(body))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), shared.NoRedirect())
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read(MAX_JSON + 1)
        if len(content) > MAX_JSON:
            raise FixtureError("Packmate HTTP response exceeds limit")
        return response.status, content, response.headers.get("WWW-Authenticate", "")


def json_request(port, state, path, method="GET", body=None):
    status, content, _ = request(port, state, path, method, body)
    if status != 200:
        # Only fixture-controlled routes, methods and the numeric status belong
        # in diagnostics. Never include response bodies, headers or credentials.
        label = (method + " " + path if method in {"GET", "POST"} and
                 isinstance(path, str) and SAFE_API_PATH.fullmatch(path) else "unlisted request")
        code = str(status) if type(status) is int and 100 <= status <= 599 else "invalid"
        raise FixtureError("Packmate API request failed: " + label + " returned HTTP " + code +
                           "; raw response suppressed")
    return json.loads(content) if content else None


def wait_ready(port, state, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = json_request(port, state, "/api/service/")
            if isinstance(result, list):
                return
        except (FixtureError, OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise FixtureError("Packmate readiness timed out")


def image_evidence(state):
    result = {}
    for role, reference in (("packmate", APP_IMAGE), ("postgres", state["postgres_image"])):
        raw = shared.checked(["docker", "image", "inspect", "--format",
                              '{{.Os}};{{.Architecture}};{{.Id}}', reference], capture=True)
        match = re.fullmatch(rb"(linux);(amd64|arm64);(sha256:[a-f0-9]{64})\s*", raw)
        if not match:
            raise FixtureError("runtime image identity is unavailable")
        result[role] = {"reference": reference, "os": match[1].decode(), "architecture": match[2].decode(),
                        "image_id": match[3].decode()}
    return result


def smoke(command, state):
    port = app_port(command)
    wait_ready(port, state)
    checks = {}
    for auth in ("none", "wrong"):
        code, _, challenge = request(port, state, "/api/service/", auth=auth)
        checks["auth_" + auth + "_rejected"] = code == 401 and challenge.lower().startswith("basic")
    code, content, _ = request(port, state, "/")
    checks["authenticated_ui"] = code == 200 and b"<html" in content.lower()
    # A fresh fixture prevents old persisted results from producing a false PASS.
    if json_request(port, state, "/api/service/") != [] or json_request(port, state, "/api/pcap/started") is not False:
        raise FixtureError("smoke requires a fresh unprocessed fixture database")
    service = {"port": pcap.SERVICE_PORT, "name": "DurkaHelper synthetic HTTP", "decryptTls": False,
               "http": False, "urldecodeHttpRequests": False, "mergeAdjacentPackets": False,
               "parseWebSockets": False}
    created = json_request(port, state, "/api/service/", "POST", service)
    checks["service_created"] = isinstance(created, dict) and created.get("port") == pcap.SERVICE_PORT
    pattern = json_request(port, state, "/api/pattern/", "POST", {
        "name": "Synthetic marker", "value": state["marker"], "color": "#123456", "searchType": "SUBSTRING",
        "directionType": "BOTH", "actionType": "FIND", "serviceId": pcap.SERVICE_PORT})
    pattern_id = pattern.get("id") if isinstance(pattern, dict) else None
    if type(pattern_id) is not int or pattern_id < 1 or pattern.get("enabled") is not True:
        raise FixtureError("fixture pattern creation was not confirmed")
    checks["pattern_created"] = True
    json_request(port, state, "/api/pcap/start", "POST")
    checks["file_import_started"] = json_request(port, state, "/api/pcap/started") is True
    query = {"startingFrom": None, "pageSize": 10, "favorites": False, "pattern": {"id": pattern_id}}
    streams = []
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        streams = json_request(port, state, "/api/stream/" + str(pcap.SERVICE_PORT), "POST", query)
        if isinstance(streams, list) and streams:
            break
        time.sleep(1)
    checks["filtered_stream_found"] = isinstance(streams, list) and len(streams) == 1
    checks["request_exact_and_incoming"] = False
    checks["response_exact_and_outgoing"] = False
    checks["pattern_matches_both_directions"] = False
    if checks["filtered_stream_found"]:
        stream = streams[0]
        stream_id = stream.get("id")
        if type(stream_id) is not int or stream_id < 1:
            raise FixtureError("invalid imported stream identifier")
        checks["stream_metadata"] = (stream.get("service") == pcap.SERVICE_PORT and stream.get("protocol") == "TCP"
                                     and pattern_id in stream.get("foundPatternsIds", []))
        packets = json_request(port, state, "/api/packet/" + str(stream_id), "POST",
                               {"startingFrom": None, "pageSize": 20})
        if not isinstance(packets, list) or len(packets) > 20:
            raise FixtureError("invalid imported packet collection")
        wanted_request, wanted_response = pcap.payloads(state["marker"])
        matched_directions = set()
        for packet in packets:
            data = base64.b64decode(packet.get("content", ""), validate=True)
            incoming = packet.get("incoming")
            if data == wanted_request and incoming is True:
                checks["request_exact_and_incoming"] = True
            if data == wanted_response and incoming is False:
                checks["response_exact_and_outgoing"] = True
            if any(match.get("patternId") == pattern_id for match in packet.get("matches", [])):
                matched_directions.add(incoming)
        checks["pattern_matches_both_directions"] = matched_directions == {True, False}
    return {"schema": "durkahelper.packmate-smoke.v1", "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "project": state["project"], "source_contract_commit": SOURCE_PIN,
            "mode": "FILE", "runtime_images": image_evidence(state), "not_validated": NOT_VALIDATED,
            "rollback": ROLLBACK, "network_scope": NETWORK_SCOPE,
            "upstream_warning": "failed authentication logs passwords; fixture Docker logs disabled"}


def execute(args):
    workspace, state = fixture(args.workspace, check_payload=args.action != "down")
    args.validated_project = state["project"]
    command = compose_command(workspace, state)
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "project": state["project"], "mode": "FILE",
                "requires": "--apply --approval-id", "rollback": ROLLBACK, "network_scope": NETWORK_SCOPE}
    shared.checked(command + ["config", "--quiet"])
    if args.action == "pull":
        shared.checked(command + ["pull", "--quiet"], timeout=300)
    elif args.action == "up":
        image_evidence(state)  # Fail closed when images have not been pre-pulled.
        try:
            shared.checked(command + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
            wait_ready(app_port(command), state)
        except (FixtureError, OSError, ValueError, urllib.error.URLError, KeyboardInterrupt):
            try:
                shared.checked(command + ["down", "--timeout", "10"], timeout=60)
                args.rollback_status = "generated project stopped; data retained"
            except (FixtureError, KeyboardInterrupt):
                args.rollback_status = "automatic stop failed; exact project cleanup required"
            raise
    elif args.action == "smoke":
        return smoke(command, state)
    elif args.action == "down":
        shared.checked(command + ["down", "--timeout", "10"], timeout=60)
    return {"status": "PASS", "action": args.action, "project": state["project"], "mode": "FILE",
            "runtime_images": image_evidence(state) if args.action != "down" else {}, "rollback": ROLLBACK,
            "network_scope": NETWORK_SCOPE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "pull", "up", "smoke", "down"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--source", help="reviewed Packmate checkout at the retained source pin")
    parser.add_argument("--postgres-image", help="postgres:15.2@sha256:... resolved repository digest")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise FixtureError("mutations require a non-secret approval identifier")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if result["status"] == "FAIL" else 0
    except (FixtureError, OSError, ValueError, TypeError, KeyError, AttributeError, urllib.error.URLError, KeyboardInterrupt) as error:
        result = {"status": "BLOCKED", "reason":
                  "fixture operation interrupted; raw output suppressed" if isinstance(error, KeyboardInterrupt)
                  else str(error) if isinstance(error, FixtureError) else "fixture operation failed: " + type(error).__name__}
        if getattr(args, "validated_project", None):
            result.update({"project": args.validated_project, "rollback": ROLLBACK,
                           "rollback_status": getattr(args, "rollback_status", "not automatically performed")})
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    sys.exit(main())
