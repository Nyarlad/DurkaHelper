#!/usr/bin/env python3
"""Opt-in, isolated S4DFarm/Neo integration fixture. Never a deployment installer.

All commands are previews unless --apply and --approval-id are supplied. Sources
are exported from exact Git commits; dependencies/images must be prepared before
an offline rehearsal. No external competition endpoint is accepted by this fixture.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request

PINS = {
    "s4dfarm": "3b8b057c95e0467c6afb3a47648e8b6befd1a815",
    "neo": "2f2a4eb63f9715155844284f253ba786d330c9ae",
}
IMAGE_KEYS = {"python", "node", "nginx", "postgres", "redis", "golang", "alpine"}
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}\Z")
SCHEMA = "durkahelper.integration-fixture.v1"
MAX_SOURCE = 64 * 1024 * 1024
MAX_HTTP = 1024 * 1024
LIVE_SERVICES = ["postgres", "redis", "neo-redis", "receiver", "farm", "celery", "front"]
# Official npm registry integrity for pnpm 8.15.9, converted from base64 SHA-512
# to Corepack's hexadecimal descriptor. It reads the retained v6 lockfile.
PNPM_VERSION = "8.15.9"
PNPM_SHA512 = ("499434c9d8fdd1a2794ebf4552b3b25c0a633abcee5bb15e7b5de90f32f47b513"
               "aca98cd5cfd001c31f0db454bc3804edccd578501e4ca293a6816166bbd9f81")
PNPM_DESCRIPTOR = "pnpm@" + PNPM_VERSION + "+sha512." + PNPM_SHA512


class FixtureError(Exception):
    """A sanitized diagnostic; raw application output must not escape."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def macos_ancestor_alias(path, item, info):
    """Recognize only root-owned stock macOS aliases, never a selected leaf."""
    aliases = {"/var": "/private/var", "/tmp": "/private/tmp", "/etc": "/private/etc"}
    target = aliases.get(item.as_posix())
    if sys.platform != "darwin" or item == path or target is None or getattr(info, "st_uid", None) != 0:
        return None
    if os.readlink(item) not in (target, target.lstrip("/")):
        return None
    return type(path)(target) / path.relative_to(item)


def no_links(path):
    """Reject leaf/user links; canonicalize only trusted macOS system ancestors."""
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            canonical_path = macos_ancestor_alias(path, item, info)
            if canonical_path is not None:
                return no_links(canonical_path)
            raise FixtureError("fixture paths must not contain links or junctions")
        if getattr(info, "st_file_attributes", 0) & 0x400:
            raise FixtureError("fixture paths must not contain reparse points")
    return path


def read_json(path):
    no_links(path)
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > MAX_HTTP:
        raise FixtureError("JSON input must be a bounded regular file")
    return json.loads(path.read_text(encoding="utf-8"))


def image_map(path):
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != IMAGE_KEYS:
        raise FixtureError("image map must contain exactly: " + ", ".join(sorted(IMAGE_KEYS)))
    if not all(isinstance(v, str) and IMAGE.fullmatch(v) for v in value.values()):
        raise FixtureError("every base image requires an explicit sha256 repository digest")
    return value


def checked(argv, cwd=None, timeout=60, capture=False, environment=None):
    """No shell; never return application stderr or configuration logs."""
    try:
        result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False, env=environment)
    except subprocess.TimeoutExpired as error:
        raise FixtureError("command timed out; daemon work may remain active: " + Path(argv[0]).name) from error
    except OSError as error:
        raise FixtureError("command unavailable: " + Path(argv[0]).name) from error
    if result.returncode:
        raise FixtureError("command failed (raw output suppressed): " + Path(argv[0]).name)
    if capture:
        if len(result.stdout) > MAX_SOURCE:
            raise FixtureError("command output exceeds fixture limit")
        return result.stdout
    return b""


def git_read(source, arguments):
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    environment.update({"GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1"})
    return checked(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                    "-C", str(source)] + arguments, capture=True, environment=environment)


def export_source(source, target, component):
    source = no_links(source)
    head = git_read(source, ["rev-parse", "HEAD"]).decode().strip()
    if head != PINS[component]:
        raise FixtureError(component + " source HEAD does not match retained pin")
    dirty = git_read(source, ["status", "--porcelain", "--untracked-files=all"])
    if dirty:
        raise FixtureError(component + " source checkout must be clean")
    archive = git_read(source, ["archive", "--format=tar", head])
    extract_source(archive, target)


def extract_source(archive, target):
    """Do not trust tar member paths or links, even in the pinned source archive."""
    if len(archive) > MAX_SOURCE:
        raise FixtureError("source archive exceeds fixture limit")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        total = 0
        seen = set()
        for member in members:
            part = PurePosixPath(member.name)
            if (part.is_absolute() or not part.parts or any(p in {"..", ".git", ".ssh"} for p in part.parts)
                    or "\\" in member.name or ":" in member.name or member.name in seen
                    or not (member.isfile() or member.isdir())):
                raise FixtureError("unsafe source archive member")
            seen.add(member.name)
            total += member.size
            if total > MAX_SOURCE or len(seen) > 10000:
                raise FixtureError("expanded source exceeds fixture limit")
        for member in members:
            path = target.joinpath(*PurePosixPath(member.name).parts)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if member.isdir():
                path.mkdir(exist_ok=True, mode=0o700)
            else:
                with tar.extractfile(member) as src, path.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(0o700 if member.mode & 0o111 else 0o600)


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as stream:
        stream.write(content.encode("utf-8") if isinstance(content, str) else content)
    path.chmod(0o600)


def pin_dockerfile(text, replacements):
    lines = []
    for line in text.splitlines():
        if line.upper().startswith("FROM "):
            words = line.split()
            if words[1] in replacements:
                words[1] = replacements[words[1]]
            elif words[1] not in {"front-base"}:
                raise FixtureError("unexpected Dockerfile base image")
            line = " ".join(words)
        # Only build-cache mounts are removed for resource-capped legacy builds.
        # They do not change application source or resolved dependency versions.
        line = re.sub(r"--mount=type=cache,[^\s]+", "", line)
        if "--mount=" in line:
            raise FixtureError("unexpected build mount")
        lines.append(line)
    return "\n".join(lines) + "\n"


def compose_spec(project, images, edge=True):
    def service(**values):
        result = {"restart": "no", "cpus": 1.0, "mem_limit": "512m", "pids_limit": 128,
                  "security_opt": ["no-new-privileges:true"],
                  "logging": {"driver": "none"}, "networks": ["fixture"]}
        result.update(values)
        return result

    def build(role):
        return {"context": "./sources/s4dfarm/server", "dockerfile": "Dockerfile.fixture." + role}

    app_env = {"POSTGRES_DSN": "host=postgres port=5432 user=farm password=fixture-only dbname=farm",
               "REDIS_URL": "redis://redis:6379/0", "CELERY_BROKER_URL": "redis://redis:6379/1",
               "SERVER_PASSWORD": "fixture-only", "PYTHONDONTWRITEBYTECODE": "1", "FARM_DATA": "/tmp"}
    app_volumes = ["./sources/s4dfarm/server/app:/app:ro", "./config/farm.py:/app/config.py:ro"]
    depends = {"postgres": {"condition": "service_healthy"}, "redis": {"condition": "service_started"},
               "receiver": {"condition": "service_started"}}
    neo_image = project + "-neo:fixture"
    spec = {
        "services": {
            "postgres": service(image=images["postgres"], environment={"POSTGRES_USER": "farm",
                "POSTGRES_PASSWORD": "fixture-only", "POSTGRES_DB": "farm"},
                volumes=["./data/postgres:/var/lib/postgresql/data"],
                healthcheck={"test": ["CMD-SHELL", "pg_isready -U farm -d farm"],
                             "interval": "2s", "timeout": "2s", "retries": 30}),
            "redis": service(image=images["redis"], command=["redis-server", "--appendonly", "yes"],
                             volumes=["./data/redis:/data"]),
            "neo-redis": service(image=images["redis"], command=["redis-server", "--appendonly", "yes"],
                                 volumes=["./data/neo-redis:/data"]),
            "receiver": service(image=images["python"], user="65534:65534", read_only=True,
                cap_drop=["ALL"], command=["python", "-B", "/receiver.py"],
                volumes=["./receiver.py:/receiver.py:ro"]),
            "farm": service(build=build("server"), image=project + "-farm:fixture", environment=app_env,
                            volumes=app_volumes, tmpfs=["/tmp"], depends_on=depends),
            "celery": service(build=build("celery"), image=project + "-celery:fixture", environment=app_env,
                              volumes=app_volumes, tmpfs=["/tmp"], depends_on=depends),
            "front": service(build=build("front"), image=project + "-front:fixture",
                ports=[{"target": 80, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}],
                depends_on={"farm": {"condition": "service_started"}}),
            "neo-server": service(image=neo_image,
                build={"context": "./sources/neo", "dockerfile": "Dockerfile.fixture"},
                volumes=["./config/neo-server.yml:/config.yml:ro", "./data/neo:/data"],
                ports=[{"target": 5005, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}],
                depends_on={"neo-redis": {"condition": "service_started"}}),
            "neo-client": service(image=neo_image, profiles=["test"], read_only=True,
                cap_drop=["ALL"], volumes=["./config/neo-client.yml:/client.yml:ro"],
                entrypoint=["/neo_client"], command=["--verbose=false", "--config", "/client.yml", "info"]),
            "neo-client-denied": service(image=neo_image, profiles=["test"], read_only=True,
                cap_drop=["ALL"], volumes=["./config/neo-denied.yml:/client.yml:ro"],
                entrypoint=["/neo_client"], command=["--verbose=false", "--config", "/client.yml", "info"]),
        },
        "networks": {"fixture": {"internal": True}},
    }
    if edge:
        # Docker does not publish ports for internal-only containers. Only the
        # loopback-published entrypoints join this project-owned normal bridge.
        # They can initiate outbound connections; backend services cannot.
        spec["networks"]["edge"] = {}
        for name in ("front", "neo-server"):
            spec["services"][name]["networks"] = ["fixture", "edge"]
    return spec


def prepare(args):
    images = image_map(Path(args.images))
    workspace = no_links(args.workspace)
    if workspace.exists() or not workspace.parent.is_dir():
        raise FixtureError("workspace must be a new directory under an existing parent")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "source_pins": PINS,
                "effects": ["new isolated directory", "export retained tracked sources", "generate synthetic configs"]}
    workspace.mkdir(mode=0o700)
    for name in PINS:
        export_source(getattr(args, name + "_source"), workspace / "sources" / name, name)
    project = "dh-smoke-" + secrets.token_hex(6)
    replacements = {"python:3.9-slim": images["python"], "node:20-slim": images["node"],
                    "nginx:1.21.0-alpine": images["nginx"], "golang:1.21-alpine": images["golang"],
                    "alpine": images["alpine"]}
    for role in ("server", "celery", "front"):
        root = workspace / "sources/s4dfarm/server"
        text = (root / "docker" / role / "Dockerfile").read_text(encoding="utf-8")
        text = pin_dockerfile(text, replacements)
        if role == "front":
            text = text.replace("ENV PNPM_HOME=", 'ENV NODE_OPTIONS="--max-old-space-size=768"\n'
                'ENV COREPACK_DEFAULT_TO_LATEST=0\nENV COREPACK_ENABLE_AUTO_PIN=0\nENV PNPM_HOME=')
            text = text.replace("RUN corepack enable", "RUN corepack enable && corepack prepare "
                + PNPM_DESCRIPTOR + ' --activate && test "$(pnpm --version)" = "' + PNPM_VERSION + '"')
            # Vite preserves mode 0600 from private exported HTML assets. Only
            # final public static output must be readable by nginx's worker UID.
            text = text.replace("COPY --from=front-build /app/dist /front",
                                "COPY --from=front-build /app/dist /front\nRUN chmod -R a+rX /front")
        write(root / ("Dockerfile.fixture." + role), text)
    neo_root = workspace / "sources/neo"
    neo_dockerfile = pin_dockerfile((neo_root / "Dockerfile").read_text(encoding="utf-8"), replacements)
    neo_dockerfile = neo_dockerfile.replace("ENV CGO_ENABLED=0", "ENV CGO_ENABLED=0\nENV GOMAXPROCS=1\nENV GOFLAGS=-p=1\nENV GOMEMLIMIT=768MiB")
    # Build a matched source client for the info/authentication smoke only.
    needle = "FROM " + images["alpine"]
    neo_dockerfile = neo_dockerfile.replace(needle, "RUN go build -o neo_client cmd/client/main.go\n\n" + needle)
    neo_dockerfile = neo_dockerfile.replace("COPY --from=build /app/neo_server /neo_server",
        "COPY --from=build /app/neo_server /neo_server\nCOPY --from=build /app/neo_client /neo_client")
    write(neo_root / "Dockerfile.fixture", neo_dockerfile)
    farm_config = {"DEBUG": False, "TEAMS": {"Synthetic": "192.0.2.1"}, "FLAG_FORMAT": "[A-Z0-9]{31}=",
                   "SYSTEM_PROTOCOL": "ructf_http", "SYSTEM_URL": "http://receiver:8080/flags",
                   "SYSTEM_TOKEN": "fixture-only", "SUBMIT_FLAG_LIMIT": 10, "SUBMIT_PERIOD": 1,
                   "FLAG_LIFETIME": 300, "SERVER_PASSWORD": "fixture-only", "TIMEZONE": "UTC"}
    write(workspace / "config/farm.py", "CONFIG = " + repr(farm_config) + "\n")
    write(workspace / "config/neo-server.yml", 'db_path: "/data/db.db"\nredis_url: "redis://neo-redis:6379/0"\n'
          'base_dir: "/data/exploits"\nping_every: "5s"\nsubmit_every: "2s"\ngrpc_auth_key: "fixture-only"\n'
          'farm:\n  url: "http://front"\n  password: "fixture-only"\n')
    client = ('host: "neo-server:5005"\ngrpc_auth_key: "fixture-only"\nexploit_dir: "/tmp/unused"\n'
              'client_id: "synthetic-info-client"\n')
    write(workspace / "config/neo-client.yml", client)
    write(workspace / "config/neo-denied.yml", client.replace("fixture-only", "incorrect-fixture-key"))
    # The cap_drop=ALL clients cannot bypass host-owned 0600 bind permissions.
    # These are disposable synthetic credentials inside a mode-0700 workspace.
    for name in ("neo-client.yml", "neo-denied.yml"):
        (workspace / "config" / name).chmod(0o644)
    write(workspace / "receiver.py", Path(__file__).with_name("synthetic_receiver.py").read_bytes())
    # The unprivileged receiver must be able to read this non-secret synthetic file.
    (workspace / "receiver.py").chmod(0o644)
    for folder in ("postgres", "redis", "neo-redis", "neo"):
        (workspace / "data" / folder).mkdir(parents=True, mode=0o700)
    write(workspace / "compose.json", canonical(compose_spec(project, images)))
    files = {str(p.relative_to(workspace)).replace("\\", "/"): digest(p)
             for p in workspace.rglob("*") if p.is_file()}
    state = {"schema": SCHEMA, "project": project, "source_pins": PINS, "images": images,
             "files": files, "approval_id": args.approval_id, "build_tools": {"pnpm": PNPM_DESCRIPTOR},
             "network_layout": "internal-backend-loopback-edge"}
    write(workspace / "fixture.json", canonical(state))
    return {"status": "PASS", "action": "prepare", "project": project, "source_pins": PINS,
            "limits": "not production configuration; no external competition or team-LAN acceptance",
            "network_boundary": "backends internal-only; loopback-published front/neo-server have outbound connectivity"}


def fixture(workspace, check_files=True):
    workspace = no_links(workspace)
    state = read_json(workspace / "fixture.json")
    if (state.get("schema") != SCHEMA or state.get("source_pins") != PINS
            or not re.fullmatch(r"dh-smoke-[a-f0-9]{12}", state.get("project", ""))):
        raise FixtureError("invalid fixture identity")
    files = state.get("files", {}) if check_files else {}
    if check_files and (not files or len(files) > 10000):
        raise FixtureError("invalid fixture file ledger")
    for name, sha in files.items():
        part = PurePosixPath(name)
        if part.is_absolute() or ".." in part.parts or "\\" in name or ":" in name:
            raise FixtureError("invalid fixture file path")
        path = no_links(workspace.joinpath(*part.parts))
        if not path.is_file() or digest(path) != sha:
            raise FixtureError("fixture file changed; create a new fixture")
    layout = state.get("network_layout", "legacy-internal-only")
    if layout not in {"legacy-internal-only", "internal-backend-loopback-edge"}:
        raise FixtureError("invalid fixture network layout")
    if read_json(workspace / "compose.json") != compose_spec(state["project"], state["images"],
                                                             edge=layout == "internal-backend-loopback-edge"):
        raise FixtureError("fixture Compose isolation settings changed")
    if check_files:
        for folder in ("postgres", "redis", "neo-redis", "neo"):
            no_links(workspace / "data" / folder)
    return workspace, state


def compose_command(workspace, state):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(workspace),
            "--file", str(workspace / "compose.json")]


def farm_port(command):
    port = checked(command + ["port", "front", "80"], capture=True).decode().strip()
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", port)
    if not match or not 1 <= int(match[1]) <= 65535:
        raise FixtureError("farm must publish only one loopback ephemeral port")
    return int(match[1])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(port, path, method="GET", body=None, auth=True):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "fixture-only"
    req = urllib.request.Request("http://127.0.0.1:" + str(port) + path,
                                 data=None if body is None else canonical(body), headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read(MAX_HTTP + 1)
        if len(content) > MAX_HTTP:
            raise FixtureError("fixture HTTP response exceeds limit")
        return response.status, content


def wait_ready(port, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            code, content = request(port, "/api/get_config")
            if code == 200 and json.loads(content).get("SYSTEM_PROTOCOL") == "ructf_http":
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise FixtureError("farm readiness timed out")


def stop_probe(container, project, service):
    """Stop only a generated one-shot container after verifying exact ownership."""
    labels = checked(["docker", "inspect", "--format",
        '{{index .Config.Labels "com.docker.compose.project"}};{{index .Config.Labels "com.docker.compose.service"}}',
        container], capture=True).decode().strip()
    if labels != project + ";" + service:
        raise FixtureError("probe cleanup blocked: container ownership mismatch")
    checked(["docker", "stop", "--time", "5", container], timeout=15)
    # compose run --rm removes it on exit. Never remove an unverified name afterwards.


def capture_probe(argv, timeout=25):
    """Bound combined Neo output to 64 KiB; keep credentials only in memory."""
    output, issues = bytearray(), []
    done = threading.Event()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def reader():
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                if len(output) + len(chunk) > 65536:
                    issues.append("Neo probe output exceeded limit; raw output suppressed")
                    break
                output.extend(chunk)
        except OSError:
            issues.append("Neo probe output read failed; raw output suppressed")
        finally:
            done.set()

    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout
    try:
        while not done.wait(0.05):
            if time.monotonic() >= deadline:
                raise FixtureError("Neo probe timed out; raw output suppressed")
        if issues:
            raise FixtureError(issues[0])
        try:
            code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise FixtureError("Neo probe timed out; raw output suppressed") from error
        return code, bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        worker.join(timeout=1)
        process.stdout.close()


def neo_probe(command, service):
    project = command[command.index("--project-name") + 1]
    container = project + "-probe-" + secrets.token_hex(4)
    try:
        return capture_probe(command + ["run", "--name", container, "--rm", "--no-deps", "-T", service])
    except (FixtureError, KeyboardInterrupt) as error:
        condition = "Neo probe interrupted" if isinstance(error, KeyboardInterrupt) else str(error)
        try:
            stop_probe(container, project, service)
        except (FixtureError, KeyboardInterrupt):
            raise FixtureError(condition + "; exact owned probe cleanup required: " + container) from error
        raise FixtureError(condition + "; owned one-shot container stopped") from error


def smoke(command):
    port = farm_port(command)
    wait_ready(port)
    checks = {}
    checks["farm_auth_rejected"] = request(port, "/api/get_config", auth=False)[0] == 403
    code, content = request(port, "/api/get_config")
    config = json.loads(content)
    checks["farm_config"] = code == 200 and config.get("TEAMS") == {"Synthetic": "192.0.2.1"}
    checks["farm_config_no_credentials"] = not any("PASSWORD" in k or "TOKEN" in k for k in config)
    code, content = request(port, "/", auth=False)
    checks["farm_ui"] = code == 200 and b"<html" in content.lower()
    flag = secrets.token_hex(16).upper()[:31] + "="
    checks["farm_ingest"] = request(port, "/api/post_flags", "POST",
                                    [{"flag": flag, "sploit": "synthetic-smoke", "team": "Synthetic"}])[0] == 200
    accepted = False
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        code, content = request(port, "/api/filter_flags?flag=" + flag)
        found = json.loads(content).get("flags", []) if code == 200 else []
        if any(item.get("flag") == flag and item.get("status") == "ACCEPTED" for item in found):
            accepted = True
            break
        time.sleep(1)
    checks["farm_mock_submission_accepted"] = accepted
    code, _ = neo_probe(command, "neo-client")
    checks["neo_source_client_info"] = code == 0
    # Do not classify an arbitrary Docker error/timeout as authentication rejection.
    code, denied = neo_probe(command, "neo-client-denied")
    checks["neo_wrong_key_rejected"] = code != 0 and b"Unauthenticated" in denied
    return {"schema": "durkahelper.integration-smoke.v1", "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "source_pins": PINS, "scope": "isolated synthetic farm and matched-source Neo info/auth only",
            "not_validated": ["release client", "exploit execution", "Packmate", "recovery", "offline build",
                              "Apple Silicon", "Docker Desktop", "team Ethernet access", "competition adapter"]}


def execute(args):
    workspace, state = fixture(args.workspace, check_files=args.action != "down")
    command = compose_command(workspace, state)
    args.validated_project = state["project"]
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "project": state["project"],
                "requires": "--apply --approval-id; Docker daemon; reviewed prepared fixture",
                "rollback": "down stops only this generated project; data and images are retained"}
    checked(command + ["config", "--quiet"])
    if args.action == "build":
        environment = dict(os.environ, DOCKER_BUILDKIT="0", COMPOSE_PARALLEL_LIMIT="1")
        spec = compose_spec(state["project"], state["images"])
        image_ids = {}
        for role in ("farm", "celery", "front", "neo-server"):
            service = spec["services"][role]
            context = workspace / service["build"]["context"]
            # Runtime Compose limits do NOT constrain builds. Use a capped legacy
            # build per role, serially; fail closed if the engine no longer supports it.
            checked(["docker", "build", "--force-rm", "--memory=2g", "--memory-swap=2g", "--cpu-period=100000",
                     "--cpu-quota=100000", "--tag", service["image"], "--file",
                     str(context / service["build"]["dockerfile"]), str(context)],
                    timeout=1800, environment=environment)
            image_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", service["image"]],
                               capture=True).decode().strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
                raise FixtureError("could not record built image identity")
            image_ids[role] = image_id
        return {"status": "PASS", "action": "build", "source_pins": PINS, "image_ids": image_ids,
                "base_images": state["images"], "build_tools": state.get("build_tools", {}),
                "build_limits": "serial; 2GiB memory+swap; one CPU"}
    elif args.action == "up":
        try:
            checked(command + ["up", "--detach", "--no-build"] + LIVE_SERVICES, timeout=180)
            wait_ready(farm_port(command))
            checked(command + ["up", "--detach", "--no-build", "neo-server"], timeout=60)
        except (FixtureError, KeyboardInterrupt):
            try:
                checked(command + ["down", "--timeout", "10"], timeout=60)
                args.rollback_status = "generated project stopped; data retained"
            except (FixtureError, KeyboardInterrupt):
                args.rollback_status = "automatic stop failed; exact project cleanup required"
            raise
    elif args.action == "smoke":
        result = smoke(command)
        result["rollback"] = "down --workspace SAME_WORKSPACE --apply --approval-id ID; data retained"
        return result
    elif args.action == "down":
        # No --volumes, --rmi, --remove-orphans or host-wide prune; retain evidence/data.
        checked(command + ["down", "--timeout", "10"], timeout=60)
    return {"status": "PASS", "action": args.action, "project": state["project"], "source_pins": PINS}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "build", "up", "smoke", "down"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--s4dfarm-source")
    parser.add_argument("--neo-source")
    parser.add_argument("--images", help="JSON map of seven immutable base image repository digests")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise FixtureError("mutations require a non-secret approval identifier")
        if args.action == "prepare" and not all([args.images, args.s4dfarm_source, args.neo_source]):
            raise FixtureError("prepare requires --images, --s4dfarm-source and --neo-source")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if result["status"] == "FAIL" else 0
    except (FixtureError, OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            subprocess.TimeoutExpired, urllib.error.URLError, KeyboardInterrupt) as error:
        message = ("fixture operation interrupted; raw output suppressed" if isinstance(error, KeyboardInterrupt)
                   else str(error) if isinstance(error, FixtureError) else "fixture operation failed: " + type(error).__name__)
        result = {"status": "BLOCKED", "reason": message}
        if getattr(args, "validated_project", None):
            result.update({"project": args.validated_project,
                "rollback": "down --workspace SAME_WORKSPACE --apply --approval-id ID; data retained",
                "rollback_status": getattr(args, "rollback_status", "not automatically performed")})
            if args.action == "build":
                # Killing/interruption of the CLI does not prove daemon-side
                # build cancellation. A project down only stops its services.
                result.update({"rollback_status": "daemon build cancellation not confirmed; build may remain active",
                    "rollback": "project down does not cancel Docker builds; inspect/cancel only the verified test build; no broad prune"})
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    sys.exit(main())
