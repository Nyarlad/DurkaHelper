#!/usr/bin/env python3
"""New synthetic source -> native/cold backups -> new isolated stack restore.

Only immutable files and cached images are reused from validated lab templates.
Existing database files/containers are never read or changed. Restored Celery,
receiver and Neo worker stay disabled: this drill never replays restored queues.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import threading
import time


def sibling(name):
    spec = importlib.util.spec_from_file_location("whole_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stack = sibling("stack_smoke")
pm = sibling("packmate_smoke")
life = sibling("neo_lifecycle_smoke")
Error = stack.FixtureError
SCHEMA = "durkahelper.stack-recovery.v1"
LABEL = "io.durkahelper.stack-recovery"
MAX_BACKUP = 32 * 1024 * 1024
ROLES = ("source-farm", "source-packmate", "target-farm", "target-packmate")
NOT_VALIDATED = ["production data/queues", "automatic queue replay", "VM rollback", "Docker Desktop", "ARM64", "physical LAN", "LIVE capture", "large-data RPO/RTO"]


def read(path, limit=MAX_BACKUP):
    # Reuse bounded no-follow regular-file reader; never read shared live DBs.
    try:
        return life.release.bounded_read(path, limit)
    except life.release.FixtureError as error:
        raise Error(str(error)) from error


def load(path):
    return json.loads(read(path, 4 * 1024 * 1024))


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def checked(argv, timeout=60):
    """Bound combined command output while reading, including native dumps."""
    data, errors = bytearray(), []
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def drain():
        try:
            while True:
                part = process.stdout.read(65536)
                if not part:
                    break
                if len(data) + len(part) > MAX_BACKUP:
                    raise Error("bounded recovery command exceeded output limit")
                data.extend(part)
        except (OSError, Error) as error:
            errors.append(error)
            process.kill()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise Error("recovery command timed out; raw output suppressed") from error
        reader.join(timeout=5)
        if reader.is_alive() or errors or code:
            raise Error("recovery command failed or exceeded bounds; raw output suppressed")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        reader.join(timeout=5)
        process.stdout.close()


def image_id(reference):
    raw = checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", reference]).decode().strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64};linux;amd64", raw):
        raise Error("whole-stack drill requires cached native Linux amd64 images")
    return raw.split(";")[0]


def owned_spec(spec, project, images, restored=False):
    result = copy.deepcopy(spec)
    for name, service in result["services"].items():
        service["image"] = images[name]
        service.pop("build", None)
        service["labels"] = {LABEL: project}
        service["restart"] = "no"
        if restored and name in {"celery", "receiver", "neo-client", "neo-client-denied"}:
            service["profiles"] = ["disabled-recovery"]
        if restored:
            service.get("depends_on", {}).pop("receiver", None)
        if restored and name in {"redis", "neo-redis"}:
            service["command"] = ["redis-server", "--appendonly", "no", "--save", ""]
    for network in result["networks"].values():
        network["labels"] = {LABEL: project}
    return result


def copy_immutable(source, target, filenames):
    total = 0
    for name in sorted(filenames):
        part = PurePosixPath(name)
        if part.is_absolute() or ".." in part.parts or "\\" in name or ":" in name or part.parts[0] == "data":
            raise Error("unsafe template member")
        if name in {"compose.json", "fixture.json"}:
            continue
        data = read(stack.no_links(source / name), stack.MAX_SOURCE)
        total += len(data)
        if total > stack.MAX_SOURCE:
            raise Error("template immutable files exceed size bound")
        stack.write(target / name, data)
        (target / name).chmod(stat.S_IMODE((source / name).stat().st_mode))


def validate_synthetic_template(root):
    """Do not trust a rehashed fixture ledger to authorize a real endpoint."""
    try:
        tree = ast.parse(read(root / "config/farm.py", 16384).decode("utf-8"))
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign) or len(tree.body[0].targets) != 1 or not isinstance(tree.body[0].targets[0], ast.Name) or tree.body[0].targets[0].id != "CONFIG":
            raise ValueError()
        config = ast.literal_eval(tree.body[0].value)
    except (ValueError, TypeError, SyntaxError, UnicodeError) as error:
        raise Error("farm template must contain literal synthetic configuration only") from error
    expected = {"DEBUG": False, "TEAMS": {"Synthetic": "192.0.2.1"}, "FLAG_FORMAT": "[A-Z0-9]{31}=",
                "SYSTEM_PROTOCOL": "ructf_http", "SYSTEM_URL": "http://receiver:8080/flags", "SYSTEM_TOKEN": "fixture-only",
                "SUBMIT_FLAG_LIMIT": 10, "SUBMIT_PERIOD": 1, "FLAG_LIFETIME": 300, "SERVER_PASSWORD": "fixture-only", "TIMEZONE": "UTC"}
    if config != expected:
        raise Error("farm template differs from the exact synthetic competition settings")
    neo = ('db_path: "/data/db.db"\nredis_url: "redis://neo-redis:6379/0"\nbase_dir: "/data/exploits"\nping_every: "5s"\nsubmit_every: "2s"\ngrpc_auth_key: "fixture-only"\nfarm:\n  url: "http://front"\n  password: "fixture-only"\n').encode()
    if read(root / "config/neo-server.yml", 16384) != neo:
        raise Error("Neo template differs from the exact synthetic server settings")
    if read(root / "receiver.py", 65536) != read(Path(__file__).with_name("synthetic_receiver.py"), 65536):
        raise Error("synthetic receiver implementation differs from this harness")


def prepare(args):
    farm_root, farm = stack.fixture(args.stack_workspace)
    validate_synthetic_template(farm_root)
    pm_root, packmate = pm.fixture(args.packmate_workspace)
    release_root, _ = life.release.fixture(args.release_workspace)
    root = stack.no_links(args.workspace)
    if root.exists() or not root.parent.is_dir() or any(root.is_relative_to(p) for p in (farm_root, pm_root, release_root)):
        raise Error("recovery workspace must be new and outside all templates")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "effects": ["new private source/target configurations", "read-only cached image identity checks"],
                "existing_template_data": "never read or copied", "not_validated": NOT_VALIDATED}
    if os.name == "nt" or os.getuid() == 0:
        raise Error("drill preparation requires a non-root POSIX operator")
    original_farm = load(farm_root / "compose.json")
    original_pm = load(pm_root / "compose.json")
    farm_images = {name: image_id(svc["image"]) for name, svc in original_farm["services"].items()}
    pm_images = {name: image_id(svc["image"]) for name, svc in original_pm["services"].items()}
    helper_image = image_id(farm["images"]["alpine"])
    root.mkdir(mode=0o700)
    project = "dh-whole-" + secrets.token_hex(6)
    projects = {role: project + "-" + role for role in ROLES}
    for role in ROLES:
        target = root / role
        target.mkdir(mode=0o700)
        is_farm = role.endswith("farm")
        copy_immutable(farm_root if is_farm else pm_root, target, farm["files"] if is_farm else ["application.properties", "pcaps/synthetic.pcap"])
        if not is_farm:
            (target / "pcaps").chmod(0o755)
        for directory in (("postgres", "redis", "neo-redis", "neo") if is_farm else ("postgres",)):
            (target / "data" / directory).mkdir(parents=True, mode=0o700)
        spec = owned_spec(original_farm if is_farm else original_pm, projects[role], farm_images if is_farm else pm_images, role.startswith("target"))
        stack.write(target / "compose.json", stack.canonical(spec))
    (root / "backups").mkdir(mode=0o700)
    (root / "client").mkdir(mode=0o700)
    identifier = "dh-life-" + secrets.token_hex(6)
    flag = secrets.token_hex(16).upper()[:31] + "="
    for name, data in (("neo", read(release_root / "neo")), ("client.yml", life.config(identifier)), ("synthetic.sh", life.payload(flag))):
        stack.write(root / "client" / name, data)
        (root / "client" / name).chmod(0o555 if name == "neo" else 0o644)
    files = {p.relative_to(root).as_posix(): hash_bytes(read(p, stack.MAX_SOURCE)) for p in root.rglob("*") if p.is_file()}
    state = {"schema": SCHEMA, "id": project, "projects": projects, "files": files, "helper_image": helper_image,
             "packmate": packmate, "task": {"id": identifier, "flag": flag}, "approval_id": args.approval_id,
             "uid": os.getuid(), "source_pins": stack.PINS, "release_sha256": life.release.SHA256}
    stack.write(root / "recovery.json", stack.canonical(state))
    return {"status": "PASS", "action": "prepare", "fixture": project, "existing_template_data": "never read or copied", "not_validated": NOT_VALIDATED}


def fixture(path):
    root = stack.no_links(path)
    state = load(root / "recovery.json")
    if (state.get("schema") != SCHEMA or not re.fullmatch(r"dh-whole-[a-f0-9]{12}", state.get("id", ""))
            or state.get("source_pins") != stack.PINS or state.get("release_sha256") != life.release.SHA256
            or set(state.get("projects", {})) != set(ROLES) or not 1 <= len(state.get("files", {})) <= 20000):
        raise Error("invalid whole-stack recovery identity")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", state.get("helper_image", "")):
        raise Error("cold-copy helper must use an immutable local image identity")
    for role in ROLES:
        if state["projects"][role] != state["id"] + "-" + role:
            raise Error("invalid owned project mapping")
    for name, digest in state["files"].items():
        part = PurePosixPath(name)
        if part.is_absolute() or ".." in part.parts or "\\" in name or ":" in name or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise Error("invalid immutable recovery member")
        if hash_bytes(read(stack.no_links(root / name), stack.MAX_SOURCE)) != digest:
            raise Error("immutable recovery input changed")
    for role in ROLES:
        folder = stack.no_links(root / role / "data")
        if not folder.is_dir():
            raise Error("missing owned recovery data directory")
        spec = load(root / role / "compose.json")
        for service in spec["services"].values():
            if service.get("labels") != {LABEL: state["projects"][role]} or not re.fullmatch(r"sha256:[a-f0-9]{64}", service["image"]):
                raise Error("invalid immutable recovery service")
    return root, state


def command(root, state, role):
    if role not in ROLES:
        raise Error("invalid recovery role")
    return ["docker", "compose", "--project-name", state["projects"][role], "--project-directory", str(root / role),
            "--file", str(root / role / "compose.json")]


def ownership(state, role):
    project = state["projects"][role]
    for kind, prefix in (("container", ["ps", "--all", "--quiet"]), ("network", ["network", "ls", "--quiet"])):
        ids = checked(["docker"] + prefix + ["--filter", "label=com.docker.compose.project=" + project]).decode().split()
        if len(ids) > 32 or any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in ids):
            raise Error("invalid owned resource listing")
        for identity in ids:
            field = ".Config.Labels" if kind == "container" else ".Labels"
            label = checked(["docker", kind, "inspect", "--format", '{{index ' + field + ' "' + LABEL + '"}}', identity]).decode().strip()
            if label != project:
                raise Error("resource ownership mismatch; cleanup refused")


def compose(root, state, role, arguments, timeout=90):
    ownership(state, role)
    return checked(command(root, state, role) + arguments, timeout)


def psql(cmd, service, database, sql):
    return checked(cmd + ["exec", "-T", service, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-A", "-t", "-U", database, "-d", database, "-c", sql], 20).strip()


def ready_db(cmd, service, database):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            checked(cmd + ["exec", "-T", service, "pg_isready", "-h", "127.0.0.1", "-U", database, "-d", database], 5)
            return
        except Error:
            time.sleep(0.5)
    raise Error("owned recovery database readiness timed out")


def database_summary(cmd, service, database):
    names = psql(cmd, service, database, "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name;").decode().split()
    if not 1 <= len(names) <= 40 or any(not re.fullmatch(r"[a-z_][a-z0-9_]{0,60}", name) for name in names):
        raise Error("unexpected synthetic database schema")
    result = {}
    for name in names:
        # Names originate from a bounded identifier allowlist; order JSON text
        # rather than physical rows, so restore layout cannot affect comparison.
        data = psql(cmd, service, database, 'SELECT COALESCE(json_agg(j ORDER BY j::text),\'[]\'::json) FROM (SELECT row_to_json(t) AS j FROM "' + name + '" t) s;')
        rows = json.loads(data)
        if not isinstance(rows, list) or len(rows) > 10000:
            raise Error("synthetic table exceeds row bound")
        result[name] = {"rows": len(rows), "sha256": hash_bytes(stack.canonical(rows))}
    return result


def native_dump(cmd, service, database, path):
    data = checked(cmd + ["exec", "-T", service, "pg_dump", "-U", database, "-d", database, "--format=custom", "--compress=0", "--no-owner", "--no-privileges"], 60)
    if not data.startswith(b"PGDMP"):
        raise Error("native PostgreSQL dump signature missing")
    stack.write(path, data)
    return {"bytes": len(data), "sha256": hash_bytes(data)}


def restore_pg(cmd, service, database, path, expected):
    if psql(cmd, service, database, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';") != b"0":
        raise Error("restore target database is not empty")
    data = read(path)
    if not data.startswith(b"PGDMP") or {"bytes": len(data), "sha256": hash_bytes(data)} != expected:
        raise Error("native restore input checksum mismatch")
    result = subprocess.run(cmd + ["exec", "-T", service, "pg_restore", "-U", database, "-d", database, "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges"],
                            input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
    if result.returncode:
        raise Error("native restore failed; new target retained")


def archive_files(data):
    if len(data) > MAX_BACKUP:
        raise Error("cold archive exceeds byte bound")
    result, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        total = 0
        for member in archive:
            name = member.name[2:] if member.name.startswith("./") else member.name
            if name in {"", "."} and member.isdir():
                continue
            path = PurePosixPath(name)
            if (path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name or name in seen
                    or not (member.isfile() or member.isdir()) or len(seen) >= 256):
                raise Error("unsafe cold archive member")
            seen.add(name)
            if member.isdir():
                continue
            total += member.size
            if member.size < 0 or total > MAX_BACKUP:
                raise Error("expanded cold archive exceeds bound")
            with archive.extractfile(member) as stream:
                value = stream.read(MAX_BACKUP + 1)
            if len(value) != member.size:
                raise Error("truncated cold archive member")
            result[name] = value
    if not result:
        raise Error("cold archive is empty")
    return result


def cold_archive(root, state, directory):
    source = stack.no_links(root / "source-farm/data" / directory)
    if directory not in {"neo", "redis", "neo-redis"} or any(c in str(source) for c in (",", "\n", "\r")):
        raise Error("unapproved cold source")
    name = state["id"] + "-read-" + secrets.token_hex(4)
    created = False
    try:
        checked(["docker", "create", "--name", name, "--label", LABEL + "=" + state["id"], "--network", "none", "--read-only", "--cap-drop=ALL", "--cap-add=DAC_READ_SEARCH",
                 "--security-opt=no-new-privileges:true", "--memory=64m", "--cpus=0.5", "--pids-limit=16", "--log-driver=none", "--pull=never",
                 "--mount", "type=bind,src=" + str(source) + ",dst=/data,readonly", "--entrypoint", "tar", state["helper_image"], "-C", "/data", "-cf", "-", "."])
        created = True
        result = checked(["docker", "start", "--attach", name])
        archive_files(result)
        return result
    finally:
        if created:
            label = checked(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name]).decode().strip()
            if label != state["id"]:
                raise Error("cold-copy helper ownership mismatch")
            checked(["docker", "rm", "--force", name])


def packmate_state(cmd, state):
    port = pm.app_port(cmd)
    pm.wait_ready(port, state)
    services = pm.json_request(port, state, "/api/service/")
    patterns = pm.json_request(port, state, "/api/pattern/")
    if (not isinstance(services, list) or len(services) != 1 or services[0].get("port") != pm.pcap.SERVICE_PORT
            or not isinstance(patterns, list) or len(patterns) != 1 or patterns[0].get("value") != state["marker"] or patterns[0].get("enabled") is not True):
        raise Error("Packmate contains unexpected non-synthetic settings")
    identifier = patterns[0]["id"]
    streams = pm.json_request(port, state, "/api/stream/" + str(pm.pcap.SERVICE_PORT), "POST",
                              {"startingFrom": None, "pageSize": 10, "favorites": False, "pattern": {"id": identifier}})
    if not isinstance(streams, list) or len(streams) != 1 or streams[0].get("protocol") != "TCP":
        raise Error("Packmate synthetic stream missing or duplicated")
    packets = pm.json_request(port, state, "/api/packet/" + str(streams[0]["id"]), "POST", {"startingFrom": None, "pageSize": 20})
    wanted = pm.pcap.payloads(state["marker"])
    if not isinstance(packets, list) or len(packets) > 20:
        raise Error("unexpected synthetic packet collection")
    payloads = [(base64.b64decode(packet.get("content", ""), validate=True), packet.get("incoming")) for packet in packets]
    if (wanted[0], True) not in payloads or (wanted[1], False) not in payloads:
        raise Error("Packmate recovered packet direction/content mismatch")
    return {"services": hash_bytes(stack.canonical(services)), "patterns": hash_bytes(stack.canonical(patterns)),
            "streams": hash_bytes(stack.canonical(streams)), "packets": hash_bytes(stack.canonical(packets))}


def neo_state(root, state, role, action="info"):
    try:
        raw = life.run_client(root / "client", state["task"], root / "client/neo", state["helper_image"], state["projects"][role] + "_fixture", action)
    except life.Error as error:
        raise Error(str(error)) from error
    if action != "info":
        return None
    lines = [line.strip() for line in raw.splitlines() if b"exploit_id:" in line]
    if len(lines) != 1 or state["task"]["id"].encode() not in lines[0] or b"disabled:true" not in lines[0] or b"version:1" not in lines[0]:
        raise Error("Neo must contain exactly the disabled synthetic task at version 1")
    return hash_bytes(lines[0])


def start_farm_apps(root, state, role, *, source):
    # Pinned Neo fetches farm configuration once during server startup. Merely
    # creating both containers together can leave Neo exited before the farm
    # is ready; the restored path needs exactly the same ordering.
    services = list(stack.LIVE_SERVICES) if source else ["farm", "front"]
    compose(root, state, role, ["up", "--detach", "--no-build", "--pull", "never"] + services, 180)
    stack.wait_ready(stack.farm_port(command(root, state, role)))
    compose(root, state, role, ["up", "--detach", "--no-build", "--pull", "never", "--no-deps", "neo-server"], 60)
    deadline = time.monotonic() + 60
    while True:
        try:
            life.run_client(root / "client", state["task"], root / "client/neo", state["helper_image"],
                            state["projects"][role] + "_fixture", "info")
            return
        except life.Error as error:
            if time.monotonic() >= deadline:
                raise Error("owned Neo server readiness timed out; raw output suppressed") from error
            time.sleep(1)


def farm_state(cmd, flag):
    port = stack.farm_port(cmd)
    stack.wait_ready(port)
    status, raw = stack.request(port, "/api/get_config")
    config = json.loads(raw)
    if status != 200 or config.get("TEAMS") != {"Synthetic": "192.0.2.1"}:
        raise Error("farm synthetic configuration mismatch")
    status, raw = stack.request(port, "/api/filter_flags?flag=" + flag)
    flags = json.loads(raw).get("flags", []) if status == 200 else []
    if len(flags) != 1 or flags[0].get("flag") != flag or flags[0].get("status") != "ACCEPTED" or flags[0].get("sploit") != "synthetic-whole-recovery":
        raise Error("farm synthetic result missing or changed")
    return {"config": hash_bytes(stack.canonical(config)), "flag": hash_bytes(stack.canonical(flags))}


def run(args):
    root, state = fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "run", "effects": ["initialize new synthetic source apps", "native PostgreSQL/Redis backups", "cold Neo copy", "new isolated restore"], "not_validated": NOT_VALIDATED}
    if not args.snapshot_confirmed or os.name == "nt" or os.getuid() != state["uid"] or os.getuid() == 0:
        raise Error("restore requires --snapshot-confirmed and the same non-root POSIX operator")
    if (root / "attempt.json").exists():
        raise Error("recovery attempt already exists; prepare a fresh workspace")
    for role in ROLES:
        ownership(state, role)
        if checked(command(root, state, role) + ["ps", "--all", "--quiet"]).strip():
            raise Error("new recovery projects must have no containers")
        for folder in (root / role / "data").iterdir():
            stack.no_links(folder)
            if not folder.is_dir() or any(folder.iterdir()):
                raise Error("all new source/target data directories must be empty")
    stack.write(root / "attempt.json", stack.canonical({"approval_id": args.approval_id, "snapshot_confirmed": True}))
    report = {"schema": "durkahelper.stack-recovery-result.v1", "status": "BLOCKED", "phase": "source-start", "checks": {}, "not_validated": NOT_VALIDATED,
              "queue_policy": "no target receiver, Celery or Neo worker is started", "existing_template_data": "never read or changed"}
    sf, sp, tf, tp = [command(root, state, role) for role in ROLES]
    try:
        start_farm_apps(root, state, "source-farm", source=True)
        compose(root, state, "source-packmate", ["up", "--detach", "--no-build", "--pull", "never"], 180)
        port = stack.farm_port(sf)
        stack.wait_ready(port)
        # New source state only: exactly one explicit synthetic accepted flag.
        flag = state["task"]["flag"]
        if stack.request(port, "/api/post_flags", "POST", [{"flag": flag, "sploit": "synthetic-whole-recovery", "team": "Synthetic"}])[0] != 200:
            raise Error("synthetic farm seed failed")
        deadline = time.monotonic() + 45
        while True:
            try:
                farm_before = farm_state(sf, flag)
                break
            except Error:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        report["phase"] = "source-neo-seed"
        neo_state(root, state, "source-farm", "add")
        neo_before = neo_state(root, state, "source-farm")
        report["phase"] = "source-packmate-seed"
        packmate_smoke = pm.smoke(sp, state["packmate"])
        if packmate_smoke["status"] != "PASS":
            raise Error("new synthetic Packmate import did not pass")
        pm_before = packmate_state(sp, state["packmate"])
        report["phase"] = "quiesce-source"
        compose(root, state, "source-farm", ["stop", "--timeout", "15", "celery", "receiver", "neo-server", "farm", "front"])
        compose(root, state, "source-packmate", ["stop", "--timeout", "15", "packmate"])
        quiesced = time.monotonic()
        for service in ("redis", "neo-redis"):
            if checked(sf + ["exec", "-T", service, "redis-cli", "SET", "durkahelper:recovery", state["task"]["id"]]).strip() != b"OK":
                raise Error("synthetic Redis marker seed failed")
            if checked(sf + ["exec", "-T", service, "redis-cli", "SAVE"]).strip() != b"OK":
                raise Error("native Redis SAVE failed")
        report["phase"] = "native-backups"
        farm_rows = database_summary(sf, "postgres", "farm")
        pm_rows = database_summary(sp, "db", "packmate")
        if set(farm_rows) != {"flags"} or farm_rows["flags"]["rows"] != 1:
            raise Error("new farm database is not exactly the seeded synthetic row")
        dumps = {"farm": native_dump(sf, "postgres", "farm", root / "backups/farm.dump"),
                 "packmate": native_dump(sp, "db", "packmate", root / "backups/packmate.dump")}
        if database_summary(sf, "postgres", "farm") != farm_rows or database_summary(sp, "db", "packmate") != pm_rows:
            raise Error("quiesced source rows changed while backing up")
        compose(root, state, "source-farm", ["stop", "--timeout", "15", "postgres", "redis", "neo-redis"])
        compose(root, state, "source-packmate", ["stop", "--timeout", "15", "db"])
        cold, manifests = {}, {}
        for directory in ("neo", "redis", "neo-redis"):
            archive = cold_archive(root, state, directory)
            stack.write(root / "backups" / (directory + ".tar"), archive)
            files = archive_files(archive)
            manifests[directory] = {name: hash_bytes(data) for name, data in files.items()}
            if directory != "neo":
                if "dump.rdb" not in files or not files["dump.rdb"].startswith(b"REDIS"):
                    raise Error("native Redis RDB missing from cold snapshot")
                files = {"dump.rdb": files["dump.rdb"]}
            elif "db.db" not in files:
                raise Error("Neo bbolt database missing from cold snapshot")
            cold[directory] = files
        backup_at = time.monotonic()
        report["phase"] = "restore-empty-target"
        recovery_at = time.monotonic()
        for directory, files in cold.items():
            for name, data in files.items():
                stack.write(root / "target-farm/data" / directory / name, data)
        compose(root, state, "target-farm", ["up", "--detach", "--no-build", "--pull", "never", "postgres", "redis", "neo-redis"], 120)
        compose(root, state, "target-packmate", ["up", "--detach", "--no-build", "--pull", "never", "db"], 120)
        ready_db(tf, "postgres", "farm")
        ready_db(tp, "db", "packmate")
        restore_pg(tf, "postgres", "farm", root / "backups/farm.dump", dumps["farm"])
        farm_rto = time.monotonic() - recovery_at
        restore_pg(tp, "db", "packmate", root / "backups/packmate.dump", dumps["packmate"])
        report["checks"]["farm_rows_restored"] = database_summary(tf, "postgres", "farm") == farm_rows
        report["checks"]["packmate_rows_restored"] = database_summary(tp, "db", "packmate") == pm_rows
        for service in ("redis", "neo-redis"):
            report["checks"][service + "_native_value_restored"] = checked(tf + ["exec", "-T", service, "redis-cli", "--raw", "GET", "durkahelper:recovery"]).strip() == state["task"]["id"].encode()
        redis_rto = time.monotonic() - recovery_at
        report["phase"] = "restored-app-verification"
        start_farm_apps(root, state, "target-farm", source=False)
        compose(root, state, "target-packmate", ["up", "--detach", "--no-build", "--pull", "never", "packmate"], 120)
        report["checks"]["farm_config_and_result_restored"] = farm_state(tf, flag) == farm_before
        farm_app_rto = time.monotonic() - recovery_at
        report["checks"]["neo_disabled_task_restored"] = neo_state(root, state, "target-farm") == neo_before
        neo_rto = time.monotonic() - recovery_at
        report["checks"]["packmate_settings_packets_restored"] = packmate_state(tp, state["packmate"]) == pm_before
        pm_rto = time.monotonic() - recovery_at
        report["checks"]["packmate_capture_not_restarted"] = pm.json_request(pm.app_port(tp), state["packmate"], "/api/pcap/started") is False
        for service in ("celery", "receiver"):
            report["checks"][service + "_not_replayed"] = not checked(tf + ["ps", "--quiet", service]).strip()
        for directory in cold:
            current = archive_files(cold_archive(root, state, directory))
            report["checks"][directory + "_source_cold_unchanged"] = {name: hash_bytes(data) for name, data in current.items()} == manifests[directory]
        report["checks"]["source_databases_logically_unchanged_during_backup"] = True
        report["backups"] = dumps
        report["cold_manifests_sha256"] = {name: hash_bytes(stack.canonical(value)) for name, value in manifests.items()}
        preservation = all(report["checks"][key] for key in ("farm_rows_restored", "packmate_rows_restored", "farm_config_and_result_restored", "neo_disabled_task_restored", "packmate_settings_packets_restored"))
        report["timings"] = {"quiesced_backup_age_seconds": round(backup_at - quiesced, 3), "synthetic_records_lost": 0 if preservation else None,
            "restore_seconds": {"farm_database": round(farm_rto, 3), "farm_application": round(farm_app_rto, 3),
                                "redis": round(redis_rto, 3), "neo_application": round(neo_rto, 3), "packmate_application": round(pm_rto, 3)}}
        report["checks"]["backup_age_under_300s"] = backup_at - quiesced <= 300
        report["checks"]["whole_restore_under_600s"] = pm_rto <= 600
        report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
        report["phase"] = "complete"
    finally:
        cleanup = {}
        for role in reversed(ROLES):
            try:
                compose(root, state, role, ["--profile", "disabled-recovery", "down", "--timeout", "15"], 90)
                cleanup[role] = not checked(command(root, state, role) + ["ps", "--all", "--quiet"]).strip()
            except (Error, OSError, subprocess.SubprocessError):
                cleanup[role] = False
        report["cleanup"] = cleanup
        if not all(cleanup.values()):
            report["status"] = "BLOCKED"
        report["rollback"] = "exact labelled source/target containers and networks removed; all private data and native/cold backups retained"
        stack.write(root / "result.json", stack.canonical(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--workspace", required=True)
    for field in ("stack-workspace", "packmate-workspace", "release-workspace", "approval-id"):
        parser.add_argument("--" + field)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret approval identifier")
        if args.action == "prepare" and not all((args.stack_workspace, args.packmate_workspace, args.release_workspace)):
            raise Error("prepare requires the three strict lab template workspaces")
        result = prepare(args) if args.action == "prepare" else run(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return {"PASS": 0, "NOT_RUN": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]
    except (Exception, KeyboardInterrupt) as error:
        # Upstream helper exception classes differ by isolated import; never
        # print their arbitrary payloads. Our own diagnostics are sanitized.
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else "recovery stopped: " + type(error).__name__,
                          "raw_output": "suppressed", "retained": "private workspace, source/target data and backups; inspect local result.json"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
