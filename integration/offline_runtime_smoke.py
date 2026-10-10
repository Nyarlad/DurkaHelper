#!/usr/bin/env python3
"""Opt-in network-isolated cold start on an existing native Linux Docker Engine.

Uses a prepared maintained deployment as a source/image template, never its data
or operational settings. All new settings, credentials and records are synthetic.
This does not prove clean-daemon installation, native installers, Mac or TEAM-LAN.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


kit = module("offline_kit", "deployment/toolkit.py")
bundle = module("offline_bundle", "scripts/toolchain_bundle.py")
pcap = module("offline_pcap", "integration/synthetic_pcap.py")
shared, Error = kit.shared, kit.Error
SCHEMA = "durkahelper.offline-runtime.v1"
LABEL = "io.durkahelper.offline-runtime"
PURPOSE = "io.durkahelper.offline-helper"
ROLES = {"postgres", "redis", "neo-redis", "farm", "celery", "front", "neo-server", "neo-worker", "packmate-db", "packmate"}
APPS = ("postgres", "redis", "neo-redis", "farm", "front", "neo-server", "packmate-db", "packmate")
MAX_FILES = 50 * 1024 * 1024
NOT_VALIDATED = ["clean-daemon installation", "complete source/client/license/installer kit", "Mac or ARM64",
                 "physical LAN", "LIVE capture", "real competition submission", "operator-data recovery"]

# The helper prints only boolean checks and hashes. Fixed endpoints and paths
# prevent using profile input as a URL, shell command or generic network probe.
PROBE = b'''import base64, hashlib, json, socket, sys, time, urllib.error, urllib.request
from pathlib import Path
def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def digest(value): return hashlib.sha256(canonical(value)).hexdigest()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
def request(component,path,method="GET",body=None,auth=True):
    base="http://front" if component=="farm" else "http://packmate:65000"
    headers={"Content-Type":"application/json","Accept-Encoding":"identity"}
    if auth:
        headers["Authorization"]=C["farm_password"] if component=="farm" else "Basic "+base64.b64encode((C["packmate_user"]+":"+C["packmate_password"]).encode()).decode()
    req=urllib.request.Request(base+path,headers=headers,method=method,data=None if body is None else canonical(body))
    try: response=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(req,timeout=3)
    except urllib.error.HTTPError as error: response=error
    with response:
        raw=response.read(1048577)
        if len(raw)>1048576: raise ValueError("response too large")
        return response.status,raw
def api(component,path,method="GET",body=None):
    status,raw=request(component,path,method,body)
    if status!=200: raise ValueError("API status rejected")
    return json.loads(raw) if raw else None
def farm_summary():
    settings=api("farm","/api/get_config")
    if settings.get("TEAMS")!={"Synthetic":"192.0.2.1"} or settings.get("SYSTEM_PROTOCOL")!="ructf_http": raise ValueError("non-synthetic farm settings")
    if any("PASSWORD" in key or "TOKEN" in key for key in settings): raise ValueError("secret fields exposed")
    flags=api("farm","/api/filter_flags?flag="+C["flag"])["flags"]
    if len(flags)!=1 or flags[0].get("flag")!=C["flag"] or flags[0].get("status")!="QUEUED" or flags[0].get("sploit")!="synthetic-offline": raise ValueError("queued synthetic record changed")
    return {"farm_settings":digest(settings),"farm_queued_flag":digest(flags)}
def pack_summary():
    services=api("packmate","/api/service/"); patterns=api("packmate","/api/pattern/")
    if len(services)!=1 or services[0].get("port")!=18080 or len(patterns)!=1 or patterns[0].get("value")!=C["marker"] or patterns[0].get("enabled") is not True: raise ValueError("non-synthetic Packmate state")
    streams=api("packmate","/api/stream/18080","POST",{"startingFrom":None,"pageSize":10,"favorites":False,"pattern":{"id":patterns[0]["id"]}})
    if len(streams)!=1 or streams[0].get("protocol")!="TCP": raise ValueError("synthetic stream missing")
    packets=api("packmate","/api/packet/"+str(streams[0]["id"]),"POST",{"startingFrom":None,"pageSize":20})
    if not isinstance(packets,list) or len(packets)>20: raise ValueError("invalid packet collection")
    found=[(p.get("content"),p.get("incoming")) for p in packets]
    if (C["request"],True) not in found or (C["response"],False) not in found: raise ValueError("synthetic packet direction mismatch")
    return {"packmate_services":digest(services),"packmate_patterns":digest(patterns),"packmate_streams":digest(streams),"packmate_packets":digest(packets)}
def main(action):
    if action=="witness":
        listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind(("0.0.0.0",18765)); listener.listen(8); listener.settimeout(1)
        deadline=time.monotonic()+1200
        while time.monotonic()<deadline:
            try:
                conn,_=listener.accept()
                with conn: conn.sendall(b"offline-witness\\n")
            except socket.timeout: pass
        return {}
    if action in {"network","witness-control"}:
        target=sys.argv[2]
        socket.inet_aton(target)
        reachable=False
        try:
            with socket.create_connection((target,18765),timeout=2) as conn: reachable=conn.recv(64)==b"offline-witness\\n"
        except OSError: pass
        if action=="witness-control": return {"owned_witness_reachable":reachable}
        routes=Path("/proc/net/route").read_text().splitlines()[1:]
        default4=any(len(line.split())>3 and line.split()[1]=="00000000" and int(line.split()[3],16)&1 and not int(line.split()[3],16)&0x200 and line.split()[0]!="lo" for line in routes)
        routes6=Path("/proc/net/ipv6_route").read_text().splitlines()
        default6=any(len(line.split())>9 and line.split()[0]=="0"*32 and line.split()[1]=="00" and int(line.split()[8],16)&1 and not int(line.split()[8],16)&0x200 and line.split()[9]!="lo" for line in routes6)
        return {"no_default_ipv4":not default4,"no_default_ipv6":not default6,"owned_witness_denied":not reachable}
    if action=="farm-ready":
        data=api("farm","/api/get_config")
        return {"synthetic_farm_ready":data.get("TEAMS")=={"Synthetic":"192.0.2.1"} and data.get("SYSTEM_PROTOCOL")=="ructf_http"}
    if action=="ready": return {"packmate_ready":isinstance(api("packmate","/api/service/"),list)}
    if action=="seed":
        if api("packmate","/api/service/")!=[] or api("packmate","/api/pcap/started") is not False: raise ValueError("fresh FILE state required")
        api("farm","/api/post_flags","POST",[{"flag":C["flag"],"sploit":"synthetic-offline","team":"Synthetic"}])
        api("packmate","/api/service/","POST",{"port":18080,"name":"Synthetic offline HTTP","decryptTls":False,"http":False,"urldecodeHttpRequests":False,"mergeAdjacentPackets":False,"parseWebSockets":False})
        api("packmate","/api/pattern/","POST",{"name":"Synthetic offline marker","value":C["marker"],"color":"#123456","searchType":"SUBSTRING","directionType":"BOTH","actionType":"FIND","serviceId":18080})
        api("packmate","/api/pcap/start","POST")
        deadline=time.monotonic()+45
        while True:
            try: pack=pack_summary(); break
            except (ValueError,OSError):
                if time.monotonic()>deadline: raise
                time.sleep(1)
        return {"hashes":dict(farm_summary(),**pack),"checks":{"farm_unauthenticated_rejected":request("farm","/api/get_config",auth=False)[0]==403,"packmate_unauthenticated_rejected":request("packmate","/api/service/",auth=False)[0]==401}}
    if action=="verify": return {"hashes":dict(farm_summary(),**pack_summary()),"checks":{"file_capture_idle_after_cold_start":api("packmate","/api/pcap/started") is False}}
    raise ValueError("unknown fixed action")
try:
    action=sys.argv[1]
    C=json.loads(Path("/probe-config.json").read_text()) if action not in {"network","witness","witness-control"} else {}
    print(json.dumps(main(action),sort_keys=True))
except Exception as error:
    print(json.dumps({"error_type":type(error).__name__,"raw_output":"suppressed"})); sys.exit(2)
'''


def digest(value):
    return hashlib.sha256(value).hexdigest()


def synthetic_profile():
    return {"schema": "durkahelper.deployment-profile.v1", "platform": {"os": "linux", "architecture": "amd64", "runtime": "docker-engine"},
            "bind_address": "127.0.0.1", "ports": {"farm": 38080, "neo": 35005, "packmate": 35000}, "allow_amd64_emulation": False,
            "farm": {"teams": {"Synthetic": "192.0.2.1"}, "flag_format": "[A-Z0-9]{31}=", "protocol": "ructf_http",
                     "protocol_settings": {"SYSTEM_URL": "http://offline-no-submission.invalid/flags", "SYSTEM_TOKEN": "synthetic-offline-only"},
                     "submit_limit": 10, "submit_period": 1, "flag_lifetime": 300},
            "packmate": {"mode": "FILE", "local_ip": pcap.SERVER_IP, "pcap_file": "synthetic.pcap", "interface": "", "retention_minutes": 60}}


def image_closure(manifest, images):
    if set(images) != ROLES or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in images.values()):
        raise Error("template must pin every maintained deployment image by exact local ID")
    archives = [item for item in manifest["artifacts"] if item["kind"] == "image"]
    if (not 1 <= len(archives) <= 16 or sum(item["size"] for item in archives) > 4 * 1024 ** 3 or
            any(item["architecture"] != "linux/amd64" for item in archives)):
        raise Error("offline rehearsal requires at most sixteen Linux amd64 image archives totaling at most 4 GiB")
    available = {identity for item in archives for identity in item["image_ids"]}
    if set(images.values()) != available:
        raise Error("verified bundle image inventory must exactly cover runtime/helper identities without extra images")


def compose_spec(state):
    spec = kit.compose_spec(synthetic_profile(), state["credentials"], state["project"], shared.image_map(ROOT / "config/integration-images.lock.json"))
    spec = kit.runtime_spec(spec, state["images"])
    for name in ("celery", "neo-worker"):
        del spec["services"][name]
    for service in spec["services"].values():
        service["restart"] = "no"
        service["networks"] = ["offline"]
        service["labels"] = {LABEL: state["project"]}
        service.pop("ports", None)
        service.pop("profiles", None)
    # An in-network positive control proves that the denied cross-network
    # connection is not simply a stopped witness. It has no external network.
    spec["services"]["witness"] = {"image": state["images"]["farm"], "platform": "linux/amd64", "entrypoint": ["python", "-B", "/probe.py"],
        "command": ["witness"], "user": "65534:65534", "read_only": True, "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"], "cpus": 0.25, "mem_limit": "64m", "pids_limit": 32,
        "logging": {"driver": "none"}, "restart": "no", "labels": {LABEL: state["project"]},
        "volumes": ["./probe.py:/probe.py:ro"], "networks": ["witness"]}
    spec["networks"] = {name: {"internal": True, "enable_ipv6": False, "driver": "bridge",
        "driver_opts": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}, "labels": {LABEL: state["project"]}} for name in ("offline", "witness")}
    return spec


def generated_files(state):
    credentials, profile = state["credentials"], synthetic_profile()
    farm = profile["farm"]
    config = dict(DEBUG=False, TEAMS=farm["teams"], FLAG_FORMAT=farm["flag_format"], SYSTEM_PROTOCOL=farm["protocol"],
                  SUBMIT_FLAG_LIMIT=10, SUBMIT_PERIOD=1, FLAG_LIFETIME=300, SERVER_PASSWORD=credentials["farm_password"], TIMEZONE="UTC", **farm["protocol_settings"])
    client = ('host: "neo-server:5005"\ngrpc_auth_key: "' + credentials["neo_key"] + '"\nexploit_dir: "/work/exploits"\nclient_id: "' + state["project"] + '"\n').encode()
    request, response = pcap.payloads(state["marker"])
    helper = {name: credentials[name] for name in ("farm_password", "packmate_user", "packmate_password")}
    helper.update(marker=state["marker"], flag=state["flag"], request=base64.b64encode(request).decode(), response=base64.b64encode(response).decode())
    return {"compose.json": shared.canonical(compose_spec(state)), "probe.py": PROBE, "probe-config.json": shared.canonical(helper),
        "config/farm.py": ("CONFIG = " + repr(config) + "\n").encode(),
        "config/neo-server.yml": ('db_path: "/data/db.db"\nredis_url: "redis://neo-redis:6379/0"\nbase_dir: "/data/exploits"\nping_every: "5s"\nsubmit_every: "2s"\ngrpc_auth_key: "' + credentials["neo_key"] + '"\nfarm:\n  url: "http://front"\n  password: "' + credentials["farm_password"] + '"\n').encode(),
        "config/neo-client.yml": client, "config/neo-denied.yml": client.replace(credentials["neo_key"].encode(), b"intentionally-wrong-synthetic-key"),
        "config/packmate.properties": kit.properties(profile, credentials).encode(), "pcaps/synthetic.pcap": pcap.make_pcap(state["marker"]),
        "synthetic.sh": b"#!/bin/sh\n# flush=True\nprintf '%s\\n' 'offline-disabled-task'\n"}


def validate_state(value):
    keys = {"schema", "project", "daemon_id", "images", "credentials", "marker", "flag", "bundle", "bundle_manifest_sha256", "template_receipt_sha256", "files"}
    if not isinstance(value, dict) or set(value) != keys or value["schema"] != SCHEMA:
        raise Error("invalid offline fixture state")
    for name, pattern in (("project", r"dh-offline-[a-f0-9]{12}"), ("daemon_id", r"[A-Za-z0-9:_.-]{8,128}"),
                          ("marker", r"[a-f0-9]{24}"), ("flag", r"[A-F0-9]{31}="),
                          ("bundle_manifest_sha256", r"[a-f0-9]{64}"), ("template_receipt_sha256", r"[a-f0-9]{64}")):
        if not isinstance(value[name], str) or not re.fullmatch(pattern, value[name]):
            raise Error("invalid offline fixture identifier")
    kit.validate_credentials(value["credentials"])
    if not isinstance(value["bundle"], str) or not Path(value["bundle"]).is_absolute():
        raise Error("offline bundle must be an explicit approved absolute path")
    if not isinstance(value["files"], dict) or len(value["files"]) > 20000:
        raise Error("invalid offline immutable file inventory")
    return value


def prepare(args):
    target = kit.safe_path(args.workspace)
    if target.exists() or not target.parent.is_dir():
        raise Error("offline rehearsal requires a new private workspace")
    source, template, spec, platform = kit.workspace(args.template)
    if platform["platform"] != synthetic_profile()["platform"]:
        raise Error("offline rehearsal currently requires a native Linux amd64 template")
    runtime = kit.check_build_receipt(source, spec)
    images = {name: service["image"] for name, service in runtime["services"].items()}
    manifest = bundle.verify(args.image_bundle)
    image_closure(manifest, images)
    if not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", args.daemon_id or ""):
        raise Error("explicit approved Docker daemon identity required")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "effects": "new synthetic configuration/source mounts only", "daemon_contacted": False, "image_closure": "PASS"}
    if os.name != "posix" or not sys.platform.startswith("linux") or os.getuid() == 0:
        raise Error("offline rehearsal requires a non-root native Linux operator")
    state = {"schema": SCHEMA, "project": "dh-offline-" + secrets.token_hex(6), "daemon_id": args.daemon_id,
        "images": images, "credentials": {name: ("synthetic-" + secrets.token_hex(6) if name == "packmate_user" else secrets.token_hex(24))
            for name in ("farm_password", "database_password", "neo_key", "packmate_user", "packmate_password")},
        "marker": secrets.token_hex(12), "flag": secrets.token_hex(16).upper()[:31] + "=", "bundle": str(kit.safe_path(args.image_bundle)),
        "bundle_manifest_sha256": digest(kit.read(Path(args.image_bundle) / "manifest.json")),
        "template_receipt_sha256": digest(kit.read(source / "build-receipt.json")), "files": {}}
    validate_state(state)
    target.mkdir(mode=0o700)
    total = 0
    for name in sorted(template["files"]):
        if not name.startswith("sources/"):
            continue
        data = kit.read(source / name, MAX_FILES)
        total += len(data)
        if total > MAX_FILES:
            raise Error("source mounts exceed offline fixture byte bound")
        shared.write(target / name, data)
        state["files"][name] = digest(data)
    for name, data in generated_files(state).items():
        shared.write(target / name, data)
        state["files"][name] = digest(data)
        if name in {"probe.py", "probe-config.json", "synthetic.sh", "config/neo-client.yml", "config/neo-denied.yml", "config/packmate.properties", "pcaps/synthetic.pcap"}:
            (target / name).chmod(0o644)
    (target / "pcaps").chmod(0o755)
    for name in ("postgres", "redis", "neo-redis", "neo", "packmate-db"):
        (target / "data" / name).mkdir(parents=True, mode=0o700)
    shared.write(target / "fixture.json", shared.canonical(state))
    return {"status": "PASS", "action": "prepare", "template_data": "never read or copied", "capture_submission_worker": "disabled", "not_validated": NOT_VALIDATED}


def fixture(path):
    root = kit.safe_path(path)
    if os.name == "posix" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise Error("offline fixture must be private and owned by the current operator")
    state = validate_state(kit.load(root / "fixture.json"))
    expected = generated_files(state)
    if not set(expected) <= set(state["files"]):
        raise Error("offline generated configuration inventory is incomplete")
    total = 0
    for name, checksum in state["files"].items():
        parts = PurePosixPath(name)
        if (parts.is_absolute() or ".." in parts.parts or "\\" in name or ":" in name or
                (name not in expected and not name.startswith("sources/")) or any(p in {".git", ".ssh"} for p in parts.parts)):
            raise Error("unsafe offline fixture member")
        candidate = root / name
        if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root and root in p.parents):
            raise Error("linked offline fixture member")
        data = kit.read(candidate, MAX_FILES)
        total += len(data)
        if total > MAX_FILES or digest(data) != checksum or (name in expected and data != expected[name]):
            raise Error("offline immutable source/configuration changed")
    for name in ("data", "data/postgres", "data/redis", "data/neo-redis", "data/neo", "data/packmate-db"):
        if (root / name).is_symlink() or not (root / name).is_dir():
            raise Error("offline data directory changed")
    return root, state


def command(root, state):
    return ["docker", "compose", "--project-name", state["project"], "--project-directory", str(root), "--file", str(root / "compose.json")]


def daemon(state):
    raw = shared.checked(["docker", "info", "--format", "{{.ID}};{{.OSType}};{{.Architecture}};{{.OperatingSystem}}"], capture=True).decode().strip().split(";", 3)
    if len(raw) != 4 or raw[0] != state["daemon_id"] or raw[1] != "linux" or raw[2] not in {"x86_64", "amd64"} or "docker desktop" in raw[3].lower():
        raise Error("approved native Linux amd64 Docker Engine required")


def ownership(state):
    for kind, listing in (("container", ["ps", "--all", "--quiet", "--no-trunc"]), ("network", ["network", "ls", "--quiet", "--no-trunc"])):
        ids = shared.checked(["docker"] + listing + ["--filter", "label=com.docker.compose.project=" + state["project"]], capture=True).decode().split()
        if len(ids) > 16 or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in ids):
            raise Error("invalid owned offline resource listing")
        template = '{{index ' + ('.Config.Labels' if kind == "container" else '.Labels') + ' "' + LABEL + '"}}'
        for identity in ids:
            if shared.checked(["docker", kind, "inspect", "--format", template, identity], capture=True).decode().strip() != state["project"]:
                raise Error("offline resource ownership mismatch")


def cleanup_helpers(state, name=None):
    project = state["project"]
    if name is not None and not re.fullmatch(re.escape(project) + r"-helper-[a-f0-9]{8}", name):
        raise Error("invalid offline helper identity")
    filters = ["--filter", "name=^/" + name + "$"] if name else ["--filter", "label=" + LABEL + "=" + project, "--filter", "label=" + PURPOSE + "=true"]
    ids = shared.checked(["docker", "ps", "--all", "--quiet", "--no-trunc"] + filters, capture=True).decode().split()
    if len(ids) > (1 if name else 32) or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in ids):
        raise Error("invalid offline helper listing")
    template = '{"id":{{json .Id}},"name":{{json .Name}},"owner":{{json (index .Config.Labels "' + LABEL + '")}},"helper":{{json (index .Config.Labels "' + PURPOSE + '")}}}'
    for identity in ids:
        info = json.loads(shared.checked(["docker", "inspect", "--format", template, identity], capture=True))
        if (info.get("id") != identity or info.get("owner") != project or info.get("helper") != "true" or
                not re.fullmatch("/" + re.escape(project) + r"-helper-[a-f0-9]{8}", info.get("name", "")) or
                (name is not None and info["name"] != "/" + name)):
            raise Error("offline helper ownership mismatch")
        shared.checked(["docker", "rm", "--force", identity], timeout=20)


def helper(root, state, action, *, network=None, target=None, neo=False):
    allowed = {"farm-ready", "ready", "seed", "verify", "network", "witness-control", "neo-info", "neo-denied", "neo-add"}
    if action not in allowed:
        raise Error("unsupported fixed offline helper action")
    if action in {"network", "witness-control"}:
        import ipaddress
        if ipaddress.ip_address(target).version != 4:
            raise Error("owned witness requires an inspected IPv4 address")
    name = state["project"] + "-helper-" + secrets.token_hex(4)
    args = ["docker", "create", "--name", name, "--label", LABEL + "=" + state["project"], "--label", PURPOSE + "=true",
            "--network", network or state["project"] + "_offline", "--user", "65534:65534", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=32",
            "--log-driver=none", "--pull=never"]
    if action.startswith("neo-"):
        client = "neo-denied.yml" if action == "neo-denied" else "neo-client.yml"
        args += ["--mount", "type=bind,src=" + str(root / "config" / client) + ",dst=/client.yml,readonly",
                 "--mount", "type=bind,src=" + str(root / "synthetic.sh") + ",dst=/synthetic.sh,readonly",
                 "--entrypoint", "/usr/local/bin/neo", state["images"]["neo-worker"], "--verbose=false", "--config", "/client.yml"]
        args += ["add", "--id", state["project"], "--disabled", "--interval", "1h", "--timeout", "3s", "/synthetic.sh"] if action == "neo-add" else ["info"]
    else:
        args += ["--mount", "type=bind,src=" + str(root / "probe.py") + ",dst=/probe.py,readonly"]
        if action not in {"network", "witness-control"}:
            args += ["--mount", "type=bind,src=" + str(root / "probe-config.json") + ",dst=/probe-config.json,readonly"]
        args += ["--entrypoint", "python", state["images"]["farm"], "-B", "/probe.py", action]
        if target:
            args.append(target)
    try:
        shared.checked(args, timeout=30)
        code, raw = shared.capture_probe(["docker", "start", "--attach", name], timeout=65 if action == "seed" else 15)
        if action == "neo-denied":
            return {"neo_wrong_key_rejected": code != 0 and b"Unauthenticated" in raw}
        if code:
            raise Error("offline helper failed; raw output suppressed")
        if action.startswith("neo-"):
            lines = [line.strip() for line in raw.splitlines() if b"exploit_id:" in line]
            if action == "neo-add":
                return {}
            if not lines:
                return {"neo_authenticated": True, "task": None}
            if len(lines) != 1 or state["project"].encode() not in lines[0] or b"disabled:true" not in lines[0] or b"version:1" not in lines[0]:
                raise Error("Neo contains non-synthetic or enabled task state")
            return {"neo_authenticated": True, "task": digest(lines[0])}
        value = json.loads(raw)
        if not isinstance(value, dict) or "error_type" in value:
            raise Error("invalid sanitized offline helper result")
        return value
    finally:
        cleanup_helpers(state, name)


def wait_helper(root, state, action, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = helper(root, state, action)
            if value and all(v is True for k, v in value.items() if k != "task"):
                return value
        except Error:
            pass
        time.sleep(1)
    raise Error("offline application readiness timed out")


def container_id(root, state, service):
    if service not in APPS + ("witness",):
        raise Error("unlisted offline service")
    value = shared.checked(command(root, state) + ["ps", "--all", "--quiet", service], capture=True).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise Error("offline service must resolve to one exact container ID")
    return value


def isolation(root, state):
    networks = {}
    for role in ("offline", "witness"):
        template = '{"id":{{json .Id}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"driver":{{json .Driver}},"options":{{json .Options}},"owner":{{json (index .Labels "' + LABEL + '")}}}'
        value = json.loads(shared.checked(["docker", "network", "inspect", "--format", template, state["project"] + "_" + role], capture=True))
        if (value.get("internal") is not True or value.get("ipv6") is not False or value.get("driver") != "bridge" or
                value.get("owner") != state["project"] or value.get("options", {}).get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated" or
                not re.fullmatch(r"[a-f0-9]{64}", value.get("id", ""))):
            raise Error("Docker isolated gateway mode unavailable or network configuration changed")
        networks[role] = value["id"]
    endpoints = {}
    for service in APPS + ("witness",):
        identity = container_id(root, state, service)
        template = '{"running":{{json .State.Running}},"ports":{{json .HostConfig.PortBindings}},"networks":{{json .NetworkSettings.Networks}},"privileged":{{json .HostConfig.Privileged}},"owner":{{json (index .Config.Labels "' + LABEL + '")}}}'
        value = json.loads(shared.checked(["docker", "inspect", "--format", template, identity], capture=True))
        role = "witness" if service == "witness" else "offline"
        links = value.get("networks", {})
        if (value.get("running") is not True or value.get("owner") != state["project"] or value.get("privileged") is not False or
                value.get("ports") not in ({}, None) or len(links) != 1 or next(iter(links.values())).get("NetworkID") != networks[role]):
            raise Error("actual offline service network/publication/ownership mismatch")
        endpoints[service] = (identity, next(iter(links.values()))["IPAddress"])
    witness = endpoints["witness"][1]
    positive = helper(root, state, "witness-control", network=state["project"] + "_witness", target=witness)
    if positive != {"owned_witness_reachable": True}:
        raise Error("owned witness positive control failed")
    result = {"isolated_networks_verified": True, "owned_witness_positive_control": True}
    for service in APPS:
        values = helper(root, state, "network", network="container:" + endpoints[service][0], target=witness)
        if values != {"no_default_ipv4": True, "no_default_ipv6": True, "owned_witness_denied": True}:
            raise Error("offline default-route or cross-network denial check failed")
        result[service + "_no_route_and_witness_denied"] = True
    return result


def start(root, state):
    ownership(state)
    shared.checked(command(root, state) + ["up", "--detach", "--no-build", "--pull", "never"] + [name for name in APPS if name != "neo-server"] + ["witness"], timeout=180)
    wait_helper(root, state, "farm-ready", 90)
    shared.checked(command(root, state) + ["up", "--detach", "--no-build", "--pull", "never", "--no-deps", "neo-server"], timeout=60)
    wait_helper(root, state, "neo-info", 60)
    wait_helper(root, state, "ready", 120)


def execute(args):
    root, state = fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": args.action, "daemon_contacted": False, "effects": "image import, new isolated synthetic stack, cold restart and exact-owned cleanup", "not_validated": NOT_VALIDATED}
    if not sys.platform.startswith("linux") or os.getuid() == 0:
        raise Error("offline runtime requires a non-root native Linux operator")
    daemon(state)
    if args.action == "down":
        cleanup_helpers(state)
        ownership(state)
        shared.checked(command(root, state) + ["down", "--timeout", "10"], timeout=90)
        return {"status": "PASS", "action": "down", "data_retained": True}
    if not args.snapshot_confirmed:
        raise Error("cold restart rehearsal requires --snapshot-confirmed")
    if (root / "attempt.json").exists() or any(any((root / "data" / name).iterdir()) for name in ("postgres", "redis", "neo-redis", "neo", "packmate-db")):
        raise Error("offline run requires fresh never-started fixture data")
    manifest = bundle.verify(state["bundle"])
    if digest(kit.read(Path(state["bundle"]) / "manifest.json")) != state["bundle_manifest_sha256"]:
        raise Error("approved offline bundle manifest changed")
    image_closure(manifest, state["images"])
    shared.write(root / "attempt.json", shared.canonical({"approval_id": args.approval_id, "snapshot_confirmed": True}))
    report = {"schema": SCHEMA, "status": "BLOCKED", "phase": "image-import", "checks": {}, "not_validated": NOT_VALIDATED,
              "scope": "network-isolated runtime on preinstalled existing native Linux Engine; not a clean-daemon test",
              "synthetic_queue_policy": "QUEUED only; no Celery, Neo worker, receiver or LIVE capture is started"}
    began = time.monotonic()
    try:
        bundle.import_images(SimpleNamespace(root=state["bundle"], apply=True, daemon_id=state["daemon_id"]))
        for identity in set(state["images"].values()):
            observed = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", identity], capture=True).decode().strip()
            if observed != identity + ";linux;amd64":
                raise Error("imported offline image identity or architecture mismatch")
        report["checks"]["verified_runtime_and_helper_image_closure"] = True
        report["phase"] = "initial-start"
        start(root, state)
        report["checks"].update(isolation(root, state))
        report["checks"].update(helper(root, state, "neo-denied"))
        report["phase"] = "seed-synthetic-data"
        seeded = helper(root, state, "seed")
        report["checks"].update(seeded["checks"])
        helper(root, state, "neo-add")
        neo_before = helper(root, state, "neo-info")["task"]
        if not neo_before:
            raise Error("disabled Neo synthetic task was not persisted")
        for service in ("redis", "neo-redis"):
            shared.checked(command(root, state) + ["exec", "-T", service, "redis-cli", "SET", "durkahelper:offline", state["project"]])
        report["phase"] = "cold-stop"
        ownership(state)
        shared.checked(command(root, state) + ["stop", "--timeout", "15"], timeout=120)
        if shared.checked(command(root, state) + ["ps", "--status", "running", "--quiet"], capture=True).strip():
            raise Error("offline cold stop left a project container running")
        report["checks"]["all_services_cold_stopped"] = True
        cold_started = time.monotonic()
        report["phase"] = "cold-start"
        start(root, state)
        report["checks"].update({"cold_" + key: value for key, value in isolation(root, state).items()})
        restored = helper(root, state, "verify")
        report["checks"].update(restored["checks"])
        report["checks"]["farm_packmate_state_preserved"] = restored["hashes"] == seeded["hashes"]
        report["checks"]["disabled_neo_task_preserved"] = helper(root, state, "neo-info")["task"] == neo_before
        for service in ("redis", "neo-redis"):
            value = shared.checked(command(root, state) + ["exec", "-T", service, "redis-cli", "--raw", "GET", "durkahelper:offline"], capture=True).decode().strip()
            report["checks"][service + "_marker_preserved"] = value == state["project"]
        report["cold_start_seconds"] = round(time.monotonic() - cold_started, 3)
        report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
        report["phase"] = "complete"
    except (Error, bundle.Error, OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report["error_type"] = type(error).__name__
        report["raw_output"] = "suppressed"
    finally:
        report["cleanup"] = {}
        try:
            cleanup_helpers(state)
            report["cleanup"]["helpers"] = True
        except (Error, OSError, ValueError, KeyboardInterrupt):
            report["cleanup"]["helpers"] = False
        try:
            ownership(state)
            shared.checked(command(root, state) + ["down", "--timeout", "10"], timeout=90)
            report["cleanup"]["owned_project"] = True
        except (Error, OSError, ValueError, KeyboardInterrupt):
            report["cleanup"]["owned_project"] = False
        if not all(report["cleanup"].values()):
            report["status"] = "BLOCKED"
        report["total_seconds"] = round(time.monotonic() - began, 3)
        report["retained"] = "private synthetic files/data and imported immutable images; no tag changes"
        shared.write(root / "result.json", shared.canonical(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run", "down"])
    parser.add_argument("--workspace", required=True)
    for name in ("template", "image-bundle", "daemon-id", "approval-id"):
        parser.add_argument("--" + name)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret --approval-id")
        if args.action == "prepare" and not all((args.template, args.image_bundle, args.daemon_id)):
            raise Error("prepare requires --template, --image-bundle and --daemon-id")
        result = prepare(args) if args.action == "prepare" else execute(args)
        print(json.dumps(result, sort_keys=True))
        return {"PASS": 0, "NOT_RUN": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]
    except (Error, bundle.Error, OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
