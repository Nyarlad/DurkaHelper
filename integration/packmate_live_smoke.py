#!/usr/bin/env python3
"""Opt-in, fresh synthetic TCP/UDP LIVE capture in a dedicated Linux namespace.

No host capture, source patches, package installation or network reconfiguration.
The generated bridge permits egress but the supplied applications send only to
their explicitly supplied synthetic peer. All stages default to preview.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("live_deployment", ROOT / "deployment/packmate_live.py")
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)
shared, Error = live.shared, live.Error
SCHEMA = "durkahelper.packmate-live-smoke.v1"
LABEL = "io.durkahelper.live-smoke"
PORTS = {"tcp": 18080, "udp": 18081, "unfinished": 18082}
FRAMING = b'''def read_line(conn, limit=1024):
    result=bytearray(); deadline=time.monotonic()+5
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError("synthetic frame timeout")
        conn.settimeout(remaining)
        part=conn.recv(limit+1-len(result))
        if not part: raise ValueError("synthetic frame truncated")
        result.extend(part)
        if len(result)>limit: raise ValueError("synthetic frame too large")
        if b"\\n" in result:
            if result.index(10)!=len(result)-1: raise ValueError("multiple synthetic frames")
            return bytes(result)
'''
SERVER = b'''import socket, threading, time
''' + FRAMING + b'''
def tcp(port, hold):
    listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind(("0.0.0.0",port)); listener.listen(4)
    def answer(conn):
        with conn:
            data=read_line(conn)
            if data.startswith(b"request:"): conn.sendall(b"response:"+data)
            if hold: time.sleep(90)
    while True:
        conn,_=listener.accept(); threading.Thread(target=answer,args=(conn,),daemon=True).start()
def udp():
    endpoint=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); endpoint.bind(("0.0.0.0",18081))
    while True:
        data,addr=endpoint.recvfrom(1024)
        if data.startswith(b"request:"): endpoint.sendto(b"response:"+data,addr)
threading.Thread(target=tcp,args=(18080,False),daemon=True).start()
threading.Thread(target=tcp,args=(18082,True),daemon=True).start()
udp()
'''
CLIENT = b'''import socket, sys, time
''' + FRAMING + b'''
host,marker=sys.argv[1:]
def payload(mode): return ("request:"+marker+":"+mode+"\\n").encode("ascii")
deadline=time.monotonic()+15
while True:
    try:
        tcp=socket.create_connection((host,18080),timeout=2); break
    except OSError:
        if time.monotonic()>deadline: raise
        time.sleep(.2)
with tcp:
    data=payload("tcp"); tcp.sendall(data); assert read_line(tcp)==b"response:"+data
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.settimeout(4)
data=payload("udp"); udp.sendto(data,(host,18081)); assert udp.recvfrom(1024)[0]==b"response:"+data
hold=socket.create_connection((host,18082),timeout=4)
data=payload("unfinished"); hold.sendall(data); assert read_line(hold)==b"response:"+data
time.sleep(90)
'''


def validate_state(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "project", "marker", "daemon_id", "python_image"} or
            value["schema"] != SCHEMA or not re.fullmatch(r"dh-live-test-[a-f0-9]{12}", value.get("project", "")) or
            not re.fullmatch(r"[a-f0-9]{24}", value.get("marker", "")) or
            not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", value.get("daemon_id", "")) or
            value["python_image"] != shared.read_json(ROOT / "config/integration-images.lock.json")["python"]):
        raise Error("invalid LIVE synthetic fixture identity")
    return value


def fixture(path):
    root = live.kit.safe_path(path)
    state = validate_state(live.kit.load(root / "fixture.json"))
    if os.name == "posix" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise Error("LIVE fixture requires an owner-only workspace")
    for name, content in (("server.py", SERVER), ("client.py", CLIENT)):
        if live.kit.read(root / name) != content:
            raise Error("synthetic LIVE fixture program changed")
    return root, state


def prepare(args):
    root = live.kit.safe_path(args.workspace)
    if root.exists() or not root.parent.is_dir():
        raise Error("LIVE fixture requires a new workspace")
    state = validate_state({"schema": SCHEMA, "project": "dh-live-test-" + secrets.token_hex(6),
                            "marker": secrets.token_hex(12), "daemon_id": args.daemon_id,
                            "python_image": shared.read_json(ROOT / "config/integration-images.lock.json")["python"]})
    if not args.apply:
        return {"status": "NOT_RUN", "action": "prepare", "effects": "private synthetic programs and state only", "daemon_contacted": False}
    if os.name != "posix":
        raise Error("LIVE fixture preparation requires POSIX permissions")
    root.mkdir(mode=0o700)
    shared.write(root / "fixture.json", shared.canonical(state))
    shared.write(root / "server.py", SERVER)
    shared.write(root / "client.py", CLIENT)
    (root / "server.py").chmod(0o644)
    (root / "client.py").chmod(0o644)
    return {"status": "PASS", "action": "prepare", "capture_started": False}


def identifier(arguments):
    raw = shared.checked(arguments, capture=True).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", raw):
        raise Error("Docker did not return an exact generated resource ID")
    return raw


def private_command(root, state, image, name, network, program, extra=()):
    return ["docker", "create", "--name", name, "--label", LABEL + "=" + state["project"],
            "--label", live.CAPTURE_LABEL + "=" + state["project"], "--network", network,
            "--user", "65534:65534", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=32", "--log-driver=none", "--pull=never",
            "--mount", "type=bind,src=" + str(root / program) + ",dst=/program.py,readonly"] + list(extra) + [image, "python", "-B", "/program.py"]


def cleanup_container(identity, project):
    actual = shared.checked(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', identity], capture=True).decode().strip()
    if actual != project:
        raise Error("synthetic container ownership mismatch; cleanup refused")
    shared.checked(["docker", "rm", "--force", identity], timeout=30)


def cleanup_network(identity, project):
    actual = shared.checked(["docker", "network", "inspect", "--format", '{{index .Labels "' + live.CAPTURE_LABEL + '"}}', identity], capture=True).decode().strip()
    if actual != project:
        raise Error("synthetic network ownership mismatch; cleanup refused")
    shared.checked(["docker", "network", "rm", identity], timeout=30)


def reconcile_resource(kind, name, project):
    """Resolve pre-registered names after successful OR uncertain create.

    A matching name alone never authorizes removal. Inspect the exact returned
    ID, name and private label; then pass the immutable ID to the cleanup path.
    """
    if kind not in {"container", "network"} or not re.fullmatch(r"dh-live-test-[a-f0-9]{12}", project):
        raise Error("invalid synthetic cleanup scope")
    allowed = {project} if kind == "network" else {project + suffix for suffix in ("-source", "-first", "-restarted")}
    if name not in allowed:
        raise Error("unregistered synthetic resource name")
    listing = ["docker", "ps", "--all", "--quiet", "--no-trunc"] if kind == "container" else ["docker", "network", "ls", "--quiet", "--no-trunc"]
    listing += ["--filter", "name=^" + ("/" if kind == "container" else "") + name + "$"]
    identities = shared.checked(listing, capture=True).decode().split()
    if len(identities) > 1 or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in identities):
        raise Error("unexpected synthetic cleanup listing")
    for identity in identities:
        labels = ".Config.Labels" if kind == "container" else ".Labels"
        label = LABEL if kind == "container" else live.CAPTURE_LABEL
        template = '{"id":{{json .Id}},"name":{{json .Name}},"owner":{{json (index ' + labels + ' "' + label + '")}}}'
        metadata = json.loads(shared.checked(["docker", kind, "inspect", "--format", template, identity], capture=True))
        if metadata != {"id": identity, "name": ("/" if kind == "container" else "") + name, "owner": project}:
            raise Error("synthetic resource name or ownership mismatch; cleanup refused")
        (cleanup_container if kind == "container" else cleanup_network)(identity, project)


def collect(config, secret, patterns, marker):
    checks = {}
    for kind, port in PORTS.items():
        found = live.request(config, secret, "/api/stream/" + str(port), "POST",
                             {"startingFrom": None, "pageSize": 20, "favorites": False, "pattern": None})
        # Whole-marker SUBSTRING matches can be packet-local upstream. Do not
        # hide a correctly captured TCP stream when its marker crosses packets.
        if not isinstance(found, list) or len(found) > 4:
            raise Error("synthetic LIVE stream collection exceeded its bound")
        checks[kind + "_one_stream"] = False
        checks[kind + "_request_incoming"] = False
        checks[kind + "_response_outgoing"] = False
        checks[kind + "_protocol"] = False
        matched = []
        request = ("request:" + marker + ":" + kind + "\n").encode("ascii")
        for stream in found:
            identity = stream.get("id")
            if type(identity) is not int or identity <= 0:
                raise Error("invalid synthetic LIVE stream ID")
            packets = live.request(config, secret, "/api/packet/" + str(identity), "POST", {"startingFrom": None, "pageSize": 256})
            if not isinstance(packets, list) or len(packets) > 256:
                raise Error("invalid synthetic LIVE packet collection")
            directions, counts, previous = {True: bytearray(), False: bytearray()}, {True: 0, False: 0}, 0
            for packet in packets:
                packet_id, incoming = packet.get("id"), packet.get("incoming")
                if type(packet_id) is not int or packet_id <= previous or type(incoming) is not bool:
                    raise Error("synthetic packets must have strictly ordered IDs and explicit direction")
                previous = packet_id
                raw = base64.b64decode(packet.get("content", ""), validate=True)
                directions[incoming].extend(raw)
                if raw:
                    counts[incoming] += 1
                if len(directions[incoming]) > 2048:
                    raise Error("synthetic packet payload exceeded its bound")
            # UDP keeps datagram boundaries; only TCP permits segmentation.
            incoming = directions[True] == request and (kind != "udp" or counts[True] == 1)
            outgoing = directions[False] == b"response:" + request and (kind != "udp" or counts[False] == 1)
            if incoming or outgoing:
                matched.append((incoming, outgoing, stream.get("protocol") == ("UDP" if kind == "udp" else "TCP")))
        checks[kind + "_one_stream"] = len(matched) == 1
        if len(matched) == 1:
            checks[kind + "_request_incoming"], checks[kind + "_response_outgoing"], checks[kind + "_protocol"] = matched[0]
    return checks


def configure(config, secret, marker, first):
    result = {}
    for kind, port in PORTS.items():
        if first:
            created = live.request(config, secret, "/api/service/", "POST", {"port": port, "name": "Synthetic LIVE " + kind,
                "decryptTls": False, "http": False, "urldecodeHttpRequests": False, "mergeAdjacentPackets": False, "parseWebSockets": False})
            if not isinstance(created, dict) or created.get("port") != port:
                raise Error("synthetic LIVE service creation failed")
        pattern = live.request(config, secret, "/api/pattern/", "POST", {"name": "Synthetic LIVE marker " + kind,
            "value": marker, "color": "#123456", "searchType": "SUBSTRING", "directionType": "BOTH", "actionType": "FIND", "serviceId": port})
        identity = pattern.get("id") if isinstance(pattern, dict) else None
        if type(identity) is not int or identity < 1 or pattern.get("enabled") is not True:
            raise Error("synthetic LIVE pattern creation failed")
        result[kind] = identity
    return result


def run(args):
    root, state = fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "run", "effects": "fresh isolated TCP/UDP source, clients and LIVE Packmate; exact-owned cleanup",
                "requires": "--apply --approval-id --capture-approved", "real_traffic": "NOT_RUN"}
    if not sys.platform.startswith("linux") or not args.capture_approved:
        raise Error("synthetic LIVE run requires Linux and --capture-approved")
    if (root / "deployment").exists() or (root / "result.json").exists():
        raise Error("LIVE smoke requires a fresh fixture; previous data cannot produce a PASS")
    live.daemon({"daemon_id": state["daemon_id"]})
    raw = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", state["python_image"]], capture=True).decode().strip().split(";")
    if len(raw) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", raw[0]) or raw[1:] != ["linux", "amd64"]:
        raise Error("synthetic LIVE requires the cached pinned native Linux amd64 Python image")
    image = raw[0]
    network, owner, children, prepared = None, None, [], False
    attempted_network, attempted_containers = None, []
    checks, metrics, cleanup = {}, {}, {}
    phase, failure = "prepare-resources", None
    try:
        attempted_network = state["project"]
        network = identifier(["docker", "network", "create", "--driver", "bridge", "--label", live.CAPTURE_LABEL + "=" + state["project"], attempted_network])
        attempted_containers.append(("source", state["project"] + "-source"))
        owner = identifier(private_command(root, state, image, attempted_containers[-1][1], network, "server.py", ["--publish", "127.0.0.1::65000/tcp"]))
        shared.checked(["docker", "start", owner], timeout=30)
        local_ip = shared.checked(["docker", "inspect", "--format", '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', owner], capture=True).decode().strip()
        published = shared.checked(["docker", "port", owner, "65000/tcp"], capture=True).decode().strip()
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", published)
        if not match:
            raise Error("synthetic LIVE owner did not publish exactly a loopback UI port")
        config = live.profile({"schema": live.SCHEMA, "daemon_id": state["daemon_id"], "capture_container": owner,
            "network_id": network, "capture_scope": state["project"], "interface": "eth0", "local_ip": local_ip,
            "bind_address": "127.0.0.1", "ui_port": int(match[1]), "tcp_timeout_seconds": 4, "udp_timeout_seconds": 3,
            "timeout_check_seconds": 1, "retention_minutes": 60, "cleanup_interval_minutes": 1})
        secret = {"username": "synthetic-" + secrets.token_hex(6), "password": secrets.token_hex(24), "db_password": secrets.token_hex(24)}
        shared.write(root / "profile.json", shared.canonical(config))
        shared.write(root / "credentials.json", shared.canonical(secret))
        params = SimpleNamespace(workspace=root / "deployment", profile=root / "profile.json", credentials=root / "credentials.json",
                                 apply=True, approval_id=args.approval_id, capture_approval=owner, action="up")
        live.prepare(params)
        prepared = True
        phase = "live-start"
        live.execute(params)
        checks["live_started_automatically"] = live.request(config, secret, "/api/pcap/started") is True
        if live.request(config, secret, "/api/service/") != []:
            raise Error("synthetic LIVE smoke requires empty initial service state")
        for index, suffix in enumerate(("first", "restarted")):
            phase = "traffic-" + suffix
            marker = state["marker"] + "-" + suffix
            patterns = configure(config, secret, marker, index == 0)
            started = time.monotonic()
            attempted_containers.append(("client_" + str(index), state["project"] + "-" + suffix))
            child = identifier(private_command(root, state, image, attempted_containers[-1][1], network, "client.py") + [local_ip, marker])
            children.append(child)
            shared.checked(["docker", "start", child], timeout=30)
            observed = {}
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                observed = collect(config, secret, patterns, marker)
                if all(observed.values()):
                    break
                time.sleep(1)
            checks.update({suffix + "_" + key: value for key, value in observed.items()})
            metrics[suffix + "_all_streams_visible_seconds"] = round(time.monotonic() - started, 3)
            checks[suffix + "_timeout_saved_while_connection_open"] = shared.checked(["docker", "inspect", "--format", "{{.State.Running}}", child], capture=True).strip() == b"true" and all(observed.values())
            if index == 0:
                first_patterns, first_marker = patterns, marker
                phase = "restart-capture"
                _, deployment = live.workspace(root / "deployment")
                live.owned(deployment)
                shared.checked(live.command(root / "deployment", deployment, True) + ["stop", "--timeout", "10", "packmate"], timeout=30)
                live.execute(params)
                checks["restart_preserved_streams"] = all(collect(config, secret, first_patterns, first_marker).values())
        phase = "complete"
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt) as error:
        failure = type(error).__name__
    finally:
        if prepared:
            try:
                live.execute(SimpleNamespace(workspace=root / "deployment", action="down", apply=True, capture_approval=None))
                cleanup["deployment"] = True
            except (Error, OSError, ValueError, KeyboardInterrupt):
                cleanup["deployment"] = False
        for key, name in reversed(attempted_containers):
            try:
                reconcile_resource("container", name, state["project"])
                cleanup[key] = True
            except (Error, OSError, ValueError, KeyboardInterrupt):
                cleanup[key] = False
        if attempted_network:
            try:
                reconcile_resource("network", attempted_network, state["project"])
                cleanup["network"] = True
            except (Error, OSError, ValueError, KeyboardInterrupt):
                cleanup["network"] = False
    result = {"schema": SCHEMA, "status": "BLOCKED" if failure else "PASS" if checks and all(checks.values()) and all(cleanup.values()) else "FAIL",
              "phase": phase, "error_type": failure, "checks": checks, "metrics": metrics, "cleanup": cleanup,
              "mode": "LIVE", "network_scope": "generated bridge and synthetic container namespace only; no host capture",
              "retention": "age cleanup configured; hard disk bound and long-running cleanup NOT_RUN", "not_validated": live.NOT_VALIDATED,
              "raw_output": "suppressed", "private_artifacts_retained": True}
    shared.write(root / "result.json", shared.canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--daemon-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--capture-approved", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("mutations require --apply and a non-secret --approval-id")
        result = prepare(args) if args.action == "prepare" else run(args)
        print(json.dumps(result, sort_keys=True))
        return {"PASS": 0, "NOT_RUN": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]
    except (Error, OSError, ValueError, TypeError, KeyError, AttributeError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
