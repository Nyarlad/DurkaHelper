#!/usr/bin/env python3
"""Opt-in host-interface capture of ONLY a fresh internal synthetic Docker bridge."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import secrets
import socket
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


synthetic = module("host_synthetic", ROOT / "integration/packmate_live_smoke.py")
host = module("host_capture", ROOT / "deployment/packmate_host.py")
shared, Error = host.shared, host.Error
# Separate file imports have distinct exception classes; both must stay inside
# the redacted report and scoped-cleanup path.
EXPECTED_ERRORS = (Error, synthetic.Error, OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt)


def free_port(excluded):
    for _ in range(20):
        with socket.socket() as endpoint:
            endpoint.bind(("127.0.0.1", 0))
            value = endpoint.getsockname()[1]
        if value not in excluded:
            return value
    raise Error("no distinct loopback test port")


def run(args):
    root, state = synthetic.fixture(args.workspace)
    if not args.apply:
        return {"status": "NOT_RUN", "scope": "new internal test bridge only; explicit host-network capture approval required"}
    if not sys.platform.startswith("linux") or not args.capture_approved:
        raise Error("host synthetic capture requires native Linux and capture approval")
    if (root / "deployment").exists() or (root / "result.json").exists():
        raise Error("new fixture required")
    host.live.daemon({"daemon_id": state["daemon_id"]})
    observed = shared.checked(["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}", state["python_image"]], capture=True).decode().strip().split(";")
    if len(observed) != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", observed[0]) or observed[1:] != ["linux", "amd64"]:
        raise Error("cached pinned Python image required")
    image = observed[0]
    attempted_network, attempted_containers, prepared = None, [], False
    checks, cleanup, metrics, failure, phase = {}, {}, {}, None, "create-owned-bridge"
    try:
        attempted_network = state["project"]
        network = synthetic.identifier(["docker", "network", "create", "--driver", "bridge", "--internal", "--label", synthetic.live.CAPTURE_LABEL + "=" + state["project"], attempted_network])
        attempted_containers.append(state["project"] + "-source")
        owner = synthetic.identifier(synthetic.private_command(root, state, image, attempted_containers[-1], network, "server.py"))
        shared.checked(["docker", "start", owner], timeout=30)
        metadata = json.loads(shared.checked(["docker", "network", "inspect", "--format", '{"internal":{{json .Internal}},"containers":{{json .Containers}}}', network], capture=True))
        if metadata.get("internal") is not True or set(metadata.get("containers", {})) != {owner}:
            raise Error("test bridge must be internal and contain only the exact synthetic server")
        service_ip = metadata["containers"][owner]["IPv4Address"].split("/", 1)[0]
        iface = "br-" + network[:12]
        link = json.loads(shared.checked(["ip", "-json", "link", "show", "dev", iface], capture=True))[0]
        ui = free_port(set())
        config = host.profile({"schema": host.SCHEMA, "daemon_id": state["daemon_id"], "interface": iface,
            "ifindex": link["ifindex"], "interface_mac": link["address"], "local_ip": service_ip,
            "bind_address": "127.0.0.1", "ui_port": ui, "db_port": free_port({ui}),
            "tcp_timeout_seconds": 4, "udp_timeout_seconds": 3, "timeout_check_seconds": 1,
            "retention_minutes": 60, "cleanup_interval_minutes": 1})
        secret = {"username": "synthetic-" + secrets.token_hex(6), "password": secrets.token_hex(24), "db_password": secrets.token_hex(24)}
        shared.write(root / "profile.json", shared.canonical(config))
        shared.write(root / "credentials.json", shared.canonical(secret))
        params = SimpleNamespace(workspace=root / "deployment", profile=root / "profile.json", credentials=root / "credentials.json",
            apply=True, approval_id=args.approval_id, action="up", host_network_approved=True, interface_scope_approved=True,
            capture_approval=iface + ":" + str(link["ifindex"]) + ":" + link["address"],
            bootstrap_images=getattr(args, "bootstrap_images", None),
            expected_images_sha256=getattr(args, "expected_images_sha256", None))
        host.prepare(params)
        prepared = True
        phase = "start-host-capture"
        started_capture = host.execute(params)
        if params.bootstrap_images is not None:
            checks["fresh_offline_image_bootstrap"] = started_capture["images_sha256"] == params.expected_images_sha256
            if not checks["fresh_offline_image_bootstrap"]:
                raise Error("bootstrap result does not match the independently approved image receipt")
            # A successful first launch creates the local receipt. Restarts
            # bind that receipt to the same detached hash, never bootstrap it.
            params.bootstrap_images = None
        checks["internal_synthetic_interface_only"] = True
        checks["capture_started"] = host.live.request(config, secret, "/api/pcap/started") is True
        for index, suffix in enumerate(("first", "restarted")):
            phase = "traffic-" + suffix
            marker = state["marker"] + "-" + suffix
            patterns = synthetic.configure(config, secret, marker, index == 0)
            started = time.monotonic()
            attempted_containers.append(state["project"] + "-" + suffix)
            child = synthetic.identifier(synthetic.private_command(root, state, image, attempted_containers[-1], network, "client.py") + [service_ip, marker])
            shared.checked(["docker", "start", child], timeout=30)
            found = {}
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                found = synthetic.collect(config, secret, patterns, marker)
                if all(found.values()):
                    break
                time.sleep(1)
            checks.update({suffix + "_" + key: value for key, value in found.items()})
            metrics[suffix + "_visible_seconds"] = round(time.monotonic() - started, 3)
            if index == 0:
                _, deployment = host.workspace(params.workspace)
                host.owned(params.workspace, deployment)
                shared.checked(host.command(params.workspace, deployment, True) + ["stop", "--timeout", "10", "packmate"], timeout=30)
                host.execute(params)
                checks["restart_preserved_streams"] = all(synthetic.collect(config, secret, patterns, marker).values())
        phase = "complete"
    except EXPECTED_ERRORS as error:
        failure = type(error).__name__
    finally:
        if prepared:
            try:
                host.execute(SimpleNamespace(workspace=root / "deployment", action="down", apply=True))
                cleanup["deployment"] = True
            except EXPECTED_ERRORS:
                cleanup["deployment"] = False
        for name in reversed(attempted_containers):
            try:
                synthetic.reconcile_resource("container", name, state["project"])
                cleanup[name.rsplit("-", 1)[-1]] = True
            except EXPECTED_ERRORS:
                cleanup[name.rsplit("-", 1)[-1]] = False
        if attempted_network:
            try:
                synthetic.reconcile_resource("network", attempted_network, state["project"])
                cleanup["network"] = True
            except EXPECTED_ERRORS:
                cleanup["network"] = False
    result = {"schema": "durkahelper.packmate-host-smoke.v1", "status": "BLOCKED" if failure else "PASS" if checks and all(checks.values()) and all(cleanup.values()) else "FAIL",
              "phase": phase, "error_type": failure, "checks": checks, "metrics": metrics, "cleanup": cleanup,
              "scope": "native Linux host network with capture only on fresh internal synthetic bridge",
              "not_validated": ["real Vulnbox", "physical mirror port", "Mac", "team LAN", "long-running loss or hard disk quota"],
              "raw_output": "suppressed", "private_data_retained": True}
    shared.write(root / "result.json", shared.canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--daemon-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--bootstrap-images")
    parser.add_argument("--expected-images-sha256")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--capture-approved", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.apply and not (args.approval_id and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id)):
            raise Error("apply requires a non-secret approval ID")
        result = synthetic.prepare(args) if args.action == "prepare" else run(args)
        print(json.dumps(result, sort_keys=True))
        return {"PASS": 0, "NOT_RUN": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]
    except EXPECTED_ERRORS as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__, "raw_output": "suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
