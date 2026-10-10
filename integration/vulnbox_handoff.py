#!/usr/bin/env python3
"""Portable synthetic PCAP handoff and Docker review smoke; no Docker required.

An optional workflow input carries ONLY an approved, closed synthetic capture.
The transfer test uses a loopback HTTP server, not a connection to a private VM.
Packmate processing and LIVE capture are validated separately on Linux.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_CAPTURE = 32768
MARKER = b"d00dc0ded00dc0ded00dc0de"
INPUT = "synthetic_pcap_base64"
BAD_COMPOSE = "services:\n  web:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
GOOD_COMPOSE = "services:\n  web:\n    privileged: false\n    read_only: true\n    cap_drop: [ALL]\n"


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def capture_from_event(path):
    """No expressions, URLs, target commands or arbitrary output paths accepted."""
    if path is None:
        return None
    capture = module("handoff_file", "deployment/packmate_file.py")
    raw = capture.kit.read(Path(path))
    if len(raw) > 131072:
        raise ValueError("workflow event exceeds bound")
    event = json.loads(raw)
    if not isinstance(event, dict):
        raise ValueError("workflow event must be an object")
    inputs = event.get("inputs", {})
    if not isinstance(inputs, dict):
        raise ValueError("invalid workflow inputs")
    encoded = inputs.get(INPUT, "")
    if encoded in ("", None):
        return None
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_CAPTURE + 2) // 3):
        raise ValueError("synthetic capture exceeds bound")
    data = base64.b64decode(encoded, validate=True)
    if not 24 <= len(data) <= MAX_CAPTURE or MARKER not in data:
        raise ValueError("only bounded marked synthetic captures are accepted")
    return data


def transfer(data):
    """Exercise portable closed-file retrieval with exact bytes and a timeout."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path != "/synthetic.pcap":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:" + str(server.server_port) + "/synthetic.pcap", timeout=5) as response:
            result = response.read(MAX_CAPTURE + 1)
            if response.status != 200 or result != data:
                raise ValueError("closed-capture transfer mismatch")
        return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def command(arguments, expected):
    result = subprocess.run([sys.executable, "-I", "-S", *arguments], cwd=ROOT,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=20, check=False)
    if result.returncode != expected or len(result.stdout) > 1048576:
        raise ValueError("tool smoke failed; raw output suppressed")
    return json.loads(result.stdout)


def run(data=None):
    supplied = data is not None
    if data is None:
        fixture = module("handoff_synthetic", "integration/synthetic_pcap.py")
        data = fixture.make_pcap(MARKER.decode("ascii"))
    if not isinstance(data, bytes) or not 24 <= len(data) <= MAX_CAPTURE or MARKER not in data:
        raise ValueError("only a bounded marked synthetic capture is accepted")
    capture = module("handoff_closed_capture", "deployment/packmate_file.py")
    with tempfile.TemporaryDirectory(prefix="durka-vulnbox-") as directory:
        root = Path(directory).resolve()
        incoming = root / "received.pcap"
        incoming.write_bytes(transfer(data))
        incoming.chmod(0o600)
        try:
            _, _, summary = capture.inspect_file(incoming)
        except capture.Error as error:
            raise ValueError("invalid closed synthetic capture") from error
        if summary["packet_records"] < 2 or summary["sha256"] != hashlib.sha256(data).hexdigest():
            raise ValueError("capture validation mismatch")
        truncated = root / "truncated.pcap"
        truncated.write_bytes(data[:-1])
        try:
            capture.inspect_file(truncated)
        except capture.Error:
            pass
        else:
            raise ValueError("truncated capture accepted")
        sources = root / "service sources"
        sources.mkdir()
        compose = sources / "compose.yml"
        dockerfile = sources / "Dockerfile"
        compose.write_text(BAD_COMPOSE, encoding="utf-8")
        dockerfile.write_text("FROM example.invalid/synthetic\nUSER root\n", encoding="utf-8")
        before = command([str(ROOT / "scripts/defense_scan.py"), str(sources), "--json"], 1)
        expected = {"CFG-DOCKER-PRIV", "CFG-DOCKER-SOCKET", "CFG-DOCKER-ROOT"}
        if not expected <= {hit["rule"] for hit in before["findings"]}:
            raise ValueError("Docker misconfiguration signals missing")
        before_path = root / "before.json"
        before_path.write_text(json.dumps(before), encoding="utf-8")
        # Fixture-only simulated MANUAL edits; the scanner never patches sources.
        compose.write_text(GOOD_COMPOSE, encoding="utf-8")
        dockerfile.write_text("FROM example.invalid/synthetic\nUSER 65534\n", encoding="utf-8")
        after = command([str(ROOT / "scripts/defense_scan.py"), str(sources), "--json"], 0)
        after_path = root / "after.json"
        after_path.write_text(json.dumps(after), encoding="utf-8")
        diff = command([str(ROOT / "scripts/defense_diff.py"), str(before_path), str(after_path), "--json"], 0)
        if diff["exit_code"] != 0 or after["partial"]:
            raise ValueError("manual patch comparison failed")
    return {"status": "PASS", "capture_origin": "approved-synthetic-input" if supplied else "runner-generated-synthetic",
            "packet_records": summary["packet_records"], "capture_bytes": len(data),
            "checks": ["loopback_closed_file_transfer", "closed_pcap_framing", "truncated_capture_rejected",
                       "docker_misconfiguration_scan", "manual_fixture_patch_comparison"],
            "not_tested": ["remote_VM_connectivity", "Docker_Desktop", "Packmate_import", "LIVE_capture", "team_LAN"],
            "raw_capture_output": "suppressed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, help="GitHub workflow event with optional synthetic PCAP input")
    args = parser.parse_args(argv)
    try:
        result = run(capture_from_event(args.event))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__, "raw_output": "suppressed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
