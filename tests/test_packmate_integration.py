"""No-Docker/no-capture contract tests for the opt-in Packmate FILE fixture."""
import argparse
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("packmate_fixture_test", ROOT / "integration/packmate_smoke.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
pcap = fixture.pcap
POSTGRES = "postgres:15.2@sha256:" + "a" * 64


@contextlib.contextmanager
def temporary_directory():
    with tempfile.TemporaryDirectory() as path:
        # macOS /var is a legitimate ancestor link; the integration fixture
        # intentionally accepts only canonical workspace paths.
        yield str(Path(path).resolve())


def state():
    return {"schema": fixture.SCHEMA, "project": "dh-packmate-" + "1" * 12,
            "source_contract_commit": fixture.SOURCE_PIN, "app_image": fixture.APP_IMAGE,
            "postgres_image": POSTGRES, "username": "fixture-" + "2" * 12,
            "password": "3" * 48, "db_password": "4" * 48, "marker": "5" * 24,
            "approval_id": "synthetic-test"}


class SyntheticPcapTests(unittest.TestCase):
    def test_complete_deterministic_tcp_capture_checksums_and_payloads(self):
        marker = "a" * 24
        data = pcap.make_pcap(marker)
        self.assertEqual(data, pcap.make_pcap(marker))
        self.assertNotEqual(data, pcap.make_pcap("b" * 24))
        self.assertLess(len(data), 4096)
        self.assertEqual(struct.unpack("<IHHIIII", data[:24]), (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        offset, packets, payloads = 24, [], []
        while offset < len(data):
            timestamp, micros, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
            self.assertEqual(captured, original)
            packet = data[offset + 16:offset + 16 + captured]
            self.assertEqual(len(packet), captured)
            self.assertEqual(timestamp, pcap.EPOCH)
            self.assertLess(micros, 1000000)
            self.assertEqual(packet[12:14], b"\x08\x00")
            ip, tcp = packet[14:34], packet[34:]
            self.assertEqual(ip[0], 0x45)
            self.assertEqual(struct.unpack("!H", ip[2:4])[0], len(ip) + len(tcp))
            self.assertEqual(self.internet_sum(ip), 0xFFFF)
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
            self.assertEqual(self.internet_sum(pseudo + tcp), 0xFFFF)
            packets.append(tcp[13])
            if tcp[20:]:
                payloads.append(tcp[20:])
            offset += 16 + captured
        self.assertEqual(offset, len(data))
        self.assertEqual(packets, [2, 18, 16, 24, 24, 17, 16, 17, 16])
        self.assertEqual(payloads, list(pcap.payloads(marker)))

    @staticmethod
    def internet_sum(data):
        data += b"\0" if len(data) % 2 else b""
        total = sum(int.from_bytes(data[n:n + 2], "big") for n in range(0, len(data), 2))
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return total

    def test_marker_is_bounded_and_not_arbitrary_payload(self):
        for marker in (None, "", "a" * 23, "a" * 25, "../../outside", "A" * 24, "a\n" * 12):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                pcap.make_pcap(marker)


class PackmateIsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_regular_file_replaced_by_fifo_before_open_is_rejected_without_blocking(self):
        with temporary_directory() as temp:
            target = Path(temp) / "regular.json"
            target.write_bytes(b"{}")
            real_open = os.open

            def replace_with_fifo(path, flags, *args, **kwargs):
                if Path(path) == target:
                    self.assertTrue(flags & os.O_NONBLOCK,
                                    "a FIFO race would block before fstat without O_NONBLOCK")
                    target.unlink()
                    os.mkfifo(target)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(fixture.os, "open", side_effect=replace_with_fifo):
                with self.assertRaisesRegex(fixture.FixtureError, "changed during open"):
                    fixture.bounded_bytes(target)

    def test_fixed_images_file_only_nonprivileged_loopback_and_limits(self):
        spec = fixture.compose_spec(state())
        self.assertEqual(spec["networks"], {"backend": {"internal": True}, "edge": {"internal": False}})
        self.assertEqual(set(spec["services"]), {"db", "packmate"})
        app, db = spec["services"]["packmate"], spec["services"]["db"]
        self.assertEqual(app["image"], fixture.APP_IMAGE)
        self.assertEqual(db["image"], POSTGRES)
        self.assertEqual(db["networks"], ["backend"])
        self.assertEqual(app["networks"], ["backend", "edge"])
        self.assertEqual(app["cap_drop"], ["ALL"])
        self.assertTrue(app["read_only"])
        self.assertEqual(app["user"], "65534:65534")
        self.assertEqual(app["ports"], [{"target": 65000, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}])
        self.assertNotIn("ports", db)
        self.assertIn("--packmate.capture-mode=FILE", app["command"])
        self.assertIn("--spring.datasource.url=jdbc:postgresql://db:5432/packmate", app["command"])
        for service in spec["services"].values():
            self.assertEqual(service["logging"], {"driver": "none"})
            self.assertEqual(service["cpus"], 1.0)
            self.assertEqual(service["pids_limit"], 128)
            self.assertIn("mem_limit", service)
            self.assertNotIn("network_mode", service)
            self.assertNotIn("privileged", service)
            self.assertNotIn("build", service)
            self.assertNotIn("cap_add", service)
        serialized = json.dumps(spec)
        self.assertNotIn("docker.sock", serialized)
        self.assertNotIn("latest", serialized)
        self.assertNotIn(state()["password"], serialized)

    def test_state_rejects_floating_changed_pins_and_extra_fields(self):
        for key, value in (("postgres_image", "postgres:15.2"), ("app_image", "packmate:latest"),
                           ("source_contract_commit", "0" * 40), ("project", "other-workload"),
                           ("marker", "../outside"), ("password", "${HOST_SECRET}"),
                           ("username", "user\nkey=value"), ("extra", True)):
            changed = state()
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(fixture.FixtureError):
                fixture.validate_state(changed)

    def test_jna_exec_tmpfs_is_small_app_owned_and_general_tmp_is_noexec(self):
        app = fixture.compose_spec(state())["services"]["packmate"]
        self.assertIn("-Djna.tmpdir=/jna", app["command"])
        self.assertEqual(app["tmpfs"], ["/tmp:size=67108864,mode=1777,noexec",
            "/jna:size=16777216,mode=0700,uid=65534,gid=65534,nosuid,nodev,exec"])
        self.assertEqual(app["user"], "65534:65534")
        self.assertEqual(app["cap_drop"], ["ALL"])
        self.assertEqual(app["security_opt"], ["no-new-privileges:true"])

    def test_pre_jna_edge_fixture_only_allows_cleanup(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            (root / "compose.json").write_bytes(fixture.shared.canonical(
                fixture.compose_spec(generated, legacy_no_jna=True)))
            self.assertEqual(fixture.fixture(root, check_payload=False)[1], generated)
            with self.assertRaises(fixture.FixtureError):
                fixture.fixture(root)

    def test_preview_prepare_has_no_writes_or_commands(self):
        with temporary_directory() as temp:
            target = Path(temp) / "new"
            args = argparse.Namespace(workspace=str(target), postgres_image=POSTGRES, apply=False)
            with patch.object(fixture.shared, "checked") as checked:
                result = fixture.prepare(args)
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertFalse(target.exists())
            checked.assert_not_called()

    def test_apply_without_approval_does_not_start_docker(self):
        output = io.StringIO()
        with patch.object(fixture.shared, "checked") as checked, contextlib.redirect_stdout(output):
            code = fixture.main(["up", "--workspace", "unused", "--apply"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
        checked.assert_not_called()

    def prepare_fixture(self, parent):
        args = argparse.Namespace(workspace=str(Path(parent) / "generated"), postgres_image=POSTGRES,
                                  source=str(parent), apply=True, approval_id="unit-test")
        with patch.object(fixture.shared, "git_read", side_effect=[fixture.SOURCE_PIN.encode(), b""]):
            result = fixture.prepare(args)
        self.assertEqual(result["status"], "PASS")
        root, generated = fixture.fixture(args.workspace)
        self.assertNotIn(generated["password"], json.dumps(result))
        self.assertNotIn(generated["db_password"], json.dumps(result))
        self.assertNotEqual(generated["password"], generated["db_password"])
        return root, generated

    def test_prepare_never_overwrites_and_detects_payload_drift_but_allows_down(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            (root / "pcaps/synthetic.pcap").write_bytes(b"changed")
            with self.assertRaises(fixture.FixtureError):
                fixture.fixture(root)
            self.assertEqual(fixture.fixture(root, check_payload=False)[1], generated)
            args = argparse.Namespace(workspace=str(root), postgres_image=POSTGRES, apply=False)
            with self.assertRaises(fixture.FixtureError):
                fixture.prepare(args)

    def test_compose_tamper_blocks_even_down(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            changed = fixture.compose_spec(generated)
            changed["services"]["packmate"]["privileged"] = True
            (root / "compose.json").write_bytes(fixture.shared.canonical(changed))
            with self.assertRaises(fixture.FixtureError):
                fixture.fixture(root, check_payload=False)

    def test_legacy_internal_only_fixture_allows_cleanup_but_not_reuse(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            (root / "compose.json").write_bytes(fixture.shared.canonical(
                fixture.compose_spec(generated, legacy_internal_only=True)))
            self.assertEqual(fixture.fixture(root, check_payload=False)[1], generated)
            with self.assertRaises(fixture.FixtureError):
                fixture.fixture(root)

    def test_db_edge_network_tamper_blocks_execution_and_cleanup(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            changed = fixture.compose_spec(generated)
            changed["services"]["db"]["networks"].append("edge")
            (root / "compose.json").write_bytes(fixture.shared.canonical(changed))
            for check_payload in (True, False):
                with self.assertRaises(fixture.FixtureError):
                    fixture.fixture(root, check_payload=check_payload)

    def test_preview_existing_fixture_does_not_call_docker(self):
        with temporary_directory() as temp:
            root, _ = self.prepare_fixture(temp)
            for action in ("pull", "up", "smoke", "down"):
                args = argparse.Namespace(workspace=str(root), action=action, apply=False)
                with patch.object(fixture.shared, "checked") as checked:
                    result = fixture.execute(args)
                self.assertEqual(result["status"], "NOT_RUN")
                checked.assert_not_called()

    def test_up_failure_stops_only_exact_project_and_retains_data(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            args = argparse.Namespace(workspace=str(root), action="up", apply=True)
            calls = []

            def command(argv, **kwargs):
                calls.append(argv)
                if "up" in argv:
                    raise fixture.FixtureError("synthetic timeout")
                return b""

            with patch.object(fixture.shared, "checked", side_effect=command), patch.object(fixture, "image_evidence", return_value={}):
                with self.assertRaises(fixture.FixtureError):
                    fixture.execute(args)
            self.assertEqual(calls[-1][-3:], ["down", "--timeout", "10"])
            self.assertTrue(all(generated["project"] in cmd for cmd in calls))
            self.assertTrue(all("--volumes" not in cmd and "prune" not in cmd for cmd in calls))
            self.assertIn("stopped", args.rollback_status)
            self.assertTrue((root / "data/postgres").is_dir())

    def test_up_interrupt_stops_exact_project_and_reports_sanitized_blocked(self):
        with temporary_directory() as temp:
            root, generated = self.prepare_fixture(temp)
            calls = []

            def checked(argv, **kwargs):
                calls.append(argv)
                if "up" in argv:
                    raise KeyboardInterrupt("sensitive-interrupt-payload")
                return b""

            with patch.object(fixture.shared, "checked", side_effect=checked), \
                 patch.object(fixture, "image_evidence", return_value={}), contextlib.redirect_stdout(io.StringIO()) as output:
                try:
                    code = fixture.main(["up", "--workspace", str(root), "--apply", "--approval-id", "qa-approved"])
                except KeyboardInterrupt:
                    code = None
            self.assertEqual(code, 2, "Ctrl-C must produce a sanitized blocked result")
            report = json.loads(output.getvalue())
            self.assertEqual(report["status"], "BLOCKED")
            self.assertIn("stopped", report["rollback_status"])
            self.assertNotIn("sensitive", output.getvalue())
            downs = [argv for argv in calls if "down" in argv]
            self.assertEqual(len(downs), 1)
            self.assertIn(generated["project"], downs[0])
            self.assertNotIn("--volumes", downs[0])
            self.assertNotIn("prune", downs[0])
            self.assertTrue((root / "data/postgres").is_dir())

    def test_readiness_interrupt_cleanup_failure_is_reported_not_hidden(self):
        with temporary_directory() as temp:
            root, _ = self.prepare_fixture(temp)
            calls = []

            def checked(argv, **kwargs):
                calls.append(argv)
                if "down" in argv:
                    raise fixture.FixtureError("synthetic cleanup failure")
                return b""

            with patch.object(fixture.shared, "checked", side_effect=checked), \
                 patch.object(fixture, "image_evidence", return_value={}), patch.object(fixture, "app_port", return_value=1234), \
                 patch.object(fixture, "wait_ready", side_effect=KeyboardInterrupt("sensitive-payload")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                code = fixture.main(["up", "--workspace", str(root), "--apply", "--approval-id", "qa-approved"])
            self.assertEqual(code, 2)
            self.assertIn("automatic stop failed", json.loads(output.getvalue())["rollback_status"])
            self.assertNotIn("sensitive", output.getvalue())
            self.assertEqual(len([argv for argv in calls if "down" in argv]), 1)

    def test_nonloopback_published_port_is_rejected(self):
        for value in (b"0.0.0.0:1234", b"[::]:1234", b"127.0.0.1:0", b"127.0.0.1:65536", b"127.0.0.1:22\n127.0.0.1:23"):
            with self.subTest(value=value), patch.object(fixture.shared, "checked", return_value=value):
                with self.assertRaises(fixture.FixtureError):
                    fixture.app_port(["docker", "compose"])


class PackmateSmokeTests(unittest.TestCase):
    def test_api_failure_diagnostic_contains_only_allowlisted_route_method_status(self):
        with patch.object(fixture, "request", return_value=(404, b"sensitive-response", "sensitive-header")):
            with self.assertRaises(fixture.FixtureError) as caught:
                fixture.json_request(12345, state(), "/api/pcap/started")
        self.assertEqual(str(caught.exception),
                         "Packmate API request failed: GET /api/pcap/started returned HTTP 404; raw response suppressed")
        self.assertNotIn("sensitive", str(caught.exception))
        self.assertNotIn(state()["password"], str(caught.exception))

    def test_api_failure_diagnostic_redacts_unlisted_route_and_invalid_status(self):
        with patch.object(fixture, "request", return_value=("sensitive-status", b"sensitive-response", "")):
            with self.assertRaises(fixture.FixtureError) as caught:
                fixture.json_request(12345, state(), "/api/pcap/started?password=sensitive-query", "sensitive-method")
        self.assertEqual(str(caught.exception),
                         "Packmate API request failed: unlisted request returned HTTP invalid; raw response suppressed")
        self.assertNotIn("sensitive", str(caught.exception))

    def run_smoke(self, *, bad_auth=False, corrupt_response=False, fresh=True, found=True):
        record = state()
        query_paths = []
        created = False
        started = False

        def request(port, current, path, method="GET", body=None, auth="valid"):
            if path == "/":
                return 200, b"<!doctype html><html>fixture</html>", ""
            return (500 if bad_auth else 401), b"", "Basic realm=fixture"

        def json_request(port, current, path, method="GET", body=None):
            nonlocal created, started
            query_paths.append((path, method, body))
            if path == "/api/service/":
                if method == "POST":
                    created = True
                    return body
                return [] if fresh else [{"port": 18080}]
            if path == "/api/pcap/started":
                return started
            if path == "/api/pattern/":
                self.assertTrue(created, "service must exist before pattern/import")
                return {"id": 7, "enabled": True}
            if path == "/api/pcap/start":
                self.assertTrue(created)
                started = True
                return None
            if path == "/api/stream/18080":
                self.assertTrue(started, "import must start before querying streams")
                self.assertEqual(body["pattern"], {"id": 7})
                return [{"id": 9, "service": 18080, "protocol": "TCP", "foundPatternsIds": [7]}] if found else []
            if path == "/api/packet/9":
                incoming, outgoing = pcap.payloads(current["marker"])
                return [{"content": base64.b64encode(payload).decode(), "incoming": direction,
                         "matches": [{"patternId": 7}]} for payload, direction in
                        ((incoming, True), (b"wrong-response" if corrupt_response else outgoing, False))]
            self.fail("unexpected API request: " + path)

        with patch.object(fixture, "app_port", return_value=12345), patch.object(fixture, "wait_ready"), \
                patch.object(fixture, "request", side_effect=request), patch.object(fixture, "json_request", side_effect=json_request), \
                patch.object(fixture, "image_evidence", return_value={}), patch.object(fixture.time, "monotonic", side_effect=[0, 1, 46]):
            result = fixture.smoke(["docker", "compose"], record)
        self.assertNotIn(record["password"], json.dumps(result))
        self.assertNotIn(record["db_password"], json.dumps(result))
        return result

    def test_real_contract_order_success_requires_exact_request_response_and_pattern(self):
        result = self.run_smoke()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(all(result["checks"].values()))
        self.assertIn("Apple Silicon", result["not_validated"])
        self.assertIn("LIVE capture", result["not_validated"])
        self.assertIn("image-to-source build provenance", result["not_validated"])
        self.assertIn("outbound connectivity", result["network_scope"])

    def test_arbitrary_auth_failure_is_not_success(self):
        result = self.run_smoke(bad_auth=True)
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["checks"]["auth_wrong_rejected"])

    def test_stream_exists_but_wrong_response_fails(self):
        result = self.run_smoke(corrupt_response=True)
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["checks"]["response_exact_and_outgoing"])

    def test_missing_import_fails(self):
        result = self.run_smoke(found=False)
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["checks"]["filtered_stream_found"])

    def test_previous_database_cannot_pass_fresh_import_smoke(self):
        with self.assertRaisesRegex(fixture.FixtureError, "fresh"):
            self.run_smoke(fresh=False)


if __name__ == "__main__":
    unittest.main()
