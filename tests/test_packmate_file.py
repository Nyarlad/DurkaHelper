"""Closed-file swap safety; mocked Docker is not upstream import validation."""
import argparse
from contextlib import ExitStack, redirect_stdout
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
SPEC = importlib.util.spec_from_file_location("tested_packmate_file", ROOT / "deployment/packmate_file.py")
file = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(file)


def classic(payload=b"synthetic", endian="<", nano=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    return struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1) + struct.pack(
        endian + "IIII", 1, 2, len(payload), len(payload)) + payload


def pcapng(endian="<"):
    section = struct.pack(endian + "IIIHHqI", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    interface = struct.pack(endian + "IIHHII", 1, 20, 1, 0, 65535, 20)
    packet = struct.pack(endian + "IIII", 3, 20, 4, 0x01020304) + struct.pack(endian + "I", 20)
    return section + interface + packet


class ClosedPcapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "pcaps").mkdir()
        self.current = self.root / "pcaps/current.pcap"
        self.source = self.root / "incoming.pcap"
        self.current.write_bytes(classic(b"old"))
        self.source.write_bytes(classic(b"new"))
        self.profile = {"packmate": {"pcap_file": "current.pcap"}}
        self.state = {"project": "dh-deploy-" + "a" * 12}
        self.runtime = {"services": {"packmate": {"image": "sha256:" + "b" * 64}}}

    def tearDown(self):
        self.temp.cleanup()

    def args(self, **changes):
        value = dict(workspace=self.root, pcap=self.source, expected_sha256=file.rec.sha(self.source.read_bytes()),
                     apply=True, approval_id="test", daemon_id="synthetic-daemon", closed_pcap_confirmed=True,
                     maintenance_confirmed=True)
        value.update(changes)
        return argparse.Namespace(**value)

    def workspace(self):
        return self.root, self.state, self.runtime, self.profile, []

    def test_classic_endianness_and_precision_variants(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                data = classic(endian=endian, nano=nano)
                self.source.write_bytes(data)
                _, _, summary = file.inspect_file(self.source, file.rec.sha(data))
                self.assertEqual(summary["format"], "PCAP")
                self.assertEqual(summary["packet_records"], 1)
                self.assertEqual(summary["bytes"], len(data))

    def test_pcapng_endianness_and_multiple_sections(self):
        for data in (pcapng("<"), pcapng(">"), pcapng("<") + pcapng(">")):
            self.source.write_bytes(data)
            summary = file.inspect_file(self.source)[2]
            self.assertEqual(summary["format"], "PCAPNG")
            self.assertEqual(summary["packet_records"], 2 if len(data) == 136 else 1)

    def test_empty_classic_container_accepted(self):
        self.source.write_bytes(classic()[:24])
        self.assertEqual(file.inspect_file(self.source)[2]["packet_records"], 0)

    def test_malformed_headers_packets_and_blocks_are_rejected(self):
        inputs = [b"private-not-pcap" * 4, classic()[:-1], classic()[:25], pcapng()[:-1],
                  pcapng()[:-4] + b"\0\0\0\0", pcapng()[:8] + b"BAD!" + pcapng()[12:],
                  classic()[:20] + b"\0\0\0\0" + classic()[24:25],
                  classic()[:24] + struct.pack("<IIII", 0, 0, 65536, 65536)]
        for data in inputs:
            self.source.write_bytes(data)
            with self.subTest(size=len(data)), self.assertRaises(file.Error):
                file.inspect_file(self.source)

    def test_expected_checksum_is_required_and_input_is_unchanged(self):
        before = self.source.read_bytes()
        with self.assertRaisesRegex(file.Error, "SHA-256"):
            file.inspect_file(self.source, "0" * 64)
        self.assertEqual(self.source.read_bytes(), before)
        with self.assertRaisesRegex(file.Error, "SHA-256"):
            file.replace(self.args(expected_sha256="not-a-hash"))

    def test_byte_limit_is_checked_before_body_read(self):
        with patch.object(file, "MAX_BYTES", 24), self.assertRaises(file.Error):
            file.inspect_file(self.source)

    def test_source_metadata_change_is_not_false_clean(self):
        with patch.object(file.ops, "_stat_identity", side_effect=["first", "changed"]), self.assertRaisesRegex(file.Error, "changed while"):
            file.inspect_file(self.source)

    @unittest.skipIf(os.name == "nt", "POSIX symlink/FIFO support")
    def test_symlink_and_fifo_are_rejected_without_blocking(self):
        link = self.root / "link.pcap"
        link.symlink_to(self.source)
        with self.assertRaises(file.Error):
            file.inspect_file(link)
        fifo = self.root / "fifo.pcap"
        os.mkfifo(fifo)
        with self.assertRaises(file.Error):
            file.inspect_file(fifo)

    def test_preview_reads_only_no_daemon_or_output_files(self):
        before = {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        with patch.object(file.rec, "source_workspace", return_value=self.workspace()), \
             patch.object(file.rec, "run", side_effect=AssertionError("Docker")):
            result = file.replace(self.args(apply=False))
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse(result["daemon_contacted"])
        self.assertTrue(result["processing"].startswith("NOT_RUN"))
        after = {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def test_using_the_current_file_as_source_is_rejected(self):
        with patch.object(file.rec, "source_workspace", return_value=self.workspace()), self.assertRaisesRegex(file.Error, "separate"):
            file.replace(self.args(pcap=self.current, expected_sha256=file.rec.sha(self.current.read_bytes()), apply=False))

    def test_approval_closed_file_and_maintenance_are_mandatory(self):
        for fields in ({"approval_id": None}, {"approval_id": "bad\nvalue"}, {"closed_pcap_confirmed": False}, {"maintenance_confirmed": False}):
            with patch.object(file.rec, "daemon", side_effect=AssertionError("Docker contacted")), self.assertRaises(file.Error):
                file.gates(self.args(**fields))

    def mocks(self):
        stack = ExitStack()
        stack.enter_context(patch.object(file.rec, "source_workspace", return_value=self.workspace()))
        stack.enter_context(patch.object(file, "gates"))
        stack.enter_context(patch.object(file.rec, "owned", return_value={"packmate-db": {"running": True}, "packmate": {"running": True}}))
        stack.enter_context(patch.object(file.kit, "image_preflight"))
        stack.enter_context(patch.object(file, "stage_files", return_value=self.root / "pcap-import-synthetic"))
        stack.enter_context(patch.object(file, "cutover"))
        stack.enter_context(patch.object(file.rec, "run"))
        stack.enter_context(patch.object(file.activation, "packmate_ready"))
        return stack

    def test_stopped_database_is_never_automatically_started(self):
        with self.mocks(), patch.object(file.rec, "owned", return_value={"packmate-db": {"running": False}}), \
             patch.object(file.rec, "stop") as stop, patch.object(file.rec, "run") as run:
            with self.assertRaisesRegex(file.Error, "must already be running"):
                file.replace(self.args())
        stop.assert_not_called()
        run.assert_not_called()

    def test_copy_failure_leaves_only_app_stopped_and_never_restarts(self):
        with self.mocks(), patch.object(file, "stage_files", side_effect=file.Error("copy failed")), \
             patch.object(file.rec, "stop") as stop, patch.object(file.rec, "run") as run:
            with self.assertRaisesRegex(file.Error, "copy failed"):
                file.replace(self.args())
        self.assertEqual(stop.call_count, 2)
        self.assertTrue(all(call.args[1] == ("packmate",) for call in stop.call_args_list))
        run.assert_not_called()

    def test_apply_restarts_only_packmate_and_never_starts_processing(self):
        running = {"packmate-db": {"running": True}, "packmate": {"running": True}}
        stopped = {"packmate-db": {"running": True}, "packmate": {"running": False}}
        original_inspect = file.inspect_file
        count = [0]
        def inspect(*args, **kw):
            count[0] += 1
            if count[0] == 3:
                return original_inspect(self.source)
            return original_inspect(*args, **kw)
        with self.mocks(), patch.object(file.rec, "owned", side_effect=[running, stopped, stopped, running]), \
             patch.object(file.rec, "stop") as stop, patch.object(file.rec, "run") as run, \
             patch.object(file, "inspect_file", side_effect=inspect):
            result = file.replace(self.args())
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["capture_started"])
        self.assertTrue(result["processing"].startswith("NOT_RUN"))
        stop.assert_called_once()
        self.assertEqual(run.call_args.args[0][-7:], ["up", "--detach", "--no-deps", "--no-build", "--pull", "never", "packmate"])
        self.assertNotIn("celery", run.call_args.args[0])
        self.assertNotIn("neo-worker", run.call_args.args[0])
        self.assertTrue(result["rollback"]["relative_input"].endswith("/previous.pcap"))

    def test_readiness_failure_stops_only_packmate_and_retains_rollback(self):
        running = {"packmate-db": {"running": True}, "packmate": {"running": True}}
        stopped = {"packmate-db": {"running": True}, "packmate": {"running": False}}
        with self.mocks(), patch.object(file.rec, "owned", side_effect=[running, stopped, stopped]), \
             patch.object(file.rec, "stop") as stop, \
             patch.object(file.activation, "packmate_ready", side_effect=file.Error("readiness failed")):
            with self.assertRaisesRegex(file.Error, "readiness failed"):
                file.replace(self.args())
        self.assertEqual(stop.call_count, 2)
        self.assertTrue(all(call.args[1] == ("packmate",) for call in stop.call_args_list))

    def test_restart_during_staging_blocks_before_cutover(self):
        running = {"packmate-db": {"running": True}, "packmate": {"running": True}}
        with self.mocks(), patch.object(file.rec, "owned", side_effect=[running, running]), \
             patch.object(file.rec, "stop") as stop, patch.object(file, "cutover") as cutover, \
             patch.object(file.rec, "run") as run:
            with self.assertRaisesRegex(file.Error, "while staging; no file replaced"):
                file.replace(self.args())
        cutover.assert_not_called()
        run.assert_not_called()
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(self.current.read_bytes(), classic(b"old"))

    @unittest.skipIf(os.name == "nt", "descriptor-anchored replacement requires POSIX")
    def test_real_staging_cutover_and_reverse_replacement_preserve_rollback(self):
        old = file.inspect_file(self.current)[2]
        new = file.inspect_file(self.source)[2]
        transaction = file.stage_files(self.root, self.source, new, self.current, old)
        self.assertEqual((transaction / "previous.pcap").read_bytes(), classic(b"old"))
        file.cutover(self.root, self.current.name, transaction, old, new)
        self.assertEqual(self.current.read_bytes(), classic(b"new"))
        self.assertEqual(self.current.stat().st_mode & 0o777, 0o644)
        reverse = file.stage_files(self.root, transaction / "previous.pcap", old, self.current, new)
        file.cutover(self.root, self.current.name, reverse, new, old)
        self.assertEqual(self.current.read_bytes(), classic(b"old"))
        self.assertEqual((reverse / "previous.pcap").read_bytes(), classic(b"new"))

    @unittest.skipIf(os.name == "nt", "descriptor-anchored replacement requires POSIX")
    def test_source_race_before_replace_is_rejected_without_false_success(self):
        old, new = file.inspect_file(self.current)[2], file.inspect_file(self.source)[2]
        transaction = file.stage_files(self.root, self.source, new, self.current, old)
        original_replace = os.replace
        def race(source, destination, **kwargs):
            (self.root / "pcaps" / source).write_bytes(classic(b"raced"))
            return original_replace(source, destination, **kwargs)
        with patch.object(file.os, "replace", side_effect=race), self.assertRaisesRegex(file.Error, "bytes changed"):
            file.cutover(self.root, self.current.name, transaction, old, new)
        self.assertEqual((transaction / "previous.pcap").read_bytes(), classic(b"old"))

    def test_cli_never_echoes_unexpected_exception_payload(self):
        output = io.StringIO()
        with patch.object(file, "replace", side_effect=ValueError("SECRET-PCAP-CONTENT")), redirect_stdout(output):
            code = file.main(["replace", "--workspace", "unused", "--pcap", "unused", "--expected-sha256", "0" * 64])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET-PCAP-CONTENT", output.getvalue())


if __name__ == "__main__":
    unittest.main()
