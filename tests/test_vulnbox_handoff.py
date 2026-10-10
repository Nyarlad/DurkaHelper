"""Portable handoff uses synthetic inert captures, never a remote VM."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("vulnbox_handoff", ROOT / "integration/vulnbox_handoff.py")
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class HandoffTests(unittest.TestCase):
    def event(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "event.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return handoff.capture_from_event(path)

    def data(self):
        return handoff.module("handoff_test_pcap", "integration/synthetic_pcap.py").make_pcap(handoff.MARKER.decode())

    def test_missing_event_or_input_uses_local_fixture(self):
        self.assertIsNone(handoff.capture_from_event(None))
        self.assertIsNone(self.event({"inputs": {}}))

    def test_approved_capture_decoded_exactly(self):
        data = self.data()
        self.assertEqual(self.event({"inputs": {handoff.INPUT: base64.b64encode(data).decode()}}), data)

    def test_malformed_base64_rejected(self):
        with self.assertRaises(ValueError):
            self.event({"inputs": {handoff.INPUT: "not base64!"}})

    def test_unmarked_capture_rejected(self):
        data = handoff.module("handoff_other_pcap", "integration/synthetic_pcap.py").make_pcap("a" * 24)
        with self.assertRaises(ValueError):
            self.event({"inputs": {handoff.INPUT: base64.b64encode(data).decode()}})

    def test_oversized_input_rejected(self):
        with self.assertRaises(ValueError):
            self.event({"inputs": {handoff.INPUT: "A" * 50000}})

    def test_non_object_inputs_rejected(self):
        with self.assertRaises(ValueError):
            self.event({"inputs": ["unexpected"]})

    def test_non_object_event_rejected(self):
        with self.assertRaises(ValueError):
            self.event([])

    def test_invalid_capture_does_not_start_transfer(self):
        with patch.object(handoff, "transfer", side_effect=AssertionError("network")):
            with self.assertRaises(ValueError):
                handoff.run(b"arbitrary")

    def test_real_cli_and_file_transfer(self):
        result = handoff.run(self.data())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["capture_origin"], "approved-synthetic-input")
        self.assertIn("Packmate_import", result["not_tested"])


if __name__ == "__main__":
    unittest.main()
