from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
MODULE_PATH = TOOLS / "probe_m11_upstream_color132.py"
spec = importlib.util.spec_from_file_location("probe_m11_upstream_color132", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class UpstreamColor132ProbeTests(unittest.TestCase):
    def _payload(self, endian: str = "little") -> bytes:
        # Exactly 33 signed-int32 words with all three recorded signatures and
        # the two historical temperature anchors in the six remaining slots.
        words = [
            2850,
            6807,
            7,
            *module.SIGNATURES["cm1_q12"],
            11,
            *module.SIGNATURES["cm2_q12"],
            13,
            *module.SIGNATURES["extra_matrix"],
            17,
        ]
        self.assertEqual(len(words), module.STRUCT_WORDS)
        return module.pack_words(words, endian)

    def test_exact_132byte_little_endian_candidate_is_recovered(self):
        data = b"\xaa" * 16 + self._payload("little") + b"\xbb" * 16
        scans = module.scan_payload(data)
        little = next(x for x in scans if x["endian"] == "little")
        exact = [x for x in little["candidate_windows"] if x["start"] == 16]
        self.assertTrue(exact)
        candidate = exact[0]
        self.assertTrue(candidate["contains_both_recorded_temperatures"])
        self.assertEqual(candidate["signature_word_offsets"]["cm1_q12"], 3)
        self.assertEqual(candidate["signature_word_offsets"]["cm2_q12"], 13)
        self.assertEqual(candidate["signature_word_offsets"]["extra_matrix"], 23)
        self.assertEqual(candidate["recorded_temperature_word_positions"]["2850"], [0])
        self.assertEqual(candidate["recorded_temperature_word_positions"]["6807"], [1])

    def test_big_endian_signature_is_distinguished(self):
        data = self._payload("big")
        scans = module.scan_payload(data)
        big = next(x for x in scans if x["endian"] == "big")
        self.assertTrue(big["candidate_windows"])
        little = [x for x in scans if x["endian"] == "little"]
        self.assertFalse(little)

    def test_separated_signatures_outside_132_bytes_do_not_form_candidate(self):
        cm1 = module.pack_words(module.SIGNATURES["cm1_q12"], "little")
        cm2 = module.pack_words(module.SIGNATURES["cm2_q12"], "little")
        extra = module.pack_words(module.SIGNATURES["extra_matrix"], "little")
        data = cm1 + b"\x00" * 80 + cm2 + b"\x00" * 80 + extra
        hits = module.signature_hits(data, "little")
        self.assertEqual(module.candidate_windows(data, "little", hits), [])


if __name__ == "__main__":
    unittest.main()
