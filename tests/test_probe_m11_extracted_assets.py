from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "probe_m11_extracted_assets.py"
spec = importlib.util.spec_from_file_location("m11_asset_probe", MODULE_PATH)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


def synthetic_tone_curve(lo: int, hi: int, n: int = 1024) -> list[int]:
    if lo == hi:
        return [lo] * n
    # Smooth deterministic ramp that hits the recorded range endpoints exactly.
    return [round(lo + (hi - lo) * i / (n - 1)) for i in range(n)]


class ExtractedAssetProbeTests(unittest.TestCase):
    def make_tone_family(self, endian: str = "le") -> bytes:
        prefix = "<" if endian == "le" else ">"
        chunks = []
        for state in probe.TONE_STATES:
            lo, hi = probe.TONE_EXPECTED_RANGES[state]
            vals = synthetic_tone_curve(lo, hi)
            chunks.append(struct.pack(prefix + "1024H", *vals))
        return b"".join(chunks)

    def test_exact_tone_family_is_recovered_little_endian(self) -> None:
        payload = b"HEADER" + self.make_tone_family("le") + b"TAIL"
        candidates = probe.find_tone_candidates(payload)
        exact = [c for c in candidates if c["exact_recorded_range_match"]]
        self.assertTrue(exact)
        self.assertEqual(exact[0]["endian"], "le")
        self.assertEqual(exact[0]["state_order"], probe.TONE_STATES)
        self.assertEqual(exact[0]["start"], len(b"HEADER"))

    def test_exact_tone_family_is_recovered_big_endian(self) -> None:
        payload = b"01234567" + self.make_tone_family("be")
        candidates = probe.find_tone_candidates(payload)
        exact = [c for c in candidates if c["exact_recorded_range_match"]]
        self.assertTrue(exact)
        self.assertEqual(exact[0]["endian"], "be")
        self.assertEqual(exact[0]["start"], 8)

    def test_modified_range_does_not_claim_exact_match(self) -> None:
        data = bytearray(self.make_tone_family("le"))
        # State -2 block begins after the 2048-byte -3 block. Replace its first
        # sample so the observed minimum no longer matches the recorded value.
        struct.pack_into("<H", data, probe.TONE_BYTES, 3005)
        candidates = probe.find_tone_candidates(bytes(data))
        self.assertFalse(any(c["exact_recorded_range_match"] for c in candidates))

    def test_monotonic_10bit_gamma_coarse_candidate_is_retained(self) -> None:
        vals = [round(1023 * i / 255) for i in range(256)]
        payload = struct.pack("<256H", *vals)
        candidates = probe.find_gamma_coarse_candidates(payload, max_candidates=5)
        self.assertTrue(candidates)
        best = candidates[0]
        self.assertEqual(best["offset"], 0)
        self.assertEqual(best["endian"], "le")
        self.assertTrue(best["stats"]["nondecreasing"])
        self.assertEqual(best["stats"]["first"], 0)
        self.assertEqual(best["stats"]["last"], 1023)


if __name__ == "__main__":
    unittest.main()
