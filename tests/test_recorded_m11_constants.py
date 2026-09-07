from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSTANTS = ROOT / "research" / "recorded" / "m11p_v03_recorded_constants.json"


class RecordedM11ConstantsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(CONSTANTS.read_text())

    def test_evidence_class_is_not_reproduced(self) -> None:
        self.assertEqual(
            self.data["evidence_class"],
            "recorded_prior_finding_not_yet_reproduced",
        )

    def test_category42_percent_relationship(self) -> None:
        states = self.data["category42_saturation"]["states"]
        for state, item in states.items():
            expected = round(512 * item["percent"] / 100) - 1
            self.assertEqual(
                item["field"],
                expected,
                msg=f"state {state} does not match recorded saturation relationship",
            )

    def test_recovered_mode_states_exist(self) -> None:
        states = self.data["category42_saturation"]["states"]
        self.assertEqual(states["-1"]["field"], 511)  # Natural ~100%
        self.assertEqual(states["0"]["field"], 588)   # Standard ~115%
        self.assertEqual(states["+1"]["field"], 665)  # Vivid ~130%

    def test_matrix_dimensions(self) -> None:
        for key in ("cc0_category3", "cc1_category13_low_iso_candidate"):
            matrix = self.data[key]["matrix_q9"]
            self.assertEqual(len(matrix), 3)
            self.assertTrue(all(len(row) == 3 for row in matrix))


if __name__ == "__main__":
    unittest.main()
