from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from renderer.reference import validate_forensics_data
from tools import materialize_m11_reference_tables as materializer


class MaterializeM11ReferenceTablesTests(unittest.TestCase):
    def make_source(self, root: Path) -> Path:
        source = root / "canonical"
        source.mkdir()

        cc0_matrix = [[495, -58, 63], [10, 601, -111], [49, -255, 705]]
        cc0_flat = [v for row in cc0_matrix for v in row]
        (source / "category3_CC0_candidate.json").write_text(json.dumps({
            "schema": "m11camera.forensics.category3_cc0.v1",
            "raw_i16": [7] + cc0_flat + [1] * 11,
            "matrix_q9": cc0_matrix,
        }) + "\n")

        matrices = [
            [[1041, -372, -157], [-117, 630, -1], [-4, -78, 595]],
            [[910, -290, -108], [-100, 620, -8], [-3, -70, 590]],
            [[806, -225, -69], [-90, 610, -8], [-2, -60, 580]],
            [[715, -169, -34], [-80, 600, -8], [-1, -50, 570]],
        ]
        ranges = [[0, 10000], [10000, 20000], [20000, 40000], [40000, 200000]]
        bands = []
        for index, (matrix, iso_range) in enumerate(zip(matrices, ranges)):
            flat = [v for row in matrix for v in row]
            bands.append({
                "raw_i16": [index] + flat + [0] * 6,
                "matrix_q9": matrix,
                "q_denominator": 512,
                "iso_range": iso_range,
            })
        (source / "category13_CC1_candidate.json").write_text(json.dumps({
            "schema": "m11camera.forensics.category13_cc1.v1",
            "bands": bands,
        }) + "\n")

        tone_path = source / "tone_q12_reconstructed_curves.csv"
        tone_fields = ["index", "input_norm"] + [f"gain_q12_{state:+d}" for state in range(-3, 4)]
        with tone_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=tone_fields)
            w.writeheader()
            for index in range(1024):
                row = {"index": index, "input_norm": index / 1023}
                for state in range(-3, 4):
                    row[f"gain_q12_{state:+d}"] = 2048 if state == 0 else 4096
                w.writerow(row)

        gamma_path = source / "gamma_4096_high_nibble_first.csv"
        with gamma_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["index", "input_norm", "output_10bit", "output_norm"])
            w.writeheader()
            for index in range(4096):
                value = round(index * 1023 / 4095)
                w.writerow({
                    "index": index,
                    "input_norm": index / 4095,
                    "output_10bit": value,
                    "output_norm": value / 1023,
                })
        return source

    def test_default_materialization_preserves_low_iso_matrices_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self.make_source(root)
            out = root / "materialized"
            manifest = materializer.materialize(source, out)

            cc0 = json.loads((out / "category3_CC0_candidate.json").read_text())
            self.assertEqual(cc0["signed_int16"], cc0["raw_i16"])
            self.assertFalse(cc0["materialization"]["numeric_change"])

            cc1 = json.loads((out / "category13_CC1_candidate.json").read_text())
            self.assertEqual(cc1["selected_band_index"], 0)
            self.assertEqual(cc1["signed_int16"], cc1["bands"][0]["raw_i16"])
            self.assertEqual(manifest["tables"]["cc1"]["selection_policy"], "base_iso_default_first_band")

            # The existing frozen-renderer structural validator must accept the
            # adapter output without any change to the renderer contract.
            validate_forensics_data.validate(out)

    def test_tone_materialization_is_exact_recorded_gain_equation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self.make_source(root)
            out = root / "materialized"
            materializer.materialize(source, out)

            with (out / "tone_q12_reconstructed_curves.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            row = rows[511]
            x = float(row["input_norm"])
            self.assertEqual(float(row["contrast_-3_output_norm_q12_model"]), x)
            self.assertAlmostEqual(float(row["contrast_0_output_norm_q12_model"]), x * 0.5, places=15)
            self.assertEqual(int(row["gain_q12_-3"]), 4096)
            self.assertEqual(int(row["gain_q12_+0"]), 2048)

    def test_iso_selection_uses_extracted_interval_without_nearest_band_guess(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self.make_source(root)
            out = root / "materialized"
            manifest = materializer.materialize(source, out, iso=15000)
            self.assertEqual(manifest["tables"]["cc1"]["selected_band_index"], 1)
            self.assertEqual(manifest["tables"]["cc1"]["selection_policy"], "iso_range_match")

            with self.assertRaisesRegex(ValueError, "does not match any canonical Category13 iso_range"):
                materializer.materialize(source, root / "bad", iso=250000)

    def test_gamma_is_byte_for_byte_and_manifest_marks_no_renderer_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self.make_source(root)
            out = root / "materialized"
            manifest = materializer.materialize(source, out)
            self.assertEqual(
                (source / "gamma_4096_high_nibble_first.csv").read_bytes(),
                (out / "gamma_4096_high_nibble_first.csv").read_bytes(),
            )
            self.assertFalse(manifest["renderer_math_changed"])
            self.assertTrue(manifest["no_visual_fitting"])
            self.assertTrue(manifest["no_hdr"])


if __name__ == "__main__":
    unittest.main()
