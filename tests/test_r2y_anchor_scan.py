import importlib.util
import struct
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "r2y_anchor_scan.py"
spec = importlib.util.spec_from_file_location("r2y_anchor_scan", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


def test_matrix_anchor_little_endian_offset():
    payload = b"\xAA" * 13 + mod.pack_i16(mod.ANCHORS["cc0_q9"], "little") + b"\xBB" * 7
    hits = mod.scan_matrix_anchors(payload)
    cc0 = [h for h in hits if h.anchor == "cc0_q9" and h.endian == "little"]
    assert len(cc0) == 1
    assert cc0[0].offset == 13


def test_matrix_anchor_big_endian_detected_separately():
    payload = b"\x00" * 5 + mod.pack_i16(mod.ANCHORS["category24_ycc"], "big")
    hits = mod.scan_matrix_anchors(payload)
    ycc = [h for h in hits if h.anchor == "category24_ycc"]
    assert [(h.endian, h.offset) for h in ycc] == [("big", 5)]


def test_exact_saturation_run():
    payload = b"header" + mod.pack_u16(mod.SAT_VALUES, "little") + b"tail"
    hits = mod.scan_saturation_runs(payload)
    strong = [h for h in hits if h.anchor == "category42_sat_run"]
    assert len(strong) == 1
    assert strong[0].endian == "little"
    assert strong[0].offset == len(b"header")


def test_no_false_matrix_hit_from_unrelated_data():
    payload = struct.pack("<" + "h" * 9, *range(9))
    assert mod.scan_matrix_anchors(payload) == []


def test_find_all_reports_overlapping_occurrences():
    assert mod.find_all(b"AAAA", b"AA") == [0, 1, 2]
