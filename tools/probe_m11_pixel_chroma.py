#!/usr/bin/env python3
"""Pixel-level M11 DNG/JPEG probe using a tone/gamma-invariant chroma angle.

Why this works as an early stage-order test:

- the recovered tone stage applies one luminance-dependent scalar to RGB;
- a common RGB scalar does not change Cb/Cr hue angle after linear RGB->YCC;
- the current gamma hypothesis changes Y only;
- Standard saturation multiplies Cb and Cr by the same scalar;
- therefore atan2(Cr,Cb) is invariant to the unknown tone gain, Y gamma, and
  symmetric Standard chroma amount.

The probe maps genuine M11 RAW camera RGB through the DNG no-ForwardMatrix
scene transform, into the fixed Standard-A reference M11 WB-camera basis, then
through recorded CC0 and low-ISO CC1. It compares the resulting YCC chroma angle
with the matching in-camera JPEG after inverse sRGB OETF.

This is a structural diagnostic, not a full JPEG renderer.
"""
from __future__ import annotations

import argparse
import json
import math
import subprocess
from pathlib import Path

import cv2
import numpy as np
import rawpy
from PIL import Image, ImageOps

CC0 = np.array([[495, -58, 63], [10, 601, -111], [49, -255, 705]], np.float64) / 512.0
CC1 = np.array([[1041, -372, -157], [-117, 630, -1], [-4, -78, 595]], np.float64) / 512.0
CC = CC1 @ CC0
YCC = np.array([[77, 150, 29], [-43, -85, 128], [128, -107, -21]], np.float64) / 256.0

BRADFORD = np.array(
    [[0.8951,0.2664,-0.1614],[-0.7502,1.7135,0.0367],[0.0389,-0.0685,1.0296]],
    np.float64,
)
BRADFORD_INV = np.linalg.inv(BRADFORD)
D50_XY = (0.34567, 0.35850)
STANDARD_A_XY = (0.44757, 0.40745)


def xy_to_xyz(xy):
    x, y = xy
    return np.array([x/y, 1.0, (1.0-x-y)/y], np.float64)


def cie_xy(xyz):
    s = float(np.sum(xyz))
    return float(xyz[0]/s), float(xyz[1]/s)


def mccamy_cct(x, y):
    d = y - 0.1858
    if abs(d) < 1e-9:
        d = 1e-9 if d >= 0 else -1e-9
    n = (x - 0.332) / d
    return float(-449*n**3 + 3525*n**2 - 6823.3*n + 5520.33)


def bradford(white1_xy, white2_xy):
    w1 = BRADFORD @ xy_to_xyz(white1_xy)
    w2 = BRADFORD @ xy_to_xyz(white2_xy)
    ratios = np.clip(np.where(w1 > 0, w2/w1, 10.0), 0.1, 10.0)
    return BRADFORD_INV @ np.diag(ratios) @ BRADFORD


def dng_no_forward_camera_to_pcs(cm, white_xy):
    """Adobe DNG SDK no-ForwardMatrix SetWhiteXY camera->PCS transform."""
    pcs_to_camera = cm @ bradford(D50_XY, white_xy)
    reach_scale = float(np.max(pcs_to_camera @ xy_to_xyz(D50_XY)))
    pcs_to_camera = pcs_to_camera / reach_scale
    return np.linalg.inv(pcs_to_camera)


def dng_no_forward_wb_camera_to_pcs(cm, white_xy):
    camera_white = cm @ xy_to_xyz(white_xy)
    camera_white = camera_white / np.max(camera_white)
    camera_white = np.clip(camera_white, 0.001, 1.0)
    return dng_no_forward_camera_to_pcs(cm, white_xy) @ np.diag(camera_white)


def parse_exiftool(dng: Path):
    text = subprocess.check_output([
        "exiftool", "-json", "-G1", "-a", "-u", "-n",
        "-ColorMatrix1", "-ColorMatrix2", "-AsShotNeutral",
        "-CalibrationIlluminant1", "-CalibrationIlluminant2",
        "-ISO", str(dng),
    ], text=True)
    rec = json.loads(text)[0]
    def get(suffix):
        for k,v in rec.items():
            if k.split(":")[-1].lower() == suffix.lower():
                return v
        raise KeyError(suffix)
    def nums(v):
        if isinstance(v, list): return np.array(v, np.float64)
        return np.array([float(x) for x in str(v).replace(","," ").split()], np.float64)
    return {
        "cm1": nums(get("ColorMatrix1")).reshape(3,3),
        "cm2": nums(get("ColorMatrix2")).reshape(3,3),
        "neutral": nums(get("AsShotNeutral")),
        "iso": float(get("ISO")),
    }


def reciprocal_factor_from_cct(cct, t1=2856.0, t2=6504.0):
    # factor=0 selects CM1/Standard A; factor=1 selects CM2/D65.
    cct = float(np.clip(cct, min(t1,t2), max(t1,t2)))
    w1 = (1.0/cct - 1.0/t2) / (1.0/t1 - 1.0/t2)
    return float(1.0 - w1)


def solve_cm_and_white(meta):
    cm1, cm2, neutral = meta["cm1"], meta["cm2"], meta["neutral"]
    factor = 0.5
    for _ in range(30):
        cm = cm1*(1-factor) + cm2*factor
        white_xyz = np.linalg.inv(cm) @ neutral
        white_xy = cie_xy(white_xyz)
        cct = mccamy_cct(*white_xy)
        new_factor = reciprocal_factor_from_cct(cct)
        new_factor = 0.5*(new_factor + factor)
        if abs(new_factor-factor) < 1e-4:
            factor = new_factor
            break
        factor = new_factor
    cm = cm1*(1-factor) + cm2*factor
    white_xyz = np.linalg.inv(cm) @ neutral
    white_xy = cie_xy(white_xyz)
    return cm, white_xy, factor, mccamy_cct(*white_xy)


def srgb_decode(x):
    x = np.asarray(x, np.float64)
    return np.where(x <= 0.04045, x/12.92, ((x+0.055)/1.055)**2.4)


def srgb_encode(x):
    x = np.maximum(np.asarray(x, np.float64), 0.0)
    return np.where(x <= 0.0031308, 12.92*x, 1.055*np.power(x,1/2.4)-0.055)


def resize_long(img, long_side=1200, interpolation=cv2.INTER_AREA):
    h,w = img.shape[:2]
    scale = long_side/max(h,w)
    if scale >= 1: return img.copy()
    return cv2.resize(img, (round(w*scale), round(h*scale)), interpolation=interpolation)


def camera_rgb_from_raw(dng: Path):
    with rawpy.imread(str(dng)) as raw:
        pattern = raw.raw_pattern.copy() if raw.raw_pattern is not None else None
        color_desc = bytes(raw.color_desc).decode("ascii", errors="replace")
        black = list(map(float, raw.black_level_per_channel))
        white = float(raw.white_level)
        rgb16 = raw.postprocess(
            demosaic_algorithm=rawpy.DemosaicAlgorithm.LINEAR,
            use_camera_wb=False,
            use_auto_wb=False,
            user_wb=[1.0,1.0,1.0,1.0],
            no_auto_bright=True,
            output_color=rawpy.ColorSpace.raw,
            gamma=(1.0,1.0),
            output_bps=16,
            user_flip=0,
        )
    rgb = rgb16.astype(np.float64)/65535.0
    return rgb, {
        "raw_pattern": pattern.tolist() if pattern is not None else None,
        "color_desc": color_desc,
        "black_level_per_channel": black,
        "white_level": white,
        "rawpy_output_shape": list(rgb.shape),
    }


def load_jpeg_linear(jpg: Path):
    im = Image.open(jpg)
    im = ImageOps.exif_transpose(im).convert("RGB")
    arr = np.asarray(im, np.float64)/255.0
    return srgb_decode(arr), {"jpeg_shape": list(arr.shape)}


def candidate_raw_to_pre_ycc(meta):
    cm, white_xy, factor, cct = solve_cm_and_white(meta)
    scene_camera_to_pcs = dng_no_forward_camera_to_pcs(cm, white_xy)
    a_wb_camera_to_pcs = dng_no_forward_wb_camera_to_pcs(meta["cm1"], STANDARD_A_XY)
    pcs_to_a = np.linalg.inv(a_wb_camera_to_pcs)
    raw_to_pre_ycc = CC @ pcs_to_a @ scene_camera_to_pcs
    return raw_to_pre_ycc, {"factor":factor, "cct":cct, "white_xy":list(white_xy)}


def apply_matrix(img, m):
    return np.einsum("...j,ij->...i", img, m)


def alignment_transform(candidate_rgb, jpeg_linear):
    # Build gamma-encoded, robustly normalized luma previews for ECC.
    cand = np.clip(candidate_rgb, 0, None)
    y1 = np.maximum(apply_matrix(cand, YCC)[...,0], 0)
    y2 = np.maximum(apply_matrix(jpeg_linear, YCC)[...,0], 0)
    p1 = np.percentile(y1[y1>0], 99) if np.any(y1>0) else 1.0
    p2 = np.percentile(y2[y2>0], 99) if np.any(y2>0) else 1.0
    a = resize_long(np.clip(y1/max(p1,1e-9),0,1).astype(np.float32), 1000)
    b = resize_long(np.clip(y2/max(p2,1e-9),0,1).astype(np.float32), 1000)
    # Match dimensions first. Same-camera RAW/JPEG should need at most small crop/scale.
    h = min(a.shape[0], b.shape[0]); w = min(a.shape[1], b.shape[1])
    a = cv2.resize(a, (w,h), interpolation=cv2.INTER_AREA)
    b = cv2.resize(b, (w,h), interpolation=cv2.INTER_AREA)
    warp = np.eye(2,3, dtype=np.float32)
    try:
        cc, warp = cv2.findTransformECC(b, a, warp, cv2.MOTION_AFFINE,
            (cv2.TERM_CRITERIA_EPS|cv2.TERM_CRITERIA_COUNT, 100, 1e-6), None, 5)
    except cv2.error:
        cc = float("nan")
    return warp, float(cc), (w,h)


def warp_candidate(candidate, warp_small, target_shape):
    # Re-estimate scale of affine translation for full target grid. Since ECC operates
    # after both previews were resized to the same w/h, use normalized affine matrix
    # as an initial geometric approximation by applying directly to full resized data.
    h,w = target_shape[:2]
    cand_rs = cv2.resize(candidate.astype(np.float32), (w,h), interpolation=cv2.INTER_AREA)
    # The preview affine translation scales with target/preview dimensions.
    preview_w = 1000 if max(w,h) >= 1000 else max(w,h)
    # Better: infer effective preview shape from aspect ratio.
    if w >= h:
        pw = min(1000,w); ph = round(h*pw/w)
    else:
        ph = min(1000,h); pw = round(w*ph/h)
    sx = w/max(pw,1); sy = h/max(ph,1)
    warp = warp_small.copy().astype(np.float32)
    warp[0,2] *= sx; warp[1,2] *= sy
    return cv2.warpAffine(cand_rs, warp, (w,h), flags=cv2.INTER_LINEAR|cv2.WARP_INVERSE_MAP,
                          borderMode=cv2.BORDER_CONSTANT, borderValue=0)


def angular_diff_deg(a,b):
    d = (a-b+np.pi)%(2*np.pi)-np.pi
    return np.degrees(d)


def compare_chroma(candidate_rgb, jpeg_linear):
    yc = apply_matrix(candidate_rgb, YCC)
    yj = apply_matrix(jpeg_linear, YCC)
    cc = np.hypot(yc[...,1], yc[...,2])
    cj = np.hypot(yj[...,1], yj[...,2])
    ac = np.arctan2(yc[...,2], yc[...,1])
    aj = np.arctan2(yj[...,2], yj[...,1])

    # Avoid clipped/border/near-neutral pixels where angle is unstable.
    valid_rgb = np.all(candidate_rgb > 0.005, axis=-1) & np.all(candidate_rgb < 0.98, axis=-1)
    valid_jpg = np.all(jpeg_linear > 0.002, axis=-1) & np.all(jpeg_linear < 0.98, axis=-1)
    # Adaptive chroma thresholds select meaningfully colored pixels without cherry-picking hue.
    tc = max(float(np.percentile(cc[valid_rgb], 45)) if np.any(valid_rgb) else 0.01, 0.01)
    tj = max(float(np.percentile(cj[valid_jpg], 45)) if np.any(valid_jpg) else 0.01, 0.01)
    mask = valid_rgb & valid_jpg & (cc > tc) & (cj > tj)
    # Exclude a small edge margin where RAW/JPEG crops can diverge.
    h,w = mask.shape
    margin = max(8, round(min(h,w)*0.02))
    mask[:margin]=False; mask[-margin:]=False; mask[:,:margin]=False; mask[:,-margin:]=False

    diff = angular_diff_deg(ac[mask], aj[mask])
    if diff.size == 0:
        raise ValueError("no valid chroma samples after masking")
    absd = np.abs(diff)
    return {
        "valid_pixel_count": int(diff.size),
        "valid_fraction": float(diff.size/mask.size),
        "signed_angle_mean_deg": float(np.mean(diff)),
        "signed_angle_median_deg": float(np.median(diff)),
        "absolute_angle_mean_deg": float(np.mean(absd)),
        "absolute_angle_median_deg": float(np.median(absd)),
        "absolute_angle_p75_deg": float(np.percentile(absd,75)),
        "absolute_angle_p90_deg": float(np.percentile(absd,90)),
        "candidate_chroma_threshold": tc,
        "jpeg_chroma_threshold": tj,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("dng", type=Path)
    ap.add_argument("jpg", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args=ap.parse_args()

    meta=parse_exiftool(args.dng)
    raw_rgb, raw_diag=camera_rgb_from_raw(args.dng)
    jpg_lin, jpg_diag=load_jpeg_linear(args.jpg)
    m, bridge_diag=candidate_raw_to_pre_ycc(meta)
    cand=apply_matrix(raw_rgb,m)

    # First compare after simple same-grid resize. For these genuine same-camera pairs
    # dimensions/crop are expected to be very close; ECC diagnostics tell us if not.
    warp, ecc, preview_shape=alignment_transform(cand,jpg_lin)
    cand_aligned=warp_candidate(cand,warp,jpg_lin.shape)
    metrics=compare_chroma(cand_aligned,jpg_lin)

    out={
        "schema":"m11camera.r1.pixel_chroma_invariant.v1",
        "dng":args.dng.name,"jpg":args.jpg.name,"iso":meta["iso"],
        "raw":raw_diag,"jpeg":jpg_diag,"bridge":bridge_diag,
        "raw_to_pre_ycc_matrix":m.tolist(),
        "alignment":{"ecc":ecc,"preview_shape":list(preview_shape),"affine_preview":warp.tolist()},
        "chroma_angle_metrics":metrics,
        "interpretation":"Cb/Cr angle should be insensitive to RGB-scalar tone, Y-only gamma, and symmetric Standard chroma scaling; remaining error tests colour bridge/CC/order/output-domain assumptions plus demosaic/alignment error."
    }
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps(out,indent=2))

if __name__=="__main__":
    main()
