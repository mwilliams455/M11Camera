#!/usr/bin/env python3
"""One-shot M11 gamma-placement A/B against matched Leica DNG/JPEG pairs.

This is deliberately bounded and does NOT modify the canonical renderer.

Shared path:
  M11 RAW -> DNG scene PCS -> Standard-A WB camera basis -> CC0 -> Standard tone

A (current provisional model):
  -> CC1 -> Leica YC -> Cat15/20 gamma on Y -> inverse YC

B (Milbeaut hardware-order candidate):
  -> Cat15/20 gamma applied component-wise as RGB-common -> CC1

The comparison metric is Leica-YC chroma hue against the ICC-managed linearized
camera JPEG. It is scale/chroma-magnitude insensitive, so the still-open exact
Category-42 chroma-suppress implementation is intentionally excluded. No matrix,
gamma, exposure, tone, or per-scene parameter is fitted.

Decision is directional only, not firmware proof. A paired sign test across the
12 scenes is reported; >=10 wins with two-sided p<=0.05 is called directional.
"""
from __future__ import annotations

import argparse, csv, json, math
from pathlib import Path

import cv2
import numpy as np

import jpeg_icc_srgb
import probe_m11_pixel_chroma_fast as base

base.read_jpeg = lambda p: jpeg_icc_srgb.read_jpeg_icc_to_linear_srgb(p, work_long=base.WORK_LONG)

TONE_Y = np.array([77.0, 149.0, 29.0], np.float64) / 255.0


def apply(img, m):
    return np.einsum('...j,ij->...i', img, np.asarray(m, np.float64), optimize=True).astype(np.float32)


def load_tables(forensics: Path):
    with (forensics/'tone_q12_reconstructed_curves.csv').open(newline='') as f:
        rows=list(csv.DictReader(f))
    tx=np.array([float(r['input_norm']) for r in rows],np.float64)
    tg=np.array([float(r['gain_q12_+0'])/4096.0 for r in rows],np.float64)
    with (forensics/'gamma_4096_high_nibble_first.csv').open(newline='') as f:
        rows=list(csv.DictReader(f))
    gx=np.array([float(r['input_norm']) for r in rows],np.float64)
    gy=np.array([float(r['output_norm']) for r in rows],np.float64)
    return tx,tg,gx,gy


def standard_a_bridge(meta):
    cm,xy,_,_=base.solve_scene(meta)
    scene_cam_to_pcs=base.camera_to_pcs(cm,xy)
    a_wb_to_pcs=base.wb_camera_to_pcs(meta['cm1'],base.A_XY)
    return np.linalg.inv(a_wb_to_pcs)@scene_cam_to_pcs


def tone_standard(rgb,tx,tg):
    y=np.einsum('...j,j->...',rgb.astype(np.float64),TONE_Y)
    g=np.interp(np.clip(y,0.0,1.0),tx,tg)
    g=np.where(y>0.0,g,1.0)
    return (rgb.astype(np.float64)*g[...,None]).astype(np.float32)


def gamma_interp(x,gx,gy):
    return np.interp(np.clip(np.asarray(x,np.float64),0.0,1.0),gx,gy).astype(np.float32)


def render_a(pre,gx,gy):
    cc1=apply(pre,base.CC1)
    ycc=apply(cc1,base.YCC)
    ycc[...,0]=gamma_interp(ycc[...,0],gx,gy)
    return apply(ycc,np.linalg.inv(base.YCC))


def render_b(pre,gx,gy):
    common=gamma_interp(pre,gx,gy)
    return apply(common,base.CC1)


def warp(img,target_shape,mat):
    h,w=target_shape[:2]
    r=cv2.resize(img.astype(np.float32),(w,h),interpolation=cv2.INTER_AREA)
    return cv2.warpAffine(r,mat,(w,h),flags=cv2.INTER_LINEAR|cv2.WARP_INVERSE_MAP,
                          borderMode=cv2.BORDER_CONSTANT,borderValue=0)


def common_hue_metrics(a,b,jpg):
    ya=apply(a,base.YCC); yb=apply(b,base.YCC); yj=apply(jpg,base.YCC)
    ca=np.hypot(ya[...,1],ya[...,2]); cb=np.hypot(yb[...,1],yb[...,2]); cj=np.hypot(yj[...,1],yj[...,2])
    ha=np.arctan2(ya[...,2],ya[...,1]); hb=np.arctan2(yb[...,2],yb[...,1]); hj=np.arctan2(yj[...,2],yj[...,1])
    valid=(np.all(a>.002,axis=-1)&np.all(a<.98,axis=-1)&
           np.all(b>.002,axis=-1)&np.all(b<.98,axis=-1)&
           np.all(jpg>.0015,axis=-1)&np.all(jpg<.97,axis=-1)&
           (ca>.008)&(cb>.008)&(cj>.008))
    h,w=valid.shape; mar=max(6,round(min(h,w)*.025))
    valid[:mar]=False; valid[-mar:]=False; valid[:,:mar]=False; valid[:,-mar:]=False
    lum=yj[...,0].astype(np.float32)
    gx=cv2.Sobel(lum,cv2.CV_32F,1,0,ksize=3); gy=cv2.Sobel(lum,cv2.CV_32F,0,1,ksize=3)
    grad=np.hypot(gx,gy); finite=grad[np.isfinite(grad)]
    cut=float(np.percentile(finite,70)) if finite.size else math.inf
    valid &= grad<=cut
    if np.count_nonzero(valid)<1000: raise RuntimeError('too few common comparison pixels')
    def residual(h):
        d=(h[valid]-hj[valid]+np.pi)%(2*np.pi)-np.pi
        ad=np.abs(np.degrees(d))
        return {'n':int(ad.size),'median_abs_deg':float(np.median(ad)),
                'mean_abs_deg':float(np.mean(ad)),'p75_abs_deg':float(np.percentile(ad,75)),
                'p90_abs_deg':float(np.percentile(ad,90))}
    return residual(ha),residual(hb),cut


def sign_p_two_sided(a_wins,b_wins):
    n=a_wins+b_wins
    if n==0:return 1.0
    k=min(a_wins,b_wins)
    p=2.0*sum(math.comb(n,i) for i in range(k+1))/(2.0**n)
    return min(1.0,p)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dir',type=Path,required=True);ap.add_argument('--forensics',type=Path,required=True)
    ap.add_argument('--pairs',nargs='+',required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    tx,tg,gamx,gamy=load_tables(a.forensics)
    rows=[]
    for n in a.pairs:
        dng=a.dir/f'leica_m11_{n}.dng'; jpgp=a.dir/f'leica_m11_{n}.jpg'
        meta=base.metadata(dng); raw,_=base.read_camera_rgb(dng); jpg,_=base.read_jpeg(jpgp)
        bridge=standard_a_bridge(meta)
        basis=apply(raw,bridge); cc0=apply(basis,base.CC0); pre=tone_standard(cc0,tx,tg)
        ra=render_a(pre,gamx,gamy); rb=render_b(pre,gamx,gamy)
        h1=apply(raw,base.route_matrices(meta)[0]['H1'])
        _,wm,ecc,ok=base.align(jpg,h1)
        if not ok:
            rows.append({'pair':n,'iso':meta['iso'],'valid':False,'ecc':ecc});continue
        wa=warp(ra,jpg.shape,wm); wb=warp(rb,jpg.shape,wm)
        ma,mb,cut=common_hue_metrics(wa,wb,jpg)
        delta=ma['median_abs_deg']-mb['median_abs_deg']
        row={'pair':n,'iso':meta['iso'],'valid':True,'ecc':ecc,'gradient_cut':cut,
             'A_y_after_yc':ma,'B_rgb_before_cc1':mb,'A_minus_B_median_abs_deg':delta,
             'winner':'B' if delta>0 else ('A' if delta<0 else 'tie')}
        rows.append(row)
        print(n,'ISO',meta['iso'],'ECC',round(ecc,4),'A',round(ma['median_abs_deg'],4),'B',round(mb['median_abs_deg'],4),'winner',row['winner'],flush=True)
    v=[r for r in rows if r.get('valid')]
    aw=sum(r['winner']=='A' for r in v);bw=sum(r['winner']=='B' for r in v);ties=sum(r['winner']=='tie' for r in v)
    am=np.array([r['A_y_after_yc']['median_abs_deg'] for r in v]);bm=np.array([r['B_rgb_before_cc1']['median_abs_deg'] for r in v])
    p=sign_p_two_sided(aw,bw)
    direction='inconclusive'
    if bw>=10 and p<=.05 and np.median(bm)<np.median(am):direction='B_rgb_before_cc1_directionally_supported'
    elif aw>=10 and p<=.05 and np.median(am)<np.median(bm):direction='A_y_after_yc_directionally_supported'
    result={'schema':'m11camera.r2.gamma_placement_ab.v1','policy':'single bounded A/B; no fitted parameters; directional evidence only; renderer unchanged',
            'A':'CC0 -> Standard tone -> CC1 -> YC -> Cat15/20 gamma(Y) -> inverse YC',
            'B':'CC0 -> Standard tone -> Cat15/20 gamma(RGB-common component-wise) -> CC1',
            'metric':'paired common-mask Leica-YC chroma hue residual against ICC-managed linear Leica JPEG',
            'valid_pairs':len(v),'total_pairs':len(rows),'wins_A':aw,'wins_B':bw,'ties':ties,'sign_test_two_sided_p':p,
            'median_pair_median_abs_hue_A_deg':float(np.median(am)) if len(am) else None,
            'median_pair_median_abs_hue_B_deg':float(np.median(bm)) if len(bm) else None,
            'median_A_minus_B_deg':float(np.median(am-bm)) if len(am) else None,
            'decision':direction,'pairs':rows}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('\nDECISION',direction,'wins A/B/tie',aw,bw,ties,'p',p,'median A/B',result['median_pair_median_abs_hue_A_deg'],result['median_pair_median_abs_hue_B_deg'])
if __name__=='__main__':main()
