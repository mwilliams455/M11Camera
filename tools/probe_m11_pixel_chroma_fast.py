#!/usr/bin/env python3
"""Comparative, memory-efficient M11 RAW/JPEG chroma-angle probe.

Tests three colour routes on genuine matched M11 DNG/JPEG pixels:

H0  raw -> as-shot WB camera RGB -> fixed CC0/CC1
H1  raw -> DNG scene PCS -> Standard-A reference WB-camera basis -> fixed CC0/CC1
DNG raw -> DNG scene PCS -> linear sRGB baseline (no Leica CC pair)

The comparison metric is angle atan2(Cr,Cb) in the recovered Leica/BT.601-like
YCC basis after inverse JPEG OETF. That angle is invariant to:
- a common RGB scalar tone gain,
- Y-only gamma,
- symmetric Cb/Cr saturation scaling.

Thus this test can discriminate colour-basis/CC hypotheses before the full tone
and gamma tables are recovered.
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

WORK_LONG = 1400
CC0 = np.array([[495,-58,63],[10,601,-111],[49,-255,705]], np.float64)/512.0
CC1 = np.array([[1041,-372,-157],[-117,630,-1],[-4,-78,595]], np.float64)/512.0
CC = CC1 @ CC0
YCC = np.array([[77,150,29],[-43,-85,128],[128,-107,-21]], np.float64)/256.0

BRADFORD = np.array([[.8951,.2664,-.1614],[-.7502,1.7135,.0367],[.0389,-.0685,1.0296]], np.float64)
BRADFORD_INV = np.linalg.inv(BRADFORD)
D50_XY=(.34567,.35850); D65_XY=(.31271,.32902); A_XY=(.44757,.40745)
XYZ_D65_TO_SRGB=np.array([[3.2404542,-1.5371385,-.4985314],[-.969266,1.8760108,.041556],[.0556434,-.2040259,1.0572252]],np.float64)


def xy_to_xyz(xy):
    x,y=xy; return np.array([x/y,1.,(1-x-y)/y],np.float64)


def cie_xy(xyz):
    s=float(np.sum(xyz)); return float(xyz[0]/s),float(xyz[1]/s)


def cct_mccamy(x,y):
    d=y-.1858
    if abs(d)<1e-9: d=1e-9 if d>=0 else -1e-9
    n=(x-.332)/d
    return float(-449*n**3+3525*n**2-6823.3*n+5520.33)


def bradford(w1_xy,w2_xy):
    a=BRADFORD@xy_to_xyz(w1_xy); b=BRADFORD@xy_to_xyz(w2_xy)
    r=np.clip(np.where(a>0,b/a,10.),.1,10.)
    return BRADFORD_INV@np.diag(r)@BRADFORD


def camera_to_pcs(cm,white_xy):
    pcs_to_cam=cm@bradford(D50_XY,white_xy)
    scale=float(np.max(pcs_to_cam@xy_to_xyz(D50_XY)))
    return np.linalg.inv(pcs_to_cam/scale)


def camera_white(cm,white_xy):
    w=cm@xy_to_xyz(white_xy); w=w/np.max(w)
    return np.clip(w,.001,1.)


def wb_camera_to_pcs(cm,white_xy):
    return camera_to_pcs(cm,white_xy)@np.diag(camera_white(cm,white_xy))


def pcs_to_linear_srgb():
    return XYZ_D65_TO_SRGB@bradford(D50_XY,D65_XY)


def parse_nums(v):
    if isinstance(v,list): return np.asarray(v,np.float64)
    return np.asarray([float(x) for x in str(v).replace(',',' ').split()],np.float64)


def metadata(dng):
    raw=subprocess.check_output(['exiftool','-json','-G1','-a','-u','-n','-ColorMatrix1','-ColorMatrix2','-AsShotNeutral','-ISO','-ColorSpace',str(dng)],text=True)
    r=json.loads(raw)[0]
    def get(name,required=True):
        for k,v in r.items():
            if k.split(':')[-1].lower()==name.lower(): return v
        if required: raise KeyError(name)
        return None
    return {
        'cm1':parse_nums(get('ColorMatrix1')).reshape(3,3),
        'cm2':parse_nums(get('ColorMatrix2')).reshape(3,3),
        'neutral':parse_nums(get('AsShotNeutral')),
        'iso':float(get('ISO')),
        'jpeg_color_space_tag':get('ColorSpace',False),
    }


def factor_from_cct(t,t1=2856.,t2=6504.):
    t=float(np.clip(t,t1,t2)); w1=(1/t-1/t2)/(1/t1-1/t2); return 1-w1


def solve_scene(meta):
    f=.5
    for _ in range(30):
        cm=meta['cm1']*(1-f)+meta['cm2']*f
        wxyz=np.linalg.inv(cm)@meta['neutral']; xy=cie_xy(wxyz); t=cct_mccamy(*xy)
        nf=.5*(factor_from_cct(t)+f)
        if abs(nf-f)<1e-4: f=nf; break
        f=nf
    cm=meta['cm1']*(1-f)+meta['cm2']*f
    xy=cie_xy(np.linalg.inv(cm)@meta['neutral'])
    return cm,xy,f,cct_mccamy(*xy)


def route_matrices(meta):
    cm,xy,f,cct=solve_scene(meta)
    scene_cam_to_pcs=camera_to_pcs(cm,xy)
    scene_white=camera_white(cm,xy)
    a_wb_to_pcs=wb_camera_to_pcs(meta['cm1'],A_XY)
    pcs_to_a=np.linalg.inv(a_wb_to_pcs)
    return {
        'H0': CC@np.diag(1.0/scene_white),
        'H1': CC@pcs_to_a@scene_cam_to_pcs,
        'DNG': pcs_to_linear_srgb()@scene_cam_to_pcs,
    }, {'factor':f,'cct':cct,'white_xy':list(xy),'scene_camera_white':scene_white.tolist()}


def resize_array_long(a,long_side=WORK_LONG):
    h,w=a.shape[:2]; s=min(1.,long_side/max(h,w))
    if s==1: return a.copy()
    return cv2.resize(a,(round(w*s),round(h*s)),interpolation=cv2.INTER_AREA)


def read_camera_rgb(dng):
    with rawpy.imread(str(dng)) as raw:
        diag={
            'raw_pattern': raw.raw_pattern.tolist() if raw.raw_pattern is not None else None,
            'color_desc': bytes(raw.color_desc).decode('ascii','replace'),
            'black_level_per_channel':[float(x) for x in raw.black_level_per_channel],
            'white_level':float(raw.white_level),
        }
        rgb16=raw.postprocess(
            demosaic_algorithm=rawpy.DemosaicAlgorithm.LINEAR,
            half_size=True,
            use_camera_wb=False,use_auto_wb=False,user_wb=[1.,1.,1.,1.],
            no_auto_bright=True,output_color=rawpy.ColorSpace.raw,
            gamma=(1.,1.),output_bps=16,user_flip=0,
        )
        diag['rawpy_half_shape']=list(rgb16.shape)
    small=resize_array_long(rgb16,WORK_LONG)
    diag['working_shape']=list(small.shape)
    return small.astype(np.float32)*(1.0/65535.0),diag


def srgb_decode(x):
    x=np.asarray(x,np.float32)
    return np.where(x<=.04045,x/12.92,((x+.055)/1.055)**2.4).astype(np.float32)


def read_jpeg(jpg):
    im=ImageOps.exif_transpose(Image.open(jpg)).convert('RGB')
    native=(im.height,im.width,3)
    im.thumbnail((WORK_LONG,WORK_LONG),Image.Resampling.LANCZOS)
    a=np.asarray(im,np.float32)*(1.0/255.0)
    return srgb_decode(a),{'jpeg_native_shape':list(native),'working_shape':list(a.shape),'icc_profile_present':bool(im.info.get('icc_profile'))}


def apply(img,m):
    return np.einsum('...j,ij->...i',img,m.astype(np.float32),optimize=True).astype(np.float32)


def luma_preview(rgb):
    y=np.maximum(apply(rgb,YCC)[...,0],0)
    pos=y[y>0]; p=float(np.percentile(pos,99)) if pos.size else 1.
    return np.clip(y/max(p,1e-9),0,1).astype(np.float32)


def align(reference_jpg,candidate_h1):
    h,w=reference_jpg.shape[:2]
    c=cv2.resize(candidate_h1,(w,h),interpolation=cv2.INTER_AREA)
    templ=luma_preview(reference_jpg); inp=luma_preview(c)
    warp=np.eye(2,3,dtype=np.float32)
    try:
        ecc,warp=cv2.findTransformECC(templ,inp,warp,cv2.MOTION_AFFINE,
            (cv2.TERM_CRITERIA_EPS|cv2.TERM_CRITERIA_COUNT,80,1e-6),None,5)
    except cv2.error:
        ecc=float('nan')
    aligned=cv2.warpAffine(c,warp,(w,h),flags=cv2.INTER_LINEAR|cv2.WARP_INVERSE_MAP,borderMode=cv2.BORDER_CONSTANT,borderValue=0)
    return aligned,warp,float(ecc)


def warp_same(candidate,target_shape,warp):
    h,w=target_shape[:2]
    c=cv2.resize(candidate,(w,h),interpolation=cv2.INTER_AREA)
    return cv2.warpAffine(c,warp,(w,h),flags=cv2.INTER_LINEAR|cv2.WARP_INVERSE_MAP,borderMode=cv2.BORDER_CONSTANT,borderValue=0)


def angle_metrics(candidate,jpg):
    yc=apply(candidate,YCC); yj=apply(jpg,YCC)
    mc=np.hypot(yc[...,1],yc[...,2]); mj=np.hypot(yj[...,1],yj[...,2])
    ac=np.arctan2(yc[...,2],yc[...,1]); aj=np.arctan2(yj[...,2],yj[...,1])
    vc=np.all(candidate>.003,axis=-1)&np.all(candidate<.97,axis=-1)
    vj=np.all(jpg>.0015,axis=-1)&np.all(jpg<.97,axis=-1)
    tc=max(float(np.percentile(mc[vc],45)) if np.any(vc) else .01,.01)
    tj=max(float(np.percentile(mj[vj],45)) if np.any(vj) else .01,.01)
    mask=vc&vj&(mc>tc)&(mj>tj)
    h,w=mask.shape; mar=max(6,round(min(h,w)*.025))
    mask[:mar]=mask[-mar:]=False; mask[:,:mar]=mask[:,-mar:]=False
    d=(ac[mask]-aj[mask]+np.pi)%(2*np.pi)-np.pi
    deg=np.degrees(d); ad=np.abs(deg)
    if not ad.size: raise RuntimeError('no valid chroma pixels')
    return {
        'n':int(ad.size),'fraction':float(ad.size/mask.size),
        'signed_median_deg':float(np.median(deg)),
        'abs_median_deg':float(np.median(ad)),
        'abs_mean_deg':float(np.mean(ad)),
        'abs_p75_deg':float(np.percentile(ad,75)),
        'abs_p90_deg':float(np.percentile(ad,90)),
        'candidate_threshold':tc,'jpeg_threshold':tj,
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('dng',type=Path); ap.add_argument('jpg',type=Path); ap.add_argument('--out',type=Path,required=True); a=ap.parse_args()
    meta=metadata(a.dng); mats,bridge=route_matrices(meta)
    raw,rawdiag=read_camera_rgb(a.dng); jpg,jdiag=read_jpeg(a.jpg)
    routed={k:apply(raw,m) for k,m in mats.items()}
    h1_aligned,warp,ecc=align(jpg,routed['H1'])
    aligned={'H1':h1_aligned}
    for k in ('H0','DNG'): aligned[k]=warp_same(routed[k],jpg.shape,warp)
    metrics={k:angle_metrics(v,jpg) for k,v in aligned.items()}
    out={
        'schema':'m11camera.r1.pixel_chroma_invariant.comparative.v2',
        'dng':a.dng.name,'jpg':a.jpg.name,'iso':meta['iso'],'jpeg_color_space_tag':meta['jpeg_color_space_tag'],
        'raw':rawdiag,'jpeg':jdiag,'bridge':bridge,
        'alignment':{'ecc':ecc,'warp':warp.tolist()},
        'route_matrices':{k:v.tolist() for k,v in mats.items()},
        'metrics':metrics,
        'invariant':'atan2(Cr,Cb) after linearized JPEG; invariant to RGB-scalar tone, Y-only gamma, symmetric chroma scale',
    }
    a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'iso':meta['iso'],'ecc':ecc,'metrics':metrics},indent=2))

if __name__=='__main__': main()
