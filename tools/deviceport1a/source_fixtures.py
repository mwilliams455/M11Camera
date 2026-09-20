#!/usr/bin/env python3
"""Synthetic source-format checks only; no photographic fidelity claims."""
from pathlib import Path
import struct, argparse, json, hashlib, sys

def encode(t,v):
    if t==2:return v.encode('ascii')+b'\0'
    if t==1:return bytes(v)
    if t==3:return struct.pack('<'+'H'*len(v),*v)
    if t==4:return struct.pack('<'+'I'*len(v),*v)
    if t in (5,10):return b''.join(struct.pack('<ii',round(x*1000000),1000000) for x in v)
    raise ValueError(t)
def fixture(phase,white,orientation,brand,margin=0):
    w,h=48+margin*2,40+margin*2
    pixels=b''.join(struct.pack('<H',64+((x*71+y*131) % (white-64))) for y in range(h) for x in range(w))
    cm=[.8,-.1,-.1,-.4,1.4,0,-.05,.25,.6]
    tags=[(256,4,[w]),(257,4,[h]),(258,3,[16]),(259,3,[1]),(262,3,[32803]),(271,2,brand),(272,2,'DEVICEPORT1A Synthetic'),(273,4,[0]),(274,3,[orientation]),(277,3,[1]),(278,4,[h]),(279,4,[len(pixels)]),(284,3,[1]),(33421,3,[2,2]),(33422,1,[{'R':0,'G':1,'B':2}[c] for c in phase]),(34855,3,[100]),(50706,1,[1,4,0,0]),(50707,1,[1,3,0,0]),(50708,2,brand+' Synthetic Bayer'),(50713,3,[1,1]),(50714,4,[64]),(50717,4,[white]),(50721,10,cm),(50727,5,[1,1,1]),(50728,5,[.4,1,.6]),(50778,3,[21]),(50829,4,[margin,margin,h-margin,w-margin])]
    tags.sort();end=8+2+12*len(tags)+4;extra=bytearray();entries=[]
    for tag,t,v in tags:
        d=encode(t,v);n=len(d)//{1:1,2:1,3:2,4:4,5:8,10:8}[t]
        if len(d)<=4:f=d.ljust(4,b'\0')
        else:
            if (end+len(extra))%2:extra+=b'\0'
            f=struct.pack('<I',end+len(extra));extra+=d
        entries.append([tag,t,n,f])
    offset=end+len(extra)
    for e in entries:
        if e[0]==273:e[3]=struct.pack('<I',offset)
    return b'II'+struct.pack('<HIH',42,8,len(tags))+b''.join(struct.pack('<HHI',*e[:3])+e[3] for e in entries)+bytes(4)+extra+pixels

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--decode',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    rows=[]
    for i,phase in enumerate(['RGGB','GRBG','GBRG','BGGR']):
        for j,white in enumerate([1023,4095,16383,65535]):
            orientation=(i*4+j)%8+1;name=f'{phase}_{white}_o{orientation}.dng';path=a.out/name
            path.write_bytes(fixture(phase,white,orientation,'SyntheticVendor',2 if j%2 else 0))
            rows.append({'file':name,'phase':phase,'white':white,'orientation':orientation,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    if a.decode:
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from dump_m11_rawpy_pixel_parity import frozen_params
        import rawpy,numpy as np
        assert rawpy.__version__=='0.27.1' and tuple(rawpy.libraw_version)==(0,22,1)
        for row in rows:
            with rawpy.imread(str(a.out/row['file'])) as raw:
                sizes=raw.sizes;out=raw.postprocess(params=frozen_params())
                exp=(48,40,3) if row['orientation'] in (5,6,7,8) else (40,48,3)
                assert out.shape==exp,(row,out.shape,exp,sizes)
                assert out.dtype==np.uint16
                row.update({'decoded':True,'outputShape':list(out.shape),'activeWidth':sizes.width,'activeHeight':sizes.height,'top':sizes.top_margin,'left':sizes.left_margin})
        variants=[]
        for brand in ('SyntheticVendorA','SyntheticVendorB'):
            path=a.out/(brand+'.dng');path.write_bytes(fixture('RGGB',4095,1,brand))
            with rawpy.imread(str(path)) as raw:variants.append(raw.postprocess(params=frozen_params()))
        assert np.array_equal(*variants)
    (a.out/'source_fixture_results.json').write_text(json.dumps({'syntheticOnly':True,'photographicValidation':False,'decodeExecuted':a.decode,'fixtures':rows},indent=2)+'\n')
    print(f'DEVICEPORT1A synthetic DNG fixtures: {len(rows)}; LibRaw decode executed: {a.decode}')
if __name__=='__main__':main()
