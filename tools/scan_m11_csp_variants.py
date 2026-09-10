#!/usr/bin/env python3
"""Scan the exact M11-P image for R2YS databases and CSP control variants.

Goals:
1. enumerate every literal R2YS database in the unpacked image;
2. decode every Category-42 descriptor in every valid database;
3. search the whole image for conservative 44-byte R2yCtrlCs-shaped records,
   looking especially for CSYKY values other than 8 and CSYTBL=1;
4. distinguish records inside known parameter databases from unowned candidates.

The whole-image structural scan is deliberately conservative but remains a
locator, not proof that every candidate is an active CSP program.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

import numpy as np

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA, s32


def find_all(data: bytes, needle: bytes) -> list[int]:
    out=[]; p=0
    while True:
        p=data.find(needle,p)
        if p<0: return out
        out.append(p); p+=1


def parse_db_at(data: bytes, base: int):
    if base+8>len(data): return None
    size=struct.unpack_from('<I',data,base+4)[0]
    if size<0x40 or base+size>len(data): return None
    if data[base+size-4:base+size] != b'R2YE': return None
    header_pat=struct.pack('<III',1,8,315)
    h=data.find(header_pat,base+8,min(base+0x200,base+size))
    if h<0: return None
    _,_,count=struct.unpack_from('<III',data,h)
    pos=h+12; desc=[]
    try:
        for idx in range(count):
            flags,dsz,msz,mrel,cat=struct.unpack_from('<IIIII',data,pos)
            if dsz<20 or dsz%4 or pos+dsz>base+size: return None
            n=(dsz-20)//4
            deps=list(struct.unpack_from('<'+'I'*n,data,pos+20)) if n else []
            if mrel+msz>size: return None
            desc.append({
                'index':idx,'descriptor_abs':pos,'descriptor_rel':pos-base,
                'flags':flags,'descriptor_size':dsz,'map_size':msz,
                'map_offset_rel':mrel,'map_offset_abs':base+mrel,
                'category':cat,'dependencies_s32':[s32(x) for x in deps],
            })
            pos+=dsz
    except struct.error:
        return None
    if not desc: return None
    return {'base':base,'size':size,'header_abs':h,'count':count,'descriptors':desc}


def decode_cs(raw: bytes):
    if len(raw)!=44: return None
    v=struct.unpack('<22h',raw)
    return {
        'en':v[0],'ky':v[1],'tbl':v[2],
        'offset':list(v[3:7]),'gain':list(v[7:11]),'border':list(v[11:14]),
        'yrv':v[14],'crv':v[15],'cfix':v[16],
        'cb_fixed':v[17],'cr_fixed':v[18],
        'y_offset':v[19],'cb_offset':v[20],'cr_offset':v[21],
    }


def conservative_cs_shape(v) -> bool:
    if v['en'] not in (0,1) or not (0<=v['ky']<=8) or v['tbl'] not in (0,1): return False
    if any(not (0<=x<=1023) for x in v['offset']): return False
    if any(not (-1024<=x<=1023) for x in v['gain']): return False
    b=v['border']
    if any(not (0<=x<=1023) for x in b) or not (b[0]<=b[1]<=b[2]): return False
    if v['yrv'] not in (0,1) or v['crv'] not in (0,1) or v['cfix'] not in (0,1): return False
    return True


def structural_candidate_offsets(data: bytes) -> list[int]:
    """Vectorized halfword scan; excludes completely zero control windows."""
    usable=len(data)&~1
    a=np.frombuffer(memoryview(data)[:usable],dtype='<i2')
    stop=a.size-21
    out=[]
    chunk=2_000_000
    for s in range(0,stop,chunk):
        e=min(stop,s+chunk)
        en=a[s:e]; ky=a[s+1:e+1]; tbl=a[s+2:e+2]
        mask=((en==0)|(en==1)) & (ky>=0) & (ky<=8) & ((tbl==0)|(tbl==1))
        for k in range(3,7):
            x=a[s+k:e+k]; mask &= (x>=0)&(x<=1023)
        for k in range(7,11):
            x=a[s+k:e+k]; mask &= (x>=-1024)&(x<=1023)
        b0=a[s+11:e+11]; b1=a[s+12:e+12]; b2=a[s+13:e+13]
        mask &= (b0>=0)&(b0<=1023)&(b1>=b0)&(b1<=1023)&(b2>=b1)&(b2<=1023)
        for k in range(14,17):
            x=a[s+k:e+k]; mask &= ((x==0)|(x==1))
        # Zero-filled firmware naturally satisfies all width constraints. It is
        # not a useful CSP locator, so require at least one non-zero field in
        # the control portion through CFIX. Real mono survives: EN=1/KY=8.
        nonzero=np.zeros(e-s,dtype=bool)
        for k in range(17): nonzero |= a[s+k:e+k] != 0
        mask &= nonzero
        hits=np.flatnonzero(mask)
        if hits.size: out.extend(((hits+s)*2).astype(np.int64).tolist())
    return out


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True); ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); dig=hashlib.sha256(data).hexdigest()
    if dig!=EXPECTED_UNPACKED_SHA: raise ValueError(f'unexpected SHA {dig}')

    sigs=find_all(data,b'R2YS'); dbs=[]
    for base in sigs:
        db=parse_db_at(data,base)
        if db: dbs.append(db)

    owned_ranges=[(d['base'],d['base']+d['size']) for d in dbs]
    cat42=[]
    for di,db in enumerate(dbs):
        for d in db['descriptors']:
            if d['category']!=42: continue
            raw=data[d['map_offset_abs']:d['map_offset_abs']+d['map_size']]
            cs=decode_cs(raw) if d['map_size']==44 else None
            cat42.append({'db_index':di,**d,'cs':cs})

    structural=[]
    for off in structural_candidate_offsets(data):
        cs=decode_cs(data[off:off+44])
        if cs is None or not conservative_cs_shape(cs): continue
        owner=next((i for i,(lo,hi) in enumerate(owned_ranges) if lo<=off and off+44<=hi),None)
        structural.append({'offset':off,'db_index':owner,'cs':cs})

    exact_offsets={x['map_offset_abs'] for x in cat42}
    for x in structural: x['is_category42_map_start']=x['offset'] in exact_offsets

    byoff={x['offset']:x for x in structural}; families=[]; seen=set()
    for x in structural:
        o=x['offset']
        if o in seen or o-44 in byoff: continue
        run=[]; p=o
        while p in byoff:
            run.append(byoff[p]); seen.add(p); p+=44
        if len(run)>=2: families.append(run)

    interesting=[x for x in structural if x['cs']['ky']!=8 or x['cs']['tbl']!=0]
    rep={
        'sha256':dig,
        'r2ys_signature_offsets':[hex(x) for x in sigs],
        'valid_r2ys_databases':[{'base':hex(d['base']),'size':d['size'],'count':d['count']} for d in dbs],
        'category42_records':cat42,
        'category42_ky_values':sorted({x['cs']['ky'] for x in cat42 if x['cs']}),
        'category42_tbl_values':sorted({x['cs']['tbl'] for x in cat42 if x['cs']}),
        'category42_en_values':sorted({x['cs']['en'] for x in cat42 if x['cs']}),
        'structural_candidate_count':len(structural),
        'structural_ky_histogram':dict(sorted(Counter(x['cs']['ky'] for x in structural).items())),
        'structural_tbl_histogram':dict(sorted(Counter(x['cs']['tbl'] for x in structural).items())),
        'structural_candidates_non8_or_tbl1':interesting[:500],
        'contiguous_structural_families':[
            [{'offset':x['offset'],'db_index':x['db_index'],'ky':x['cs']['ky'],'tbl':x['cs']['tbl'],'en':x['cs']['en'],'offsets':x['cs']['offset'],'gains':x['cs']['gain'],'borders':x['cs']['border'],'is_category42_map_start':x['is_category42_map_start']} for x in run]
            for run in families[:200]
        ],
        'evidence_boundary':{
            'category42_records_in_valid_r2ys':'primary_firmware_structure',
            'whole_image_structural_candidates':'locator_only',
            'ky_endpoint_direction':'open','tbl_semantics':'open',
        },
    }

    lines=['# M11-P CSP variant scan','',f'- exact SHA-256: `{dig}`',f'- literal `R2YS` signatures: `{len(sigs)}`',f'- valid parsed R2YS databases: `{len(dbs)}`',f'- Category-42 records: `{len(cat42)}`','']
    for i,d in enumerate(dbs): lines.append(f"- DB {i}: base `0x{d['base']:08x}`, size `0x{d['size']:x}`, descriptors `{d['count']}`")
    lines += ['', '## Category-42 controls', '', '| DB | state/deps | map | EN | KY | TBL | offsets | gains | borders |','|---:|---|---:|---:|---:|---:|---|---|---|']
    for x in cat42:
        c=x['cs']; lines.append(f"| {x['db_index']} | `{x['dependencies_s32']}` | `0x{x['map_offset_abs']:08x}` | {c['en'] if c else '?'} | {c['ky'] if c else '?'} | {c['tbl'] if c else '?'} | `{c['offset'] if c else []}` | `{c['gain'] if c else []}` | `{c['border'] if c else []}` |")
    lines += ['', '## Category-42 invariants across every valid R2YS DB', '', f"- KY values: `{rep['category42_ky_values']}`", f"- TBL values: `{rep['category42_tbl_values']}`", f"- EN values: `{rep['category42_en_values']}`", '', '## Whole-image conservative CSP-shape scan (locator only)', '', f"- halfword-aligned non-zero structural candidates: `{len(structural)}`", f"- KY histogram: `{rep['structural_ky_histogram']}`", f"- TBL histogram: `{rep['structural_tbl_histogram']}`", f"- contiguous 44-byte candidate families (2+ records): `{len(families)}`", f"- candidates with KY != 8 or TBL = 1: `{len(interesting)}`", '']
    lines += ['### First 80 interesting structural candidates','', '| offset | DB | EN | KY | TBL | offsets | gains | borders |','|---:|---:|---:|---:|---:|---|---|---|']
    for x in interesting[:80]:
        c=x['cs']; lines.append(f"| `0x{x['offset']:08x}` | {x['db_index']} | {c['en']} | {c['ky']} | {c['tbl']} | `{c['offset']}` | `{c['gain']}` | `{c['border']}` |")
    lines += ['', '## Interpretation boundary','', 'Category-42 records decoded from valid R2YS descriptors are primary firmware parameter evidence. The whole-image 44-byte shape scan is only a locator: unrelated data can satisfy the field-width constraints. A KY/TBL variant becomes meaningful only if it is owned by a valid parameter database, belongs to a coherent contiguous control family, or can be tied to the proven CSP consumer by code/data references.','']
    a.json.parent.mkdir(parents=True,exist_ok=True); a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(rep,indent=2)+'\n'); a.markdown.write_text('\n'.join(lines)+'\n'); print(a.markdown)

if __name__=='__main__': main()
