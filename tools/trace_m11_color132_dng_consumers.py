#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, re, struct
from collections import defaultdict
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000; END=0x02000000
DELTA=0x3FAA87D0
COLOR=0x002C9A98
CM1=[2358,-546,-66,-2488,6300,1785,-403,797,3504]
CM2=[1700,-326,-200,-2354,5409,974,-612,976,2276]
EXTRA=[212,-165,-71,-73,676,85,-27,174,285]
TERMS=(
    'colormatrix','color matrix','colour matrix','calibrationilluminant','calibration illuminant',
    'asshotneutral','as shot neutral','dng','colorspec','color spec','colour spec','whitebalance',
    'white balance','illuminant','cct','chromatic adaptation','camera calibration','cameracalibration',
    'forwardmatrix','forward matrix','profilecalibration','profile calibration'
)

def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def sx(v,b):s=1<<(b-1);return (v^s)-s
def bt(a,w):
    if ((w>>25)&7)!=5 or ((w>>24)&1)!=1:return None
    return (a+8+sx(w&0xffffff,24)*4)&0xffffffff
def callers(code,t):return [START+q for q in range(0,len(code)-4,4) if bt(START+q,u32(code,q))==t]
def ispush(w):return (w&0x0fff0000)==0x092d0000 and (w&(1<<14))!=0
def pro(code,a,win=0x12000):
    q=a-START
    for p in range(q-(q%4),max(-1,q-win),-4):
        if p>=0 and p+4<=len(code) and ispush(u32(code,p)):return START+p
    return max(START,a-0x800)
def dis(md,code,lo,hi):
    lo=max(START,lo&~3);hi=min(END,(hi+3)&~3);return list(md.disasm(code[lo-START:hi-START],lo))
def fmt(i):return f'0x{i.address:08X}: {i.mnemonic} {i.op_str}'.rstrip()
def decode_mov16(w,kind):
    tag=w&0x0ff00000;want=0x03000000 if kind=='movw' else 0x03400000
    if tag!=want:return None
    return (w>>12)&0xf,(((w>>4)&0xf000)|(w&0xfff))
def movrefs(code,target):
    out=[]
    for q in range(0,len(code)-4,4):
        m=decode_mov16(u32(code,q),'movw')
        if not m:continue
        rd,lo=m
        for r in range(q+4,min(q+36,len(code)-3),4):
            mt=decode_mov16(u32(code,r),'movt')
            if mt and mt[0]==rd:
                if ((mt[1]<<16)|lo)==target:out.append((START+q,START+r,rd))
                break
    return out
def ascii_strings(d,minlen=5):
    for m in re.finditer(rb'[\x20-\x7e]{%d,}\x00'%minlen,d):
        yield m.start(),m.group()[:-1].decode('ascii','replace')
def refs_to_runtime_string(code,file_off):
    return movrefs(code,(file_off+DELTA)&0xffffffff)
def patt32(vals):return b''.join(struct.pack('<i',x) for x in vals)
def nearest_string_context(allstr,p,n=8):
    rows=sorted(allstr,key=lambda x:abs(x[0]-p))[:n]
    return sorted(rows)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('unpacked',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    d=a.unpacked.read_bytes();h=hashlib.sha256(d).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA:raise ValueError(h)
    code=d[START:END];md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);md.detail=True;md.skipdata=True
    allstr=list(ascii_strings(d,5))
    matches=[]
    for p,s in allstr:
        sl=s.lower()
        if any(t in sl for t in TERMS):matches.append((p,s))
    L=['# M11-P COLOR132 DNG / ColorSpec consumer trace','',f'- SHA: `{h}`',f'- COLOR132: `0x{COLOR:08X}`','',
       '## Exact matrix signature occurrences','']
    for name,vals in (('CM1',CM1),('CM2',CM2),('EXTRA',EXTRA)):
        hs=[];p=0;n=patt32(vals)
        while True:
            p=d.find(n,p)
            if p<0:break
            hs.append(p);p+=1
        L += [f'- {name}: `{[hex(x) for x in hs]}`']
    L += ['','## Candidate DNG / colour-management strings and code xrefs','']
    xref_funcs=defaultdict(list)
    for p,s in matches:
        rr=refs_to_runtime_string(code,p)
        if not rr:continue
        L += [f'### string `0x{p:08X}` `{s}`',f'- runtime `0x{p+DELTA:08X}`',f'- MOVW/MOVT refs: `{[(hex(x),hex(y),r) for x,y,r in rr]}`','']
        for x,y,r in rr:
            e=pro(code,x);xref_funcs[e].append((p,s,x,y))
    L += ['## Functions referencing candidate DNG / colour strings','']
    for e,refs in sorted(xref_funcs.items()):
        lo=min(x for _,_,x,_ in refs);hi=max(y for _,_,_,y in refs)
        ins=dis(md,code,max(e,lo-0x100),hi+0x300)
        L += [f'### function `0x{e:08X}`',f'- strings: `{[(hex(p),s) for p,s,_,_ in refs]}`',f'- direct callers: `{[hex(x) for x in callers(code,e)[:80]]}`','```asm']+[fmt(x) for x in ins]+['```','']
    # Try direct candidate runtime/file mappings for each record and offsets.
    L += ['## Direct pointer/reference probes for COLOR132 records','']
    for delta_name,delta in (('runtime-string-affine',DELTA),('raw-file',0)):
        L += [f'### mapping {delta_name} `+0x{delta:08X}`']
        for off,label in ((0,'CM1'),(0x2c,'CM2'),(0x58,'EXTRA'),(0x24,'marker1'),(0x28,'temp1'),(0x50,'marker2'),(0x54,'temp2'),(0x7c,'marker3'),(0x80,'temp3')):
            t=(COLOR+off+delta)&0xffffffff
            rr=movrefs(code,t)
            lit=[];needle=struct.pack('<I',t);q=0
            while True:
                q=d.find(needle,q)
                if q<0:break
                if START<=q<END and q%4==0:lit.append(q)
                q+=1
            if rr or lit:L += [f'- {label} target `0x{t:08X}` MOV refs `{[(hex(x),hex(y),r) for x,y,r in rr]}` code literals `{[hex(x) for x in lit[:100]]}`']
        L += ['']
    # Integer constants CCTs and 44-byte stride in functions that have colour/DNG strings.
    L += ['## 2850 / 6807 / 0x2C evidence inside DNG-colour functions','']
    for e,refs in sorted(xref_funcs.items()):
        ins=dis(md,code,e,min(END,e+0x1200));hits=[]
        for x in ins:
            if x.id==0:continue
            for op in x.operands:
                if op.type==ARM_OP_IMM and (op.imm&0xffffffff) in (2850,6807,0x2c,0x58,0x80,12):
                    hits.append(fmt(x));break
        if hits:L += [f'### function `0x{e:08X}`']+[f'- `{x}`' for x in hits]+['']
    # Semantic string-only census, including unreferenced strings for names/functions.
    L += ['## Full matching-string census','']
    for p,s in matches:L += [f'- `0x{p:08X}` `{s}`']
    L += ['','## Interpretation boundary','',
          'Exact CM1/CM2 presence is calibration evidence, not rendering placement. A DNG/metadata-only conclusion requires tying COLOR132 fields to DNG writer/tag code and finding no image-formation consumer; a rendering conclusion requires explicit dataflow from the same object into B2R/R2Y/ColorSpec pixel processing. String proximity alone is not accepted.','']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text('\n'.join(L)+'\n');print(a.output)
if __name__=='__main__':main()
