#!/usr/bin/env python3
"""Infer flat-image relocation deltas and ARM literal xrefs in M11-P 2.6.1.

This helper is deliberately forensic-only. It accepts the exact decompressed
firmware and emits derived address/disassembly metadata, never firmware bytes.

For a flat binary loaded at a fixed address, every embedded pointer to a string
obeys runtime_pointer - firmware_offset = constant K. We solve for K using many
independent diagnostic strings in the same bounded raw-image region, then look
for ARM/Thumb PC-relative loads of the recovered pointer literals.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA = "28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c"
MASK32 = 0xFFFFFFFF

GROUPS = {
    "leica_selector": [
        b"(r2y) R2Y GAMMA already loaded",
        b"NO VALID STRING   img_macro_drv_r2y_select_gamma_paraset",
        b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 2",
        b"---ERROR---   img_macro_drv_r2y_select_gamma_paraset 3",
        b"-----ERROR------   img_macro_drv_r2y_select_gamma_paraset RGBYB TABLE 1",
        b"(r2y) R2Y YC already loaded",
        b"NO VALID STRING:  E_IMG_MACRO_DRV_R2Y_CATEGORY_YC_R2Y6A  img_macro_drv_r2y_select_yc_paraset YC",
        b"NO VALID STRING: E_IMG_MACRO_DRV_R2Y_CATEGORY_YBlend_R2Y6A  img_macro_drv_r2y_select_yc_paraset  BLEND",
        b"(r2y) R2Y ToneTable already loaded",
        b"NO VALID STRING   img_macro_drv_r2y_select_colorcorrection1_paraset",
    ],
    "milbeaut_driver": [
        b"Im_R2Y_Ctrl_Gamma error. r2y_ctrl_gamma = NULL",
        b"Im_R2Y_Ctrl_Gamma error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Set_GammaTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Set_GammaYbTblAccessEnable error. pipe_no>D_IM_R2Y_PIPE12",
        b"Im_R2Y_Ctrl_CC1_Matrix error. r2y_ctrl_cc = NULL",
        b"Im_R2Y_Ctrl_Yc_Convert error. r2y_ctrl_ycc = NULL",
        b"Im_R2Y_Ctrl_Ynr error. r2y_ctrl_ynr = NULL",
        b"Im_R2Y_Ctrl_Color_NR error. r2y_ctrl_clpf = NULL",
        b"Im_R2Y_Ctrl_Chroma_Suppress error. r2y_ctrl_cs = NULL",
        b"Im_R2Y_Set_Gamma_Table error. tbl_index > 4",
    ],
}


def all_hits(data: bytes, needle: bytes) -> list[int]:
    out=[]; p=0
    while True:
        p=data.find(needle,p)
        if p<0: return out
        out.append(p); p+=1


def nearest_fill(data: bytes, center: int, direction: int, min_run: int=256, limit: int=0x400000) -> tuple[int,int] | None:
    # Prefer zero fill for these two observed raw-image regions, then FF.
    for byte in (0,255):
        pat=bytes([byte])*min_run
        if direction<0:
            p=data.rfind(pat,max(0,center-limit),center)
        else:
            p=data.find(pat,center,min(len(data),center+limit))
        if p<0: continue
        a=p; b=p+min_run
        while a>0 and data[a-1]==byte: a-=1
        while b<len(data) and data[b]==byte: b+=1
        return a,b
    return None


def bounded_region(data: bytes, center: int) -> tuple[int,int,str]:
    before=nearest_fill(data,center,-1)
    after=nearest_fill(data,center,1)
    if not before or not after:
        return max(0,center-0x100000),min(len(data),center+0x100000),"fallback ±1MiB"
    return before[1],after[0],f"between fill runs {before[0]:#x}..{before[1]:#x} and {after[0]:#x}..{after[1]:#x}"


def collect_aligned_words(data: bytes, start: int, end: int) -> tuple[dict[int,list[int]],set[int]]:
    positions: dict[int,list[int]] = {}
    p=(start+3)&~3
    while p+4<=end:
        v=struct.unpack_from('<I',data,p)[0]
        lst=positions.setdefault(v,[])
        if len(lst)<16: lst.append(p)
        p+=4
    return positions,set(positions)


def infer_candidates(wordset: set[int], targets: list[int], topn: int=16) -> list[tuple[int,int,list[int]]]:
    # Count how many distinct target strings can be explained by one relocation K.
    counts=collections.Counter()
    # Use each target independently; wordset is unique so one target contributes at most once per K.
    for t in targets:
        for v in wordset:
            counts[(v-t)&MASK32]+=1
    out=[]
    for k,n in counts.most_common(topn*8):
        if n<2: break
        supported=[t for t in targets if ((t+k)&MASK32) in wordset]
        out.append((k,len(supported),supported))
    out.sort(key=lambda x:(-x[1], x[0]&0xFFF != 0, x[0]))
    return out[:topn]


def arm_literal_refs(data: bytes, start: int, end: int, literal_off: int) -> list[tuple[int,str]]:
    refs=[]
    # ARM/A32 LDR Rt,[pc,+/-imm12]. Flat relocation cancels because PC and literal share K.
    p=(start+3)&~3
    while p+4<=end:
        w=struct.unpack_from('<I',data,p)[0]
        if ((w>>26)&0x3)==0x1 and ((w>>25)&1)==0 and ((w>>24)&1)==1 and ((w>>20)&1)==1 and ((w>>16)&0xF)==0xF:
            imm=w&0xFFF; u=(w>>23)&1
            addr=p+8+imm if u else p+8-imm
            if addr==literal_off:
                refs.append((p,"ARM LDR literal"))
        p+=4
    # Thumb-1 LDR literal: 01001 Rt imm8.
    p=(start+1)&~1
    while p+2<=end:
        h=struct.unpack_from('<H',data,p)[0]
        if (h&0xF800)==0x4800:
            imm=(h&0xFF)*4
            addr=((p+4)&~3)+imm
            if addr==literal_off:
                refs.append((p,"Thumb16 LDR literal"))
        p+=2
    refs.sort()
    return refs[:64]


def disasm(data: bytes, off: int, thumb: bool) -> str:
    try:
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
    except Exception:
        return "capstone unavailable"
    mode=(CS_MODE_THUMB if thumb else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN
    md=Cs(CS_ARCH_ARM,mode)
    lo=max(0,off-48); hi=min(len(data),off+96)
    ins=list(md.disasm(data[lo:hi],lo))
    near=[i for i in ins if off-36<=i.address<=off+72]
    return "; ".join(f"{i.address:#x}:{i.mnemonic} {i.op_str}" for i in near[:36])


def run_group(data: bytes, name: str, needles: list[bytes]) -> list[str]:
    rows=[]
    target_pairs=[]
    for n in needles:
        hs=all_hits(data,n)
        if len(hs)==1:
            target_pairs.append((n.decode('ascii',errors='replace'),hs[0]))
        else:
            rows.append(f"- target `{n.decode('ascii',errors='replace')}` has {len(hs)} hits; excluded from relocation solve")
    if len(target_pairs)<3:
        return [f"### {name}","",*rows,"","Insufficient unique targets.",""]
    center=target_pairs[0][1]
    start,end,bnote=bounded_region(data,center)
    positions,wordset=collect_aligned_words(data,start,end)
    candidates=infer_candidates(wordset,[x[1] for x in target_pairs])
    lines=[f"### {name}","",f"- raw region: `0x{start:08x}..0x{end:08x}` ({end-start} bytes), {bnote}",f"- region SHA-256: `{hashlib.sha256(data[start:end]).hexdigest()}`",f"- unique 32-bit aligned words: `{len(wordset)}`",f"- unique diagnostic targets used: `{len(target_pairs)}`",""]
    lines.extend(rows)
    lines.append("Target offsets:")
    for label,t in target_pairs:
        lines.append(f"- `0x{t:08x}` — `{label}`")
    lines += ["","Relocation candidates:"]
    if not candidates:
        lines.append("- no K supported by >=2 independent target strings")
        lines.append("")
        return lines
    label_by_off={off:label for label,off in target_pairs}
    for rank,(k,support,supported) in enumerate(candidates[:8],1):
        load=(start+k)&MASK32
        lines.append(f"- #{rank}: `K=0x{k:08x}`; support `{support}/{len(target_pairs)}`; implied region load base `0x{load:08x}`")
        for t in supported:
            ptr=(t+k)&MASK32
            slots=positions.get(ptr,[])
            lines.append(f"  - `{label_by_off[t]}` -> runtime `0x{ptr:08x}`, literal slot(s) {', '.join(f'0x{x:08x}' for x in slots) if slots else 'none'}")
            for slot in slots[:6]:
                refs=arm_literal_refs(data,start,end,slot)
                for roff,kind in refs[:12]:
                    lines.append(f"    - code xref candidate `{kind}` at `0x{roff:08x}` -> literal `0x{slot:08x}`")
                    lines.append(f"      - disasm: `{disasm(data,roff,'Thumb' in kind)}`")
        lines.append("")
    return lines


def report(data: bytes) -> str:
    digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED_SHA: raise ValueError(f"unexpected unpacked SHA-256 {digest}")
    lines=["# M11-P flat-image relocation / xref inference","", "Evidence state: **derived directly from exact M11-P 2.6.1 unpacked firmware**.","",f"- unpacked SHA-256: `{digest}`","", "## Results",""]
    for name,needles in GROUPS.items():
        lines.extend(run_group(data,name,needles))
    lines += ["## Interpretation boundary","", "A repeated relocation delta supported by multiple independent strings is strong flat-image mapping evidence. A PC-relative LDR landing on one of those recovered pointer literals is an instruction-level xref candidate. Function identity and call arguments still require control-flow inspection; no renderer behavior should change from relocation evidence alone.",""]
    return '\n'.join(lines)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    data=a.unpacked.read_bytes(); text=report(data); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(text+'\n'); print(f"wrote {a.output}")

if __name__=='__main__': main()
