#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

START=0x01000000
END=0x02000000
TARGETS={0x1AC,0x1AE,0x1B0}
DELTA=0x3FAA87D0


def ror32(v,n):
    n &= 31
    return ((v >> n) | ((v << (32-n)) & 0xffffffff)) & 0xffffffff if n else v

def dp_imm(word):
    # A32 data-processing immediate: cond | 001 | opcode | S | Rn | Rd | rot | imm8
    if ((word >> 25) & 0x7) != 0x1:
        return None
    opcode=(word >> 21) & 0xf
    if opcode not in (0x2,0x4): # SUB / ADD
        return None
    rn=(word >> 16) & 0xf; rd=(word >> 12) & 0xf
    rot=((word >> 8) & 0xf) * 2; imm=ror32(word & 0xff,rot)
    if opcode==0x2: imm=-imm
    return rn,rd,imm

def store_disp(word):
    # Return (base_reg, signed displacement, kind) for ordinary A32 STR/STRB immediate
    # and STRH immediate. Ignore post-index forms because they don't address base+disp.
    if ((word >> 26) & 0x3)==0x1 and ((word >> 25)&1)==0 and ((word >> 20)&1)==0:
        p=(word >> 24)&1
        if not p: return None
        u=(word >> 23)&1; rn=(word >> 16)&0xf; off=word & 0xfff
        return rn, off if u else -off, 'strb' if ((word>>22)&1) else 'str'
    # Extra load/store immediate. STRH has I(bit22)=1, L(bit20)=0, bits7:4=1011.
    if ((word >> 25)&0x7)==0 and ((word>>22)&1)==1 and ((word>>20)&1)==0 and ((word>>4)&0xf)==0xb:
        p=(word >> 24)&1
        if not p: return None
        u=(word >> 23)&1; rn=(word >> 16)&0xf
        off=(((word>>8)&0xf)<<4) | (word&0xf)
        return rn, off if u else -off, 'strh'
    return None

def is_push_lr(word):
    # STMDB sp!, {...,lr} aka PUSH with LR present; ignore condition bits.
    return (word & 0x0fff0000)==0x092d0000 and (word & (1<<14))!=0

def nearest_prologue(d,addr,window=0x6000):
    p=addr-START
    floor=max(0,p-window)
    for q in range(p-(p%4),floor-1,-4):
        if q+4<=len(d):
            w=struct.unpack_from('<I',d,q)[0]
            if is_push_lr(w): return START+q
    return max(START,addr-0x400)

def ascii_at(d,p,n=160):
    if not 0<=p<len(d): return None
    out=[]
    for b in d[p:p+n]:
        if b==0: break
        if b in (9,10,13) or 32<=b<127: out.append(chr(b))
        else: return None
    s=''.join(out).strip(); return s if len(s)>=5 else None

def fmt(x): return f'0x{x.address:08X}: {x.mnemonic} {x.op_str}'.rstrip()
def disasm_window(md,d,addr,before=0x80,after=0x90):
    lo=max(START,(addr-before)&~3); hi=min(END,(addr+after+3)&~3)
    return list(md.disasm(d[lo:hi],lo))

def strings_near(ins,d):
    rows=[]; seen=set()
    for i,x in enumerate(ins):
        if x.mnemonic!='movw' or len(x.operands)<2 or x.operands[1].type!=ARM_OP_IMM: continue
        reg=x.operands[0].reg; lo=x.operands[1].imm & 0xffff
        for y in ins[i+1:i+8]:
            if y.mnemonic=='movt' and len(y.operands)>=2 and y.operands[0].type==ARM_OP_REG and y.operands[0].reg==reg and y.operands[1].type==ARM_OP_IMM:
                v=((y.operands[1].imm&0xffff)<<16)|lo
                for off,label in (((v-DELTA)&0xffffffff,'translated'),(v,'raw')):
                    s=ascii_at(d,off)
                    if s and (off,s) not in seen:
                        seen.add((off,s)); rows.append((off,label,s))
                break
    return rows

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    whole=a.unpacked.read_bytes(); h=hashlib.sha256(whole).hexdigest()
    if h!=EXPECTED_UNPACKED_SHA: raise ValueError(f'unpacked SHA mismatch {h}')
    d=whole[START:END]
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True

    cand={}
    add_sites=[]
    # Pass 1: direct STR/STRB at target displacement, plus ADD/SUB-immediate bases capable
    # of reaching a target with a following <=255-byte halfword store.
    for q in range(0,len(d)-4,4):
        w=struct.unpack_from('<I',d,q)[0]; addr=START+q
        st=store_disp(w)
        if st and st[1] in TARGETS:
            cand[addr]=f'direct {st[2]} [r{st[0]}, #0x{st[1]:X}]'
        dp=dp_imm(w)
        if dp:
            rn,rd,imm=dp
            if 0 <= imm <= max(TARGETS) and any(0 <= t-imm <= 0xff for t in TARGETS):
                add_sites.append((q,rn,rd,imm))

    # Pass 2: for each relevant base materialisation inspect only the next 12 A32 words.
    for q,rn,rd,imm in add_sites:
        for r in range(q+4,min(q+4*13,len(d)-4),4):
            st=store_disp(struct.unpack_from('<I',d,r)[0])
            if not st or st[0]!=rd: continue
            eff=imm+st[1]
            if eff in TARGETS:
                cand.setdefault(START+r,
                    f'{st[2]} after base add r{rd}=r{rn}+0x{imm:X}; local disp {st[1]:+#x}; effective +0x{eff:X}')

    groups={}
    for addr,why in sorted(cand.items()):
        groups.setdefault(nearest_prologue(d,addr),[]).append((addr,why))

    L=['# M11-P B2R WB triplet writer trace','',f'- SHA: `{h}`',f'- raw A32 scan: `0x{START:08X}..0x{END:08X}`',
       f'- target frame offsets: `+0x1AC/+0x1AE/+0x1B0`',f'- relevant ADD/SUB bases: `{len(add_sites)}`',f'- candidate stores: `{len(cand)}`',f'- candidate functions: `{len(groups)}`','']
    for e,rows in sorted(groups.items()):
        L += [f'## candidate function `0x{e:08X}`',f'- stores: `{len(rows)}`','']
        # One wider disassembly around each store; bounded and cheap.
        all_strings=[]; seen_s=set()
        for addr,why in rows:
            ins=disasm_window(md,d,addr)
            hit=next((x for x in ins if x.address==addr),None)
            L += [f'### candidate `0x{addr:08X}`',f'- match: {why}','```asm']+[fmt(x) for x in ins]+['```','']
            for s in strings_near(ins,whole):
                if s not in seen_s: seen_s.add(s); all_strings.append(s)
        if all_strings:
            L += ['### nearby strings','']+[f'- {lab} `0x{off:08X}`: `{s[:150]}`' for off,lab,s in all_strings]+['']

    L += ['## Interpretation boundary','',
          'A structural offset match is not accepted as the still B2R WB producer until the candidate base is tied to the still-frame object passed through global 0x43433774, or a named AWB/WB producer is independently identified. Whole-object memcpy/copy paths will not necessarily appear here and remain the fallback if no tied writer is found.','']
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(L)+'\n'); print(a.output)
if __name__=='__main__': main()
