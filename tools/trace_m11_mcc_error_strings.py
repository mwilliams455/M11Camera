#!/usr/bin/env python3
"""Identify the closed M11-P MCC writer from its two runtime error strings.

Writer 0x01B2D324 loads runtime pointers 0x42B780E0 and 0x42B7811C,
exactly 0x3c apart. Public Milbeaut multi-axis control uses adjacent NULL and
pipe-range assertion strings. This probe finds exact/near Leica strings,
validates a single relocation delta, and reports neighboring R2Y API strings
and references to those runtime pointers.
"""
from __future__ import annotations
import argparse, hashlib, re, struct
from pathlib import Path

EXPECTED_SHA='28528c24555f93ff69b6f6f4d47f8802719d47f5ddbe1d6dcad25d1840f35e3c'
RUNTIME1=0x42B780E0
RUNTIME2=0x42B7811C

PUBLIC_VARIANTS=[
 b'im_r2y_ctrl4_multi_axis error. r2y_ctrl_multi_axis = NULL',
 b'Im_R2Y_Ctrl_Multi_Axis error. r2y_ctrl_multi_axis = NULL',
 b'Im_R2Y_Ctrl_MultiAxis error. r2y_ctrl_multi_axis = NULL',
 b'im_r2y_ctrl_multi_axis error. r2y_ctrl_multi_axis = NULL',
]
PIPE_HINTS=(b'multi_axis',b'Multi_Axis',b'MultiAxis',b'pipeNo',b'PIPE12')

def u32(d,p): return struct.unpack_from('<I',d,p)[0]

def ascii_strings(d,minlen=20):
 out=[]
 for m in re.finditer(rb'[ -~]{%d,}'%minlen,d): out.append((m.start(),m.group()))
 return out

def occurrences(d,needle):
 out=[]; p=0
 while True:
  p=d.find(needle,p)
  if p<0: return out
  out.append(p); p+=1

def a32_literal_xrefs(d,slot):
 out=[]; lo=max(0,slot-0x1010); hi=min(len(d)-4,slot+0x1010); p=(lo+3)&~3
 while p<=hi:
  w=u32(d,p); cond=(w>>28)&0xF
  if cond!=0xF and ((w>>26)&3)==1 and ((w>>25)&1)==0 and ((w>>24)&1)==1 and ((w>>21)&1)==0 and ((w>>20)&1)==1 and ((w>>16)&0xF)==0xF:
   imm=w&0xFFF; addr=p+8+imm if ((w>>23)&1) else p+8-imm
   if addr==slot: out.append(p)
  p+=4
 return out

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
 d=a.unpacked.read_bytes(); h=hashlib.sha256(d).hexdigest()
 if h!=EXPECTED_SHA: raise ValueError(h)
 strings=ascii_strings(d)

 exact=[]
 for v in PUBLIC_VARIANTS:
  exact += [(p,s) for p,s in strings if v in s]

 # Also collect any firmware string mentioning the multi-axis control or both
 # r2y and axis, because Leica may use a different capitalization/API vintage.
 semantic=[]
 for p,s in strings:
  low=s.lower()
  if (b'r2y' in low and b'axis' in low) or b'r2y_ctrl_multi' in low:
   semantic.append((p,s))

 # The two runtime pointers should map to strings exactly 0x3c apart under a
 # common relocation. Find all printable string starts with that spacing and
 # rank R2Y/control/error candidates first.
 starts={p:s for p,s in strings}
 pairs=[]
 for p,s in strings:
  q=p+(RUNTIME2-RUNTIME1)
  if q not in starts: continue
  t=starts[q]
  blob=(s+b' '+t).lower()
  score=0
  for token,w in [(b'r2y',10),(b'axis',10),(b'ctrl',5),(b'error',5),(b'null',5),(b'pipe',5)]:
   if token in blob: score+=w
  pairs.append((score,p,s,q,t))
 pairs.sort(reverse=True)

 # Validate candidate relocation deltas directly against the fixed runtime ptrs.
 validated=[]
 for score,p,s,q,t in pairs:
  delta=(RUNTIME1-p)&0xffffffff
  if ((q+delta)&0xffffffff)==RUNTIME2:
   validated.append((score,p,q,delta,s,t))

 lines=['# M11-P MCC error-string / API identity trace','',f'- unpacked SHA-256: `{h}`',
        f'- writer runtime error pointers: `0x{RUNTIME1:08x}`, `0x{RUNTIME2:08x}`',
        f'- pointer spacing: `0x{RUNTIME2-RUNTIME1:x}`','',
        '## Exact public/legacy multi-axis string hits','']
 if exact:
  for p,s in exact: lines.append(f'- `0x{p:08x}` `{s.decode("ascii","replace")}`')
 else: lines.append('- none')
 lines += ['','## Semantic R2Y multi-axis strings','']
 for p,s in semantic[:100]: lines.append(f'- `0x{p:08x}` `{s.decode("ascii","replace")}`')
 if not semantic: lines.append('- none')

 lines += ['','## Ranked printable-string pairs separated by 0x3C','']
 for score,p,q,delta,s,t in validated[:50]:
  lines += [f'### score {score} — file `0x{p:08x}` / `0x{q:08x}`',
            f'- relocation delta: `0x{delta:08x}`',
            f'- runtime check: `0x{(p+delta)&0xffffffff:08x}` / `0x{(q+delta)&0xffffffff:08x}`',
            f'- first: `{s.decode("ascii","replace")}`',f'- second: `{t.decode("ascii","replace")}`','']

 # For the best strongly semantic pair, enumerate nearby strings in the same
 # file/string region and literal slots containing the relocated addresses.
 strong=next((x for x in validated if x[0]>=20),None)
 if strong:
  score,p,q,delta,s,t=strong
  lines += ['## Best semantic pair neighborhood','',f'- chosen file starts: `0x{p:08x}`, `0x{q:08x}`',f'- relocation delta: `0x{delta:08x}`','']
  for sp,ss in strings:
   if p-0x600 <= sp <= q+0x600:
    lines.append(f'- `0x{sp:08x}` -> runtime `0x{(sp+delta)&0xffffffff:08x}` `{ss.decode("ascii","replace")}`')
  lines += ['','## Runtime-pointer literal slots / strict A32 LDR xrefs','']
  for rt,label in [(RUNTIME1,'NULL error'),(RUNTIME2,'pipe error')]:
   hits=occurrences(d,struct.pack('<I',rt))
   lines.append(f'### {label} `0x{rt:08x}` — raw slots `{len(hits)}`')
   for slot in hits[:50]:
    refs=a32_literal_xrefs(d,slot)
    lines.append(f'- slot `0x{slot:08x}` aligned `{slot%4==0}` A32 literal xrefs `{[hex(x) for x in refs]}`')

 lines += ['','## Interpretation boundary','',
          'The API identity is closed only if Leica string contents, fixed runtime-pointer spacing, and one common relocation delta agree. The dispatch/object-producer path remains separate until code/table xrefs are recovered.','']
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text('\n'.join(lines)+'\n'); print(a.output)
if __name__=='__main__': main()
