#!/usr/bin/env python3
"""Search exact M11-P firmware for CSP/R2Y semantic strings and code references.

This is a locator only. It does not alter renderer behavior. The primary goal is
to find surviving diagnostic/help strings that could disambiguate CSYKY's Y/C
endpoint or CSP placement. Exact code references to a string are reported when
the flat address is directly present; absence of such a reference is not proof
because the image also uses relocated/runtime address spaces.
"""
from __future__ import annotations

import argparse, hashlib, json, re, struct
from pathlib import Path

from extract_m11p_forensics import EXPECTED_UNPACKED_SHA

CSP_WRAPPER=0x01731970
CSP_SETTER=0x01B68B80
LOOKUP=0x0178D0A8
CORE=0x0178C89C
KEYWORDS=(
    'csy','csp','chroma','suppress','saturation','colour','color difference',
    'luminance','r2y','ycc','ycbcr','csup','cs y','mix ratio','mixing ratio'
)


def ascii_strings(data: bytes, min_len=5):
    rx=re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    for m in rx.finditer(data):
        yield m.start(),m.group().decode('ascii','replace')


def utf16le_strings(data: bytes, min_len=5):
    rx=re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)
    for m in rx.finditer(data):
        raw=m.group(); yield m.start(),raw[::2].decode('ascii','replace')


def literal_refs(data: bytes, value: int):
    pat=struct.pack('<I',value & 0xffffffff); out=[]; p=0
    while True:
        p=data.find(pat,p)
        if p<0:return out
        out.append(p); p+=1


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('unpacked',type=Path)
    ap.add_argument('--json',type=Path,required=True); ap.add_argument('--markdown',type=Path,required=True)
    a=ap.parse_args(); data=a.unpacked.read_bytes(); dig=hashlib.sha256(data).hexdigest()
    if dig!=EXPECTED_UNPACKED_SHA: raise ValueError(f'unexpected SHA {dig}')

    hits=[]
    for enc,it in [('ascii',ascii_strings(data)),('utf16le',utf16le_strings(data))]:
        for off,s in it:
            low=s.lower()
            matched=sorted({k for k in KEYWORDS if k in low})
            if matched:
                hits.append({'offset':off,'encoding':enc,'text':s[:500],'keywords':matched,
                             'literal_xrefs':literal_refs(data,off)[:100]})

    # Nearby strings can expose function/module labels even without keywords.
    nearby=[]
    for center,name in [(CSP_WRAPPER,'csp_wrapper'),(CSP_SETTER,'csp_setter'),(LOOKUP,'lookup'),(CORE,'resolver')]:
        lo=max(0,center-0x8000); hi=min(len(data),center+0x8000)
        vals=[]
        for off,s in ascii_strings(data[lo:hi],6):
            abs_off=lo+off
            vals.append({'offset':abs_off,'delta':abs_off-center,'text':s[:300]})
        nearby.append({'name':name,'center':center,'strings':vals[:1000]})

    # Also scan for exact public API spellings even if shorter/mixed case.
    tokens=['CSYKY','CSYCTL','CSYOF','CSYGA','CSYBD','Chroma Suppress','R2yCtrlCs','luminance/chroma']
    exact=[]
    for token in tokens:
        b=token.encode(); pos=[]; p=0
        while True:
            p=data.find(b,p)
            if p<0:break
            pos.append(p); p+=1
        exact.append({'token':token,'offsets':pos[:200],'count':len(pos)})

    rep={'schema':'m11camera.research.csp_strings.v1','sha256':dig,'keyword_hits':hits,
         'exact_api_token_hits':exact,'nearby_code_strings':nearby,
         'boundary':'String presence can support semantics; string absence cannot disprove them.'}
    lines=['# M11-P CSP semantic string/xref sweep','',f'- SHA-256: `{dig}`',
           f'- keyword-bearing strings: `{len(hits)}`','', '## Exact public-API token hits','',
           '| token | count | offsets |','|---|---:|---|']
    for x in exact: lines.append(f"| `{x['token']}` | {x['count']} | `{[hex(o) for o in x['offsets'][:30]]}` |")
    lines += ['', '## Keyword-bearing strings','', '| offset | encoding | keywords | direct flat-pointer xrefs | text |','|---:|---|---|---|---|']
    for x in hits[:500]:
        txt=x['text'].replace('|','\\|').replace('\n','\\n')
        lines.append(f"| `0x{x['offset']:08x}` | {x['encoding']} | `{x['keywords']}` | `{[hex(o) for o in x['literal_xrefs'][:20]]}` | {txt} |")
    for block in nearby:
        lines += ['',f"## Nearby ASCII strings: {block['name']} @ `0x{block['center']:08x}`",'', '| offset | delta | text |','|---:|---:|---|']
        for x in block['strings'][:150]:
            txt=x['text'].replace('|','\\|').replace('\n','\\n')
            lines.append(f"| `0x{x['offset']:08x}` | `{x['delta']:+#x}` | {txt} |")
    lines += ['','## Evidence boundary','',rep['boundary'],'']
    a.json.parent.mkdir(parents=True,exist_ok=True); a.markdown.parent.mkdir(parents=True,exist_ok=True)
    a.json.write_text(json.dumps(rep,indent=2)+'\n'); a.markdown.write_text('\n'.join(lines)+'\n')
    print(a.markdown)

if __name__=='__main__': main()
