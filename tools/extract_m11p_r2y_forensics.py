#!/usr/bin/env python3
"""Reproduce canonical M11-P 2.6.1 R2Y forensic assets.

Input is the *decompressed* 97,644,400-byte M11/M11-P firmware body produced by
``tools/decompress_m11.py``. The extractor does not contain or redistribute
Leica firmware bytes; it emits only compact numeric tables, hashes and offsets.

Primary M11-P 2.6.1 facts reproduced by this parser:
- embedded R2Y resource envelope ``R2YS ... R2YE``;
- 315 variable-size descriptors;
- descriptor map offsets are relative to the ``R2YS`` marker;
- Category 3 CC0 Q9 matrix;
- Category 13 four ISO-dependent CC1 Q9 matrices;
- Category 24 signed Y/Cb/Cr-like integer matrix;
- Category 42 saturation-dependent 44-byte maps;
- Category 5 tone configuration and Category 6 seven 1024-entry Q12 curves;
- Category 15 2048-byte fine gamma payload;
- Category 20 256-node uint16 coarse gamma table;
- 4096-point high-nibble-first gamma reconstruction.

Evidence/semantics note: table extraction and descriptor dependencies are primary
byte-level facts. Pipeline consumer order (especially gamma placement) remains a
separate reverse-engineering question and is not asserted by this extractor.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from dataclasses import dataclass, asdict
from pathlib import Path

R2YS = b"R2YS"
R2YE = b"R2YE"
EXPECTED_DESCRIPTOR_COUNT = 315
Q9 = 512
Q12 = 4096


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signed32(v: int) -> int:
    return v - 0x100000000 if v & 0x80000000 else v


@dataclass
class Descriptor:
    index: int
    descriptor_abs: int
    descriptor_rel_r2ys: int
    flags: int
    descriptor_size: int
    map_size: int
    map_offset_rel_r2ys: int
    map_offset_abs: int
    category: int
    dependencies_u32: list[int]
    dependencies_s32: list[int]

    def public(self) -> dict:
        return {
            "index": self.index,
            "descriptor_abs": self.descriptor_abs,
            "descriptor_rel_r2ys": self.descriptor_rel_r2ys,
            "flags": self.flags,
            "flags_hex": hex(self.flags),
            "descriptor_size": self.descriptor_size,
            "map_size": self.map_size,
            "map_offset_rel_r2ys": self.map_offset_rel_r2ys,
            "map_offset_abs": self.map_offset_abs,
            "category": self.category,
            "dependencies_u32": self.dependencies_u32,
            "dependencies_s32": self.dependencies_s32,
        }


def all_hits(data: bytes, pattern: bytes) -> list[int]:
    out=[]; pos=0
    while True:
        pos=data.find(pattern,pos)
        if pos<0: return out
        out.append(pos); pos+=1


def locate_r2y_resource(data: bytes) -> tuple[int,int,int,str]:
    candidates=[]
    for start in all_hits(data,R2YS):
        if start+8>len(data): continue
        envelope_size=struct.unpack_from("<I",data,start+4)[0]
        if envelope_size<32 or start+envelope_size>len(data): continue
        end_marker=start+envelope_size-4
        if data[end_marker:end_marker+4] != R2YE: continue
        # Resource path immediately follows marker+size and is NUL-terminated.
        nul=data.find(b"\x00",start+8,min(start+256,start+envelope_size))
        if nul<0: continue
        path=data[start+8:nul].decode("ascii",errors="replace")
        if path.endswith("/r2y.bin") or path=="r2y.bin":
            candidates.append((start,envelope_size,end_marker,path))
    if len(candidates)!=1:
        raise ValueError(f"expected exactly one R2YS/R2YE r2y resource, got {candidates}")
    return candidates[0]


def parse_descriptors(data: bytes, r2ys_abs: int) -> tuple[list[Descriptor],dict]:
    # In the observed embedded resource the NUL-terminated path is padded to 4
    # bytes and the R2Y database header begins at r2ys+0x18.
    header_abs=r2ys_abs+0x18
    version=struct.unpack_from("<I",data,header_abs+0x2c)[0]
    header_words=struct.unpack_from("<I",data,header_abs+0x30)[0]
    count=struct.unpack_from("<I",data,header_abs+0x34)[0]
    if count != EXPECTED_DESCRIPTOR_COUNT:
        raise ValueError(f"descriptor count {count} != {EXPECTED_DESCRIPTOR_COUNT}")

    pos=header_abs+0x38
    descs=[]
    for index in range(count):
        if pos+20>len(data): raise ValueError("descriptor table truncated")
        flags,dsize,msize,moff,category=struct.unpack_from("<IIIII",data,pos)
        if dsize<20 or dsize%4:
            raise ValueError(f"bad descriptor size {dsize} at index {index}")
        dep_count=(dsize-20)//4
        deps=list(struct.unpack_from("<"+"I"*dep_count,data,pos+20)) if dep_count else []
        map_abs=r2ys_abs+moff
        if map_abs<0 or map_abs+msize>len(data):
            raise ValueError(f"map outside firmware at descriptor {index}")
        descs.append(Descriptor(
            index=index,
            descriptor_abs=pos,
            descriptor_rel_r2ys=pos-r2ys_abs,
            flags=flags,
            descriptor_size=dsize,
            map_size=msize,
            map_offset_rel_r2ys=moff,
            map_offset_abs=map_abs,
            category=category,
            dependencies_u32=deps,
            dependencies_s32=[signed32(v) for v in deps],
        ))
        pos += dsize
    return descs, {
        "header_abs":header_abs,
        "header_rel_r2ys":header_abs-r2ys_abs,
        "version_word":version,
        "header_words_word":header_words,
        "descriptor_count":count,
        "descriptor_table_start_abs":header_abs+0x38,
        "descriptor_table_end_abs":pos,
        "descriptor_table_size":pos-(header_abs+0x38),
    }


def map_bytes(data: bytes, d: Descriptor) -> bytes:
    return data[d.map_offset_abs:d.map_offset_abs+d.map_size]


def descriptors_by_category(descs: list[Descriptor], category: int) -> list[Descriptor]:
    return [d for d in descs if d.category==category]


def write_json(path: Path, obj: dict) -> str:
    path.write_text(json.dumps(obj,indent=2)+"\n")
    return sha256(path.read_bytes())


def extract_cc0(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    ds=descriptors_by_category(descs,3)
    if len(ds)!=1 or ds[0].map_size!=42: raise ValueError("unexpected Category 3 inventory")
    d=ds[0]; raw=map_bytes(data,d)
    vals=list(struct.unpack("<21h",raw))
    matrix=vals[1:10]
    obj={
        "schema":"m11camera.forensics.category3_cc0.v1",
        "source":d.public(),
        "map_sha256":sha256(raw),
        "raw_i16":vals,
        "matrix_q9":[matrix[0:3],matrix[3:6],matrix[6:9]],
        "q_denominator":Q9,
        "matrix_byte_offset_within_map":2,
        "map_tail_i16":vals[10:],
    }
    path=outdir/"category3_CC0_candidate.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def extract_cc1(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    ds=descriptors_by_category(descs,13)
    if len(ds)!=4 or any(d.map_size!=32 for d in ds): raise ValueError("unexpected Category 13 inventory")
    bands=[]
    for d in ds:
        raw=map_bytes(data,d); vals=list(struct.unpack("<16h",raw)); m=vals[1:10]
        bands.append({
            "descriptor":d.public(),"map_sha256":sha256(raw),"raw_i16":vals,
            "matrix_q9":[m[0:3],m[3:6],m[6:9]],"q_denominator":Q9,
            "iso_range":d.dependencies_s32[:2],"tail_i16":vals[10:],
        })
    obj={"schema":"m11camera.forensics.category13_cc1.v1","bands":bands}
    path=outdir/"category13_CC1_candidate.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def extract_ycc(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    ds=descriptors_by_category(descs,24)
    if len(ds)!=1 or ds[0].map_size!=18: raise ValueError("unexpected Category 24 inventory")
    d=ds[0]; raw=map_bytes(data,d); vals=list(struct.unpack("<9h",raw))
    obj={
        "schema":"m11camera.forensics.category24_ycc.v1","descriptor":d.public(),
        "map_sha256":sha256(raw),"matrix":[vals[0:3],vals[3:6],vals[6:9]],
        "denominator":256,
    }
    path=outdir/"category24_YCC.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def extract_saturation(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    ds=descriptors_by_category(descs,42)
    if len(ds)!=8 or any(d.map_size!=44 for d in ds): raise ValueError("unexpected Category 42 inventory")
    states=[]
    for d in ds:
        raw=map_bytes(data,d); vals=list(struct.unpack("<22h",raw))
        state=d.dependencies_s32[2] if len(d.dependencies_s32)>=3 else None
        states.append({
            "state":state,"descriptor":d.public(),"map_sha256":sha256(raw),
            "raw_i16":vals,
            "saturation_field_raw_plus8":vals[4],
            "saturation_field_raw_plus10":vals[5],
        })
    obj={
        "schema":"m11camera.forensics.category42_saturation.v1",
        "dependency_flag_note":"flags 0x206 include recorded saturation dependency bit 0x200 plus common selector bits 0x6",
        "states":states,
    }
    path=outdir/"category42_saturation.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def extract_tone(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    configs=descriptors_by_category(descs,5)
    curves=descriptors_by_category(descs,6)
    if len(configs)!=7 or len(curves)!=7: raise ValueError("unexpected tone descriptor inventory")
    curve_by_state={d.dependencies_s32[0]:d for d in curves}
    config_by_state={d.dependencies_s32[0]:d for d in configs}
    states=list(range(-3,4))
    if set(curve_by_state)!=set(states): raise ValueError("tone states are not -3..+3")

    # Config maps encode the common tone luma weights and Q12 unity value.
    cfg0=map_bytes(data,config_by_state[-3])
    cfg_i16=list(struct.unpack("<29h",cfg0))
    luma_weights=cfg_i16[8:11]
    unity=cfg_i16[11]

    curves_data={}
    meta=[]
    for state in states:
        d=curve_by_state[state]; raw=map_bytes(data,d)
        vals=list(struct.unpack("<1024H",raw)); curves_data[state]=vals
        meta.append({
            "state":state,"descriptor":d.public(),"map_sha256":sha256(raw),
            "min":min(vals),"max":max(vals),"first":vals[0],"last":vals[-1],
        })

    csv_path=outdir/"tone_q12_reconstructed_curves.csv"
    with csv_path.open("w",newline="") as f:
        fields=["index","input_norm"]+[f"gain_q12_{s:+d}" for s in states]
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for i in range(1024):
            row={"index":i,"input_norm":i/1023.0}
            for s in states: row[f"gain_q12_{s:+d}"]=curves_data[s][i]
            w.writerow(row)
    obj={
        "schema":"m11camera.forensics.tone_q12.v1",
        "config_descriptor":config_by_state[-3].public(),
        "config_map_sha256":sha256(cfg0),"config_raw_i16":cfg_i16,
        "luma_weights":luma_weights,"luma_weight_denominator":sum(luma_weights),
        "q12_unity":unity,"curve_maps":meta,
        "csv":csv_path.name,"csv_sha256":sha256(csv_path.read_bytes()),
    }
    path=outdir/"tone_q12_metadata.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def reconstruct_gamma(coarse: list[int], fine: bytes, high_first: bool) -> list[int]:
    if len(coarse)!=256 or len(fine)!=2048: raise ValueError("unexpected gamma input dimensions")
    out=[]
    for group in range(256):
        acc=coarse[group]
        chunk=fine[group*8:(group+1)*8]
        nibbles=[]
        for byte in chunk:
            hi=(byte>>4)&0xF; lo=byte&0xF
            nibbles.extend((hi,lo) if high_first else (lo,hi))
        for delta in nibbles:
            out.append(acc)
            acc += delta
    return out


def gamma_metrics(vals: list[int]) -> dict:
    d1=[b-a for a,b in zip(vals,vals[1:])]
    d2=[b-a for a,b in zip(d1,d1[1:])]
    return {
        "second_difference_l1":sum(abs(x) for x in d2),
        "second_difference_rms":(sum(x*x for x in d2)/len(d2))**0.5,
        "u16le_sha256":sha256(struct.pack("<"+"H"*len(vals),*vals)),
    }


def extract_gamma(data: bytes, descs: list[Descriptor], outdir: Path) -> dict:
    fine_ds=descriptors_by_category(descs,15); coarse_ds=descriptors_by_category(descs,20)
    if len(fine_ds)!=1 or fine_ds[0].map_size!=2048: raise ValueError("unexpected Category 15 inventory")
    if len(coarse_ds)!=1 or coarse_ds[0].map_size!=512: raise ValueError("unexpected Category 20 inventory")
    fd,cd=fine_ds[0],coarse_ds[0]
    fine=map_bytes(data,fd); coarse_raw=map_bytes(data,cd)
    coarse=list(struct.unpack("<256H",coarse_raw))
    high=reconstruct_gamma(coarse,fine,True)
    low=reconstruct_gamma(coarse,fine,False)

    csv_path=outdir/"gamma_4096_high_nibble_first.csv"
    with csv_path.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["index","input_norm","output_10bit","output_norm"])
        w.writeheader()
        for i,v in enumerate(high):
            w.writerow({"index":i,"input_norm":i/4095.0,"output_10bit":v,"output_norm":v/1023.0})

    hm=gamma_metrics(high); lm=gamma_metrics(low)
    hm.update({"csv":csv_path.name,"csv_sha256":sha256(csv_path.read_bytes())})
    obj={
        "schema":"m11camera.forensics.gamma.v1",
        "coarse_descriptor":cd.public(),"coarse_sha256":sha256(coarse_raw),
        "coarse_nodes":coarse,
        "fine_descriptor":fd.public(),"fine_sha256":sha256(fine),
        "fine_payload_bytes":len(fine),
        "reconstruction":"for each of 256 groups: accumulator=coarse[group]; decode 16 nibbles from 8 bytes; append accumulator before adding each nibble",
        "high_nibble_first":hm,"low_nibble_first":lm,
    }
    path=outdir/"gamma_metadata.json"; obj["artifact_sha256"]=write_json(path,obj)
    return obj


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("unpacked",type=Path)
    ap.add_argument("--out-dir",type=Path,required=True)
    ap.add_argument("--source-firmware-sha256",help="optional SHA-256 of original .FW updater")
    ap.add_argument("--packed-body-md5",help="optional packed-body MD5 from verified updater header")
    args=ap.parse_args()

    data=args.unpacked.read_bytes(); args.out_dir.mkdir(parents=True,exist_ok=True)
    r2ys_abs,envelope_size,r2ye_abs,resource_path=locate_r2y_resource(data)
    descs,db=parse_descriptors(data,r2ys_abs)

    outputs={}
    outputs["cc0"]=extract_cc0(data,descs,args.out_dir)
    outputs["cc1"]=extract_cc1(data,descs,args.out_dir)
    outputs["ycc"]=extract_ycc(data,descs,args.out_dir)
    outputs["saturation"]=extract_saturation(data,descs,args.out_dir)
    outputs["tone"]=extract_tone(data,descs,args.out_dir)
    outputs["gamma"]=extract_gamma(data,descs,args.out_dir)

    # Inventory categories/flags without attaching semantics to unknown fields.
    category_counts={}
    flag_counts={}
    for d in descs:
        category_counts[str(d.category)]=category_counts.get(str(d.category),0)+1
        flag_counts[hex(d.flags)]=flag_counts.get(hex(d.flags),0)+1

    artifact_hashes={}
    for p in sorted(args.out_dir.iterdir()):
        if p.is_file() and p.name!="manifest.json": artifact_hashes[p.name]=sha256(p.read_bytes())

    manifest={
        "schema":"m11camera.forensics.manifest.v1",
        "source":{
            "unpacked_path_name":args.unpacked.name,
            "unpacked_size":len(data),"unpacked_sha256":sha256(data),
            "source_firmware_sha256":args.source_firmware_sha256,
            "packed_body_md5":args.packed_body_md5,
        },
        "r2y_resource":{
            "marker_start_abs":r2ys_abs,"marker_start_hex":hex(r2ys_abs),
            "envelope_size":envelope_size,"end_marker_abs":r2ye_abs,
            "end_marker_hex":hex(r2ye_abs),"resource_path":resource_path,
            "envelope_sha256":sha256(data[r2ys_abs:r2ys_abs+envelope_size]),
        },
        "database":db,
        "descriptor_category_counts":category_counts,
        "descriptor_flag_counts":flag_counts,
        "artifacts":artifact_hashes,
        "evidence_boundary":{
            "primary":"numeric map bytes, descriptor offsets/sizes/categories/dependencies, reconstructed gamma samples",
            "open":"exact runtime consumer order, gamma placement, fixed-point arithmetic/clamps/rounding outside table encodings",
        },
    }
    write_json(args.out_dir/"manifest.json",manifest)
    print(json.dumps({
        "unpacked_sha256":manifest["source"]["unpacked_sha256"],
        "r2y_start":manifest["r2y_resource"]["marker_start_hex"],
        "r2y_end":manifest["r2y_resource"]["end_marker_hex"],
        "descriptor_count":db["descriptor_count"],
        "artifacts":artifact_hashes,
    },indent=2))


if __name__=="__main__":
    main()
