#!/usr/bin/env python3
"""Reconstruct old output from hash-pinned JNI; compare photo-only production.
Only synthetic pixels in CI. Private DNG replay remains local.
"""
from pathlib import Path
import hashlib,struct,subprocess,json
root=Path.cwd();work=root/'work/perf1a';work.mkdir(parents=True,exist_ok=True)
s=(work/'legacy_jni.cpp').read_text()
assert hashlib.sha256(s.encode()).hexdigest()=='e216df93b1965378e71f935e6a9b8580a4cb343c8ff532ed87cc949955bba049'
asset=(root/'app/src/main/assets/m11_reference_tables_v1.bin').read_bytes()
assert hashlib.sha256(asset).hexdigest()=='54415604a45dc4ed704ebbbe6b089a946593032f464fdca0a86af6ef4be94219'
p=8+4+32*8;assert struct.unpack_from('>8H',asset,p)==(512,4096,256,1023,1024,4096,4,3);p+=16+18
cc=[]
for i in range(4):p+=8;cc.append(struct.unpack_from('>9h',asset,p));p+=18
p+=18+6;gain=struct.unpack_from('>7168H',asset,p);p+=14336;gamma=struct.unpack_from('>4096H',asset,p)
arrays='static const int cc[4][9]={'+','.join('{'+','.join(map(str,x))+'}' for x in cc)+'};\n'
arrays+='static const int gain[7168]={'+','.join(map(str,gain))+'};\n'
arrays+='static const int gammaCode[4096]={'+','.join(map(str,gamma))+'};\n'
stats=s[s.index('double percent('):s.index('std::vector<double> copyArray')]
decl=s[s.index('    Vec01Stats camera_stats'):s.index('    const auto render_start')]
config=s[s.index('        m11::render::RenderConfig config;'):s.index('        constexpr double kU16Norm')]
body=s[s.index('                const auto tr = m11::render::renderPixelTraceValidated'):s.index('                const auto& out = cat42_out;')]
source='''#include <cstdint>
#include <limits>
#include <sstream>
#include <iostream>
#include <cstring>
#include <random>
#include "m11_production_pixel.h"
'''+arrays+stats+'''
static m11::render::Vec3 oldPixel(const m11::render::Vec3& m11_rgb,const m11::render::Tables& tables){
 const auto camera_rgb=m11_rgb;
'''+decl+config+body+'''
 return cat42_out;
}
int main(){
 std::uint64_t compared=0,byteDiff=0,doubleDiff=0;
 for(int band=0;band<4;++band){
  m11::render::Tables t;t.cc0={1,0,0,0,1,0,0,0,1};
  for(int i=0;i<9;++i)t.cc1[i]=cc[band][i]/512.0;
  for(int i=0;i<1024;++i){t.tone_x.push_back(i/1023.0);for(int c=0;c<7;++c)t.tone_curves[c].push_back((i/1023.0)*gain[c*1024+i]/4096.0);}
  for(int i=0;i<4096;++i){t.gamma_x.push_back(i/4095.0);t.gamma_y.push_back(gammaCode[i]/1023.0);}
  m11::render::validateTables(t);
  auto check=[&](m11::render::Vec3 in){
    auto a=oldPixel(in,t),b=m11::production::savedPixelValidated(in,t);++compared;
    for(int c=0;c<3;++c){
      if(std::memcmp(&a[c],&b[c],sizeof(double)))++doubleDiff;
      if(std::lround(m11::render::clamp01(a[c])*255.0)!=std::lround(m11::render::clamp01(b[c])*255.0))++byteDiff;
    }
  };
  for(int i=0;i<65536;++i){double v=i/65535.0;check({v,v,v});}
  std::mt19937 rng(20260920u);
  for(int i=0;i<200000;++i){m11::render::Vec3 in;for(double& v:in)v=(rng()/4294967295.0)*3.0-0.25;check(in);}
  for(double a:{-.1,0.,1e-12,1e-10,0.0001,0.01,0.1,0.18,0.5,1.,1.5,3.})
    for(double b:{0.,0.01,0.5,1.,2.})for(double c:{0.,0.01,0.5,1.,2.})check({a,b,c});
 }
 std::cout<<"{\\"pixels\\":"<<compared<<",\\"differentDoubleComponents\\":"<<doubleDiff<<",\\"differentQuantizedComponents\\":"<<byteDiff<<"}\\n";
 return (byteDiff||doubleDiff)?1:0;
}
'''
cpp=work/'parity.cpp';cpp.write_text(source);results=[]
for opt in ['-O0','-O2']:
 exe=work/('test'+opt[1:])
 subprocess.run(['g++','-std=c++17',opt,'-ffp-contract=off','-Iapp/src/main/cpp','-Inative/m11_renderer',str(cpp),'-o',str(exe)],check=True)
 done=subprocess.run([str(exe)],check=True,text=True,capture_output=True);r=json.loads(done.stdout);r['compilerOptimization']=opt;r['contract']='host identical double output and RGBA quantization; not device timing';results.append(r);print(done.stdout.strip())
prod=Path('app/src/main/cpp/m11_production_pixel.h').read_text();assert '258' in prod and '588' in prod and '505' in prod
assert '26' in prod and '-4' in prod and '-20' in prod and '/ 512.0' in prod
assert 'config.use_cc1=false; config.use_gamma=false; config.use_chroma=false;' in prod
assert 'std::thread' not in prod and 'Xiaomi' not in prod
Path('M11_PERF1A_PARITY_TEST.json').write_text(json.dumps(results,indent=2)+'\n')
