#include "m11_portable_raw_gate.h"
#include <iostream>
#include <functional>
#include <cassert>
using namespace m11raw;
unsigned mask(const std::string& phase){unsigned f=0;for(unsigned y=0;y<8;y++)for(unsigned x=0;x<2;x++){unsigned p=phase[(y%2)*2+x]=='R'?0:phase[(y%2)*2+x]=='B'?2:1;f|=p<<((y*2+x)*2);}return f;}
int main(){int n=0;auto check=[&](bool b){if(!b)throw std::runtime_error("gate assertion");++n;};auto reject=[&](PortableRawDescriptor d){try{validatePortableRaw(d);}catch(const std::invalid_argument&){++n;return;}throw std::runtime_error("unsafe RAW accepted");};
 PortableRawDescriptor d{0x01040000,1,3,0xb4b4b4b4,4096,3072,4096,3072,0,0,1023,"RGBG"};
 check(validatePortableRaw(d)=="RGGB");
 for(const std::string p:{"RGGB","GRBG","GBRG","BGGR"})for(unsigned white:{255u,1023u,4095u,16383u,65535u}){
  d.filters=mask(p);d.maximum=white;d.rawWidth=6016;d.rawHeight=4016;d.width=6000;d.height=4000;d.top=7;d.left=9;check(validatePortableRaw(d)==p);
 }
 auto bad=d;bad.dngVersion=0;reject(bad);bad=d;bad.colors=4;reject(bad);bad=d;bad.rawCount=2;reject(bad);
 for(unsigned f:{0u,1u,9u,1000u}){bad=d;bad.filters=f;reject(bad);}
 bad=d;bad.filters=mask("RRRR");reject(bad);bad=d;bad.filters^=(3u<<12);reject(bad);
 bad=d;bad.colorDescription="RG";reject(bad);bad=d;bad.maximum=0;reject(bad);bad=d;bad.maximum=65536;reject(bad);
 bad=d;bad.left=100;reject(bad);bad=d;bad.top=100;reject(bad);bad=d;bad.width=0;reject(bad);
 bad=d;bad.rawWidth=0xffffffff;bad.rawHeight=0xffffffff;reject(bad);
 std::cout<<"DEVICEPORT1A native capability assertions passed: "<<n<<"\n";
}
