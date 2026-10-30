"""Check actual image descriptors and disjoint built-in resource contracts.

This is an image/resource check; runtime service restart and IPC checks exercise
the corresponding guest mappings. It makes no verified-compiler claim.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live_build

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True)
 p.add_argument('--artifacts',type=Path)
 p.add_argument('--output',type=Path)
 a=p.parse_args();raw=a.image.read_bytes();assert len(raw)==0x600000
 live_build.check_service_layout();services=[]
 names=['launcher','objects','vault','compositor','build-jobs','network']
 for slot in range(1,7):
  length,rights,version,limit=struct.unpack_from('<4Q',raw,0x200000+slot*32)
  offset,expected=live_build.service_image_bounds(slot)
  assert version==2 and limit==expected and 0<length<=limit and length%4==0
  assert rights=={1:0x1000000ff,2:0,3:127,4:127,5:127,6:0}[slot]
  body=raw[offset:offset+length]
  if a.artifacts:assert body==(a.artifacts/(names[slot-1]+'.bin')).read_bytes()
  services.append(dict(slot=slot,image_offset=offset,length=length,limit=limit,descriptor=version,sha256=hashlib.sha256(body).hexdigest()))
 assert not any(raw[0x340000:0x380000]),'old narrow Objects image slot was silently reused'
 device_magic,audio_profile,network_profile=struct.unpack_from('<8sQQ',raw,0x200420)
 if device_magic==bytes(8):
  assert audio_profile==0 and network_profile==0
  audio_profile=1;network_profile=1
 else:
  assert device_magic==b'LTDEV2\0\0' and audio_profile==2 and network_profile in (1,2)
 dma=[(0x80e20000,0x80e24000,'network data rings'),(0x80e24000,0x80e24800,'network data buffers'),
  (0x80e26000,0x80e26100,'audio owner/control state'),(0x80e28000,0x80e2a000,'audio output ring'),(0x80e2a000,0x80e2a400,'audio samples'),
  (0x80e2c000,0x80e30000,'audio control rings'),(0x80e30000,0x80e30408,'audio control buffers'),
  (0x80e31000,0x80e31050,'network control state'),(0x80e32000,0x80e36000,'network control rings'),(0x80e36000,0x80e36408,'network control buffers')]
 for i,(start,stop,name) in enumerate(dma):
  assert start<stop<=0x80f00000 and (i==0 or dma[i-1][1]<=start),name
 result=dict(image=hashlib.sha256(raw).hexdigest(),result='passed',image_bytes=len(raw),services=services,
  audio_profile=audio_profile,network_profile=network_profile,
  supervisor_dma_regions=[dict(start=start,end_exclusive=stop,purpose=name) for start,stop,name in dma],
  objects_physical=dict(code=[0x81100000,0x81160000],data=[0x81160000,0x81170000],stack=[0x81170000,0x81174000],next_service_code=0x81180000),
  ordinary_signed_application_code_limit=262144,process_slots=12,ram_bytes=160*1024*1024,
  assumptions='static ranges correspond to the documented kernel functions; actual boot/IPC/restart tested separately')
 if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2))

if __name__=='__main__':main()
