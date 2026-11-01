"""Execute live TorRouter record-admission predicate in compiled RV64."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import onion_crypto as native
import driver
SOURCE='''import Guest.TorRouter
namespace build.OnionRouterPolicy
def check (t : UInt64) : UInt64 :=
  let c := Guest.TorRouter.channel 0
  let t := Guest.store64 Guest.TorRouter.state 1 t
  let t := Guest.store64 (c+112) 1024 t
  let t := Guest.store64 (c+120) 4 t
  let t := Guest.store64 (c+128) 0 t
  let t := Guest.store64 (c+136) 0 t
  let t := Guest.TorRouter.accountRecord 0 532 t
  if t == Guest.LiveSDK.error || Guest.load64 (c+128) t != 532 || Guest.load64 (c+136) t != 1 then 1 else
  let t := Guest.TorRouter.accountRecord 0 492 t
  if t == Guest.LiveSDK.error || Guest.load64 (c+128) t != 1024 || Guest.load64 (c+136) t != 2 then 2 else
  let t := Guest.store64 0x6c1ff8 123 t
  let t := Guest.store64 0x6d87f8 456 t
  let r := Guest.TorRouter.accountRecord 0 1 t
  if r != Guest.LiveSDK.error || Guest.load64 Guest.TorRouter.state r != 0 || Guest.load64 (Guest.TorRouter.state+48) r != 55 then 3 else
  if Guest.load64 0x6c1ff8 r != 0 || Guest.load64 0x6d87f8 r != 0 then 6 else
  let t := Guest.store64 Guest.TorRouter.state 1 r
  let t := Guest.store64 (c+112) 1048576 t
  let t := Guest.store64 (c+120) 1 t
  let t := Guest.TorRouter.accountRecord 0 50 t
  if t == Guest.LiveSDK.error then 4 else
  let r := Guest.TorRouter.accountRecord 0 50 t
  if r != Guest.LiveSDK.error || Guest.load64 Guest.TorRouter.state r != 0 || Guest.load64 (Guest.TorRouter.state+48) r != 55 then 5 else
  0
end build.OnionRouterPolicy
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args();native.B=driver.ROOT/'build/onion-router-policy';driver.lean(['-o','Guest/TorRouter.olean','Guest/TorRouter.lean']);binary=native.build(SOURCE,'OnionRouterPolicy');report=dict(schema=1,profile='TorRouter live per-channel signed byte/work record admission',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu']],checks_executed=['exact byte boundary accepted','one-byte excess denied and route authority cleared','work allowance exhaustion denied and route authority cleared','route denial clears serialized ntor and hop scratch']);(native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
