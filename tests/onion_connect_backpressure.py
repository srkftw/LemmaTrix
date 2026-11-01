"""Regression for observed relay BEGIN failure47 behind adapter CLOSE/credit."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import onion_crypto as native
import driver,live_build
SOURCE='''import Guest.TorRouter
namespace build.OnionConnectBackpressure
def check (t : UInt64) : UInt64 :=
  let p := Guest.TorRouter.channel 1
  let peer := Guest.NodeEnrollment.peer 0
  let a := Guest.Transport.channel 1
  let t := Guest.LiveSDK.zero Guest.Transport.st 2048 t
  let t := Guest.LiveSDK.zero Guest.TorRouter.state 8192 t
  let t := Guest.LiveSDK.zero p 2048 t
  let t := Guest.store64 Guest.TorRouter.state 1 t
  let t := Guest.store64 p 1 t
  let t := Guest.store64 (p+8) 1 t
  let t := Guest.store64 (p+144) 1 t
  let t := Guest.store64 peer 1 t
  let t := Guest.store64 (peer+360) 0 t
  let t := Guest.store64 (peer+368) 1 t
  let t := Guest.store8 (peer+376) 120 t
  let t := Guest.store64 a 7 t
  let t := Guest.store64 (Guest.Transport.st+16) 16 t
  let t := Guest.TorRouter.connectPending 1 t
  if Guest.load64 (p+144) t != 1 || Guest.load64 (Guest.Transport.st+16) t != 16 || !Guest.TorRouter.enabled t then 1 else
  let t := Guest.store64 (Guest.Transport.st+16) 0 t
  let t := Guest.store64 (Guest.Transport.channel 3+48) 1 t
  let t := Guest.TorRouter.connectPending 1 t
  if Guest.load64 (p+144) t != 1 || Guest.load64 (Guest.Transport.st+16) t != 0 then 2 else
  let t := Guest.store64 (Guest.Transport.channel 3+48) 0 t
  let t := Guest.TorRouter.connectPending 1 t
  if Guest.load64 (p+144) t != 0 || Guest.load64 (Guest.Transport.st+16) t != 17 || Guest.load64 a t != 7 then 3 else
  if Guest.load64 Guest.Transport.output t != (Guest.Transport.magic ||| ((1 : UInt64) <<< 32) ||| ((1 : UInt64) <<< 40) ||| ((1 : UInt64) <<< 48)) then 4 else
  let t := Guest.store64 Guest.Transport.input (Guest.Transport.magic ||| ((4 : UInt64) <<< 32) ||| ((1 : UInt64) <<< 40)) t
  let t := Guest.store64 (Guest.Transport.input+8) ((7 : UInt64) ||| ((65536 : UInt64) <<< 32)) t
  let t := Guest.Transport.event t
  if Guest.load64 (a+8) t != 0 then 5 else
  let t := Guest.store64 (Guest.Transport.input+8) ((8 : UInt64) ||| ((65536 : UInt64) <<< 32)) t
  let t := Guest.Transport.event t
  if Guest.load64 a t != 8 || Guest.load64 (a+8) t != 1 then 6 else
  0
end build.OnionConnectBackpressure
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args()
 native.B=driver.ROOT/'build/onion-connect-backpressure';live_build.compile_module('Guest.TorRouter')
 binary=native.build(SOURCE,'OnionConnectBackpressure')
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu']],observed_failure='Relay3 BEGIN failed47 because an admitted immutable adapter frame was busy',checks_executed=['busy output defers rather than fails admitted relay connect','pending CLOSE has priority over connect','idle output queues exact endpoint once','closed epoch survives connect reset; delayed old OPEN ignored; fresh OPEN accepted'],limits='Focused compiled RV64 control transition; fresh connected journey separately exercises actual opaque adapters.')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
