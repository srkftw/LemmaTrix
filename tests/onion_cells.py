"""Three independent Tor hop states and ordinary relay-cell differential fixture.
This executes crypto/state processing locally; it is not a routed guest journey.
"""
import hashlib,json,subprocess,sys,argparse
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import onion_crypto as native
from network_crypto import store_bytes
import driver

def source():
 keys=[hashlib.shake_256(('Tor hop fixture '+str(i)).encode()).digest(92) for i in range(3)]
 data=b'Native three-hop cell state fixture';padding=hashlib.shake_256(b'public fixture padding').digest(509)
 body=bytearray(padding);body[0]=2;body[1:3]=b'\0\0';body[3:5]=(17).to_bytes(2,'big');body[5:9]=b'\0'*4;body[9:11]=len(data).to_bytes(2,'big');body[11:11+len(data)]=data;body[11+len(data):15+len(data)]=b'\0'*4
 digest=hashlib.sha1(keys[2][:20]+body).digest();body[5:9]=digest[:4]
 expected=bytes(body)
 for k in reversed(keys):expected=subprocess.run([driver.tool('openssl'),'enc','-aes-128-ctr','-K',k[40:56].hex(),'-iv','00'*16],input=expected,capture_output=True,check=True).stdout
 s='import Guest.TorCells\nset_option maxRecDepth 10000\nnamespace build.OnionCells\n'
 s+='''partial def transfer (c r i t : UInt64) : UInt64 :=
  if i == 100 then t else
    let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 35 0x701000 t
    let t := Guest.TorCells.originate c 0x6c0000 0 0x710000 t
    if t == Guest.TorCells.err then 1 else
    let t := Guest.TorCells.peel r 0x6c0000 0 0x710000 t
    if Guest.load64 0x6c03e8 t != 0 then 2 else transfer c r (i+1) t
def check (t : UInt64) : UInt64 :=
'''
 for i,k in enumerate(keys):s+=store_bytes(0x702000+i*256,k)+'\n'
 s+=store_bytes(0x700000,data)+'\n'+store_bytes(0x701000,padding)+'\n'+store_bytes(0x703000,expected)+'\n'
 contexts=[0x6d0000+i*0x1000 for i in range(6)]
 for i,c in enumerate(contexts):s+=f'  let t := Guest.TorCells.init {c} 0x6c0000 {0x702000+(i%3)*256} t\n'
 s+='  let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 35 0x701000 t\n'
 s+=f'  let t := Guest.TorCells.originate {contexts[2]} 0x6c0000 0 0x710000 t\n'
 for c in reversed(contexts[:2]):s+=f'  let t := Guest.TorCells.cryptLayer {c} 0 0x710000 t\n'
 s+='  if Guest.TorCells.difference 0x710000 0x703000 509 0 t != 0 then 1 else\n'
 for i,c in enumerate(contexts[3:]):
  s+=f'  let t := Guest.TorCells.peel {c} 0x6c0000 0 0x710000 t\n  if Guest.load64 0x6c03e8 t != {0 if i==2 else 1} then {2+i} else\n'
 s+='  if Guest.TorCells.difference 0x71000b 0x700000 35 0 t != 0 then 5 else\n'
 # reverse direction with independent counters/digests.
 s+='  let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 35 0x701000 t\n'
 s+=f'  let t := Guest.TorCells.originate {contexts[5]} 0x6c0000 1 0x710000 t\n'
 for c in reversed(contexts[3:5]):s+=f'  let t := Guest.TorCells.cryptLayer {c} 1 0x710000 t\n'
 for i,c in enumerate(contexts[:3]):
  s+=f'  let t := Guest.TorCells.peel {c} 0x6c0000 1 0x710000 t\n  if Guest.load64 0x6c03e8 t != {0 if i==2 else 1} then {6+i} else\n'
 s+='  if Guest.TorCells.difference 0x71000b 0x700000 35 0 t != 0 then 9 else\n'
 # Independent direct hop fresh state,100cells triggerauthenticatedSENDME, replaydenied.
 for c in contexts[:2]:s+=f'  let t := Guest.TorCells.init {c} 0x6c0000 0x702000 t\n'
 s+=f'''  let t := transfer {contexts[0]} {contexts[1]} 0 t
  if t == 1 || t == 2 then 10 else
  if Guest.load64 (Guest.TorCells.packageWindow {contexts[0]} 0) t != 900 then 11 else
  let t := Guest.TorCells.sendme {contexts[1]} 0 0x704000 t
  if t == Guest.TorCells.err then 12 else
  let t := Guest.TorCells.acceptSendme {contexts[0]} 0 0x704000 23 t
  if t == Guest.TorCells.err || Guest.load64 (Guest.TorCells.packageWindow {contexts[0]} 0) t != 1000 then 13 else
  let r := Guest.TorCells.acceptSendme {contexts[0]} 0 0x704000 23 t
  if r != Guest.TorCells.err then 14 else
  let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 35 0x701000 r
  let t := Guest.TorCells.copy (Guest.TorCells.hashContext {contexts[1]} 0) 0x705000 128 t
  let t := Guest.TorCells.originate {contexts[0]} 0x6c0000 0 0x710000 t
  let t := Guest.store8 0x710050 (Guest.load8 0x710050 t ^^^ 1) t
  let t := Guest.TorCells.peel {contexts[1]} 0x6c0000 0 0x710000 t
  if Guest.load64 0x6c03e8 t != 1 then 15 else
  if Guest.TorCells.difference (Guest.TorCells.hashContext {contexts[1]} 0) 0x705000 128 0 t != 0 then 16 else
  0
end build.OnionCells
'''
 return s

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);a=p.parse_args()
 driver.lean(['-o','Guest/TorCells.olean','Guest/TorCells.lean']);native.B=driver.ROOT/'build/onion-cells';binary=native.build(source(),'OnionCells');report=dict(schema=1,profile='ordinary Tor AES128CTR/SHA1 cells;3 distinct hop states',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,checks=[native.execute(binary,b) for b in a.backend or ['qemu']],checks_executed=['independent OpenSSL/hashlib509-byte three-hop fixture','forward peel transit/transit/recognition','independent reverse directions','100 DATA cell authenticated SENDME','SENDME replay rejection','failed recognition preserves digest state'],limits='Locally linked hop states are a crypto vector only, not independent relay guests or native mode1 route acceptance.')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
